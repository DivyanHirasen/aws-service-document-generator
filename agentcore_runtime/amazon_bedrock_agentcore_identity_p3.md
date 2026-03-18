# Amazon Bedrock AgentCore Identity — Security Assessment

> Cloud Security Review Board | March 2026

---

## 1. Service Overview

Amazon Bedrock AgentCore Identity is a fully managed, serverless identity and access management service purpose-built for AI agents, providing centralised workload identity management, secure credential storage (token vault), and OAuth 2.0 flow orchestration for both inbound agent authentication and outbound access to third-party services [1]. The service is powered by Amazon Cognito and operates as a shared infrastructure layer across AgentCore Runtime and Gateway — workload identities are created automatically when agents are deployed via Runtime or Gateway, and can also be created manually for self-hosted or hybrid deployments [2]. The critical security consideration for regulated workloads is that the token vault stores live OAuth access tokens, refresh tokens, API keys, and OAuth client secrets on behalf of agents and users — making it a high-value credential store that requires CMK encryption, strict IAM scoping, and audit logging of every token retrieval event [3].

---

## 2. Underlying Infrastructure & Service Substrate

- **Compute substrate:** Identity service operations (token issuance, JWT validation, OAuth flow orchestration, token vault access) run on AWS-managed serverless compute in an AWS-managed service account, powered by Amazon Cognito infrastructure. Customers have no visibility into or control over the underlying compute layer; there is no per-customer or per-session compute isolation model published by AWS [1][2]
- **Storage substrate:** The agent identity directory (workload identity metadata and ARNs) and the token vault (OAuth access tokens, refresh tokens, API keys, OAuth client credentials) are stored in AWS-managed backend storage within the AWS-managed service account. OAuth client credentials (client ID and client secret for outbound providers such as Google, GitHub, Slack, Salesforce) are stored in AWS Secrets Manager in the customer's account under the `bedrock-agentcore` prefix. Customers cannot directly access, query, or export the identity directory or token vault storage via any direct storage API — all access is exclusively through AgentCore Identity APIs [3][4]
- **AWS account boundary:** The Identity service plane, identity directory, and token vault all run in an AWS-managed service account. The customer's account boundary is the Identity API endpoint. OAuth client credentials (Secrets Manager secrets) and the `AWSServiceRoleForBedrockAgentCoreRuntimeIdentity` service-linked role are defined in and belong to the customer's account. Token exchange calls (`GetWorkloadAccessTokenForJWT`, `GetResourceOauth2Token`) cross into the AWS service account on every invocation [5]
- **VPC boundary:** AgentCore Identity has no compute or storage running inside the customer's VPC. Identity data-plane API calls are made against public AWS endpoints by default. PrivateLink is supported for Identity data-plane operations via the shared `com.amazonaws.region.bedrock-agentcore` endpoint; control-plane operations (`CreateWorkloadIdentity`, `CreateOauth2CredentialProvider`, etc.) use `bedrock-agentcore-control.<region>.amazonaws.com`, for which PrivateLink is not currently supported [6]
- **Multi-tenancy model:** Workload identities and token vault entries are logically isolated per customer account and per workload identity ARN. Token vault entries are bound to a specific agent identity and user identity combination — a token stored for agent A on behalf of user X cannot be retrieved by agent B or on behalf of user Y. AWS does not publish the physical storage isolation model; CMK encryption provides the strongest available data isolation guarantee for vault contents [3]
- **Data residency:** Workload identity metadata and token vault contents at rest are stored only in the primary AWS region where the Identity resource is created. Outbound OAuth flows (3LO authorization code grant) require the agent to redirect users to external identity providers (Google, GitHub, Salesforce, etc.) and receive callbacks at AgentCore-managed callback URLs — these flows traverse the public internet to external OAuth servers outside AWS. There is no cross-region inference component in Identity itself (unlike Memory and Policy) [1][4]

---

## 3. AWS Enabled Platform Controls

### 3a. Control Mapping

| Control Type | Control | Description |
|---|---|---|
| Detective | CloudTrail — management events | `CreateWorkloadIdentity`, `DeleteWorkloadIdentity`, `ListWorkloadIdentities`, `CreateOauth2CredentialProvider`, `UpdateOauth2CredentialProvider`, `DeleteOauth2CredentialProvider`, `CreateApiKeyCredentialProvider`, `DeleteApiKeyCredentialProvider` are logged automatically as management events with no additional configuration [7] |
| Detective | CloudTrail — data events (`GetWorkloadAccessToken`, `GetResourceOauth2Token`, `GetResourceApiKey`) | Token retrieval operations are data-plane events; they are **not** logged by default and require a manually configured CloudTrail trail with data event logging enabled — this is a material audit gap given that every credential retrieval from the token vault should be auditable in a regulated environment [7] |
| Detective | CloudWatch — `AWS/Bedrock-AgentCore` namespace | Identity emits `WorkloadAccessTokenFetchSuccess`, `WorkloadAccessTokenFetchFailures`, `ResourceAccessTokenFetchSuccess`, `ResourceAccessTokenFetchFailures`, `ApiKeyFetchSuccess`, `ApiKeyFetchFailures` metrics per workload identity and credential provider; alerts can be configured to detect anomalous token retrieval patterns, authentication failures, or quota exhaustion [8] |
| Detective | CloudWatch Logs — structured span data | When observability is enabled on a workload identity or credential provider resource, structured spans are emitted to the `aws/spans` log group with operation name, workload identity ID, user sub claim, OAuth flow type, latency, and error type — providing per-request visibility into token operations [8] |
| Proactive | Token vault binding (agent + user) | Token vault entries are cryptographically bound to a specific agent identity and user identity combination; the service enforces that a token stored for agent A on behalf of user X cannot be retrieved by any other agent or on behalf of any other user — preventing cross-agent and cross-user credential leakage [3] |
| Proactive | JWT claim validation on inbound auth | When JWT Bearer Token authentication is configured on a Runtime, the Identity service validates token signature (via OIDC discovery URL), expiration, `iss`, `aud`, `client_id`, and any required custom claims before issuing a workload access token — misconfigured or expired tokens are rejected before reaching agent code [9] |
| Preventative | Customer-managed KMS (CMK) | Token vault contents (OAuth tokens, API keys, OAuth client secrets) can be encrypted with a CMK; the KMS key policy must include `kms:ViaService` scoped to `bedrock-agentcore.<region>.amazonaws.com`, preventing key use outside the service boundary [3] |
| Preventative | IAM resource-based scoping on credential providers | Access to individual credential providers can be restricted via IAM policy scoped to specific workload identity ARNs and token vault ARNs — ensuring only named agents can retrieve credentials for specific external services [10] |
| Preventative | `InvokeAgentRuntimeForUser` permission gate | Passing the `X-Amzn-Bedrock-AgentCore-Runtime-User-Id` header (which binds a token retrieval to a specific user identity) requires the separate `bedrock-agentcore:InvokeAgentRuntimeForUser` IAM action — preventing arbitrary principals from impersonating users by injecting a different user ID [9] |
| Responsive | `DeleteWorkloadIdentity` and `DeleteOauth2CredentialProvider` APIs | Workload identities and credential providers can be deleted immediately via API to revoke an agent's ability to obtain tokens or access external services during incident response [4] |
| Responsive | Automatic token refresh with expiry enforcement | The token vault automatically uses stored refresh tokens to obtain new access tokens when the stored access token expires; when the refresh token also expires, the agent must re-initiate the OAuth consent flow — enforcing time-bounded credential validity without manual rotation [3] |

### 3b. Service Control Policy (SCP)

The following SCP is a production-ready starting point to be attached at the AWS Organizations OU level for accounts using AgentCore Identity. Substitute `["us-east-1", "eu-west-1"]` with your organisation's approved region list before applying.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIdentityResourceCreationOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:CreateWorkloadIdentity",
        "bedrock-agentcore:CreateOauth2CredentialProvider",
        "bedrock-agentcore:UpdateOauth2CredentialProvider",
        "bedrock-agentcore:CreateApiKeyCredentialProvider"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-east-1", "eu-west-1"]
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyTokenVaultAccessOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:GetWorkloadAccessToken",
        "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
        "bedrock-agentcore:GetWorkloadAccessTokenForUserId",
        "bedrock-agentcore:GetResourceOauth2Token",
        "bedrock-agentcore:GetResourceApiKey"
      ],
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": ["us-east-1", "eu-west-1"]
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyDeletionOfWorkloadIdentitiesByUnauthorisedPrincipals",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:DeleteWorkloadIdentity",
        "bedrock-agentcore:DeleteOauth2CredentialProvider",
        "bedrock-agentcore:DeleteApiKeyCredentialProvider"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/AgentCoreApprovedAdmin*",
            "arn:aws:iam::*:role/BreakGlassAdmin"
          ]
        }
      }
    },
    {
      "Sid": "DenyDeletionOfIdentityAuditTrails",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyDeletionOfTokenVaultKMSGrants",
      "Effect": "Deny",
      "Action": [
        "kms:RevokeGrant",
        "kms:RetireGrant"
      ],
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "kms:ViaService": "bedrock-agentcore.*.amazonaws.com"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyDeletionOfAgentCoreCredentialSecrets",
      "Effect": "Deny",
      "Action": [
        "secretsmanager:DeleteSecret",
        "secretsmanager:PutSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:*:*:secret:bedrock-agentcore*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/AgentCoreApprovedAdmin*",
            "arn:aws:iam::*:role/BreakGlassAdmin"
          ]
        }
      }
    },
    {
      "Sid": "DenyDeletionOfIdentityServiceLinkedRole",
      "Effect": "Deny",
      "Action": [
        "iam:DeleteServiceLinkedRole"
      ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/runtime-identity.bedrock-agentcore.amazonaws.com/*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyUserImpersonationByUnauthorisedPrincipals",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:InvokeAgentRuntimeForUser"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/AgentCoreApprovedRuntime*",
            "arn:aws:iam::*:role/BreakGlassAdmin"
          ]
        }
      }
    }
  ]
}
```

**SCP limitations — what this policy cannot enforce (must be handled at IAM or application layer):**

- The SCP cannot enforce CMK encryption on token vault contents at creation time — there is no SCP condition key for `CreateWorkloadIdentity` or `CreateOauth2CredentialProvider` that validates a KMS key is specified; CMK enforcement must be implemented via AWS Config rules or deployment pipeline checks
- The SCP cannot prevent an agent from passing an arbitrary `X-Amzn-Bedrock-AgentCore-Runtime-User-Id` header value that does not correspond to the authenticated user's actual identity — the service treats this header as an opaque identifier; the calling application is responsible for deriving the user ID from the authenticated principal's context rather than accepting it as user input [9]
- The SCP cannot restrict which external OAuth providers (Google, GitHub, Salesforce, etc.) are configured as credential providers — provider allowlisting must be enforced via code review and deployment pipeline controls
- The SCP cannot enforce that observability (CloudWatch span data) is enabled on workload identities and credential providers; this must be enforced via AWS Config rules or account-level automation
- `GetWorkloadAccessToken` and `GetResourceOauth2Token` are runtime calls made by the `AWSServiceRoleForBedrockAgentCoreRuntimeIdentity` service-linked role — restricting these actions via SCP without exempting the service-linked role ARN would break Identity functionality; the SCP region restriction above applies to the calling principal, not the service-linked role itself
- The SCP cannot prevent outbound OAuth flows from reaching external identity providers over the public internet — this is an inherent architectural dependency of 3LO flows

---

## 4. AWS Identity & Access Management (IAM)

| Role / Policy | Purpose | Trust Relationship |
|---|---|---|
| `BedrockAgentCoreFullAccess` (AWS managed) | Broad admin access to all AgentCore resources including Identity; includes `bedrock-agentcore:*`, Secrets Manager (`bedrock-agentcore*` prefix), KMS decrypt, ECR, CloudWatch — not suitable for production | Attached to IAM users/roles by account admin |
| `AWSServiceRoleForBedrockAgentCoreRuntimeIdentity` (service-linked) | Allows AgentCore Runtime to call `GetWorkloadAccessToken`, `GetWorkloadAccessTokenForJWT`, and `GetWorkloadAccessTokenForUserId` on the default workload identity directory; created automatically for new agents (on or after October 13, 2025) | Trusted by `runtime-identity.bedrock-agentcore.amazonaws.com`; cannot be assumed by customer principals [5] |
| Agent execution role (customer-managed) | Assumed by the agent at runtime; for agents created before October 13, 2025, must include `GetWorkloadAccessToken`, `GetWorkloadAccessTokenForJWT`, `GetWorkloadAccessTokenForUserId` scoped to specific workload identity ARNs; for newer agents this is handled by the service-linked role | Trusted by `bedrock-agentcore.amazonaws.com` or the agent runtime; customer-defined |
| Resource management role (customer-managed) | Used by administrators to create/update/delete workload identities and credential providers; requires `CreateWorkloadIdentity`, `CreateOauth2CredentialProvider`, `CreateApiKeyCredentialProvider`, and Secrets Manager permissions for `bedrock-agentcore*` secrets | Trusted by administrator IAM users/roles; must be kept strictly separate from the agent execution role |
| KMS key grant role (customer-managed) | Required when using CMK for token vault encryption; must include `kms:CreateGrant`, `kms:DescribeKey`, `kms:Decrypt`, `kms:GenerateDataKey` conditioned on `kms:ViaService: bedrock-agentcore.<region>.amazonaws.com` | Held by the resource management role or agent execution role depending on operation [3] |

**Least-privilege guidance for production:**
- Scope `GetResourceOauth2Token` and `GetResourceApiKey` permissions to specific workload identity ARNs and token vault ARNs — not wildcards; this ensures only named agents can retrieve credentials for specific external services [10]
- The `InvokeAgentRuntimeForUser` permission must be granted only to trusted backend services that derive the user ID from an authenticated session — never to end-user-facing applications that could pass arbitrary user IDs
- Maintain strict separation between the resource management role (identity provisioning) and the agent execution role (runtime token retrieval) — the execution role has no need for `CreateWorkloadIdentity` or `DeleteOauth2CredentialProvider`
- For agents created before October 13, 2025, manually scope the `GetWorkloadAccessToken*` permissions on the execution role to the specific workload identity ARN for that agent — not the wildcard `workload-identity-directory/default/workload-identity/*`
- Regularly audit `ListWorkloadIdentities` output to identify stale or orphaned identities that retain access to credential providers

---

## 5. Data Protection

**Encryption at Rest:**
- Token vault contents (OAuth access tokens, refresh tokens, API keys) and workload identity metadata are encrypted at rest using AWS-managed KMS keys by default; customer-managed KMS keys (CMK) are supported and strongly recommended for workloads handling sensitive user credentials [3]
- CMK usage requires the KMS key policy to grant the Identity service `kms:CreateGrant`, `kms:DescribeKey`, `kms:Decrypt`, and `kms:GenerateDataKey`, conditioned on `kms:ViaService` scoped to `bedrock-agentcore.<region>.amazonaws.com` — preventing key use outside the service boundary [3]
- OAuth client credentials (client ID and client secret for outbound providers) are stored in AWS Secrets Manager in the customer's account under the `bedrock-agentcore` prefix; Secrets Manager supports CMK encryption and is recommended for regulated workloads
- The token vault runs in an AWS-managed service account; customers cannot directly access, audit, or independently verify the physical storage — CMK encryption is the primary mechanism for ensuring AWS cannot access plaintext credentials without explicit key grants
- FIPS 140-3 validated endpoints are available for environments with FIPS compliance requirements [6]

**Encryption in Transit:**
- All API communication (control-plane and data-plane) uses TLS 1.2 minimum; TLS 1.3 is recommended [6]
- Outbound OAuth flows (3LO authorization code grant) require the agent to redirect users to external identity providers (Google, GitHub, Salesforce, etc.) over the public internet via HTTPS — these flows cannot be privatised via PrivateLink as they involve external third-party servers outside AWS
- Workload access tokens issued by AgentCore Identity are AWS-signed tokens transmitted over TLS; they are short-lived and bound to a specific agent-user combination
- Callback URLs for 3LO flows are hosted at `https://bedrock-agentcore.<region>.amazonaws.com/identities/oauth2/callback/...` — these are AWS-managed HTTPS endpoints; customers must register these callback URLs with their external OAuth providers

---

## 6. Network Security

- AgentCore Identity has no compute or storage running inside the customer's VPC; it is a fully managed service operating in an AWS-managed service account
- PrivateLink is supported for Identity data-plane operations (`GetWorkloadAccessToken`, `GetWorkloadAccessTokenForJWT`, `GetWorkloadAccessTokenForUserId`, `GetResourceOauth2Token`, `GetResourceApiKey`) via the shared `com.amazonaws.region.bedrock-agentcore` endpoint [6]
- Control-plane operations (`CreateWorkloadIdentity`, `CreateOauth2CredentialProvider`, `DeleteWorkloadIdentity`, etc.) use `bedrock-agentcore-control.<region>.amazonaws.com`; PrivateLink is not currently supported for these endpoints — they require internet connectivity or a NAT Gateway [6]
- VPC endpoint policy consideration: Identity data-plane APIs support both SigV4 and OAuth Bearer Token authentication; VPC endpoint policies can only restrict access based on IAM principals — OAuth-authenticated requests require the endpoint policy `Principal` to be set to `*` [6]
- Outbound OAuth flows (3LO) require internet connectivity to reach external identity providers (Google, GitHub, Salesforce, etc.) for the authorization code exchange — this cannot be eliminated via PrivateLink or network controls; it is an inherent dependency of delegated user authentication
- Security groups and NACLs do not apply to the Identity service itself; they apply only to the PrivateLink endpoint network interfaces created in the customer's VPC
- Internet access is not required for Identity data-plane calls (token retrieval) when PrivateLink is configured; control-plane calls and 3LO OAuth flows require internet connectivity

---

## 7. Logging and Monitoring

**CloudTrail:**
- Management events (logged by default, no additional configuration): `CreateWorkloadIdentity`, `DeleteWorkloadIdentity`, `ListWorkloadIdentities`, `CreateOauth2CredentialProvider`, `UpdateOauth2CredentialProvider`, `DeleteOauth2CredentialProvider`, `CreateApiKeyCredentialProvider`, `DeleteApiKeyCredentialProvider`
- Data events (not logged by default — must be explicitly enabled via a CloudTrail trail with data event logging; additional cost applies): `GetWorkloadAccessToken`, `GetWorkloadAccessTokenForJWT`, `GetWorkloadAccessTokenForUserId`, `GetResourceOauth2Token`, `GetResourceApiKey`
- Critical gap: without data event logging enabled, there is no CloudTrail audit trail of which agent retrieved which credential, on behalf of which user, and at what time — this is a material compliance gap for regulated workloads where auditability of credential access is required. The token vault is a high-value credential store; every retrieval event must be logged
- Supplementary observability: when observability is enabled on workload identity and credential provider resources, structured spans are emitted to the `aws/spans` CloudWatch Logs log group with operation name, workload identity ID, user `sub` claim, OAuth flow type, latency, and error type — this provides per-request visibility that partially compensates for the CloudTrail data event gap, but is not a substitute for immutable CloudTrail records [8]
- CloudTrail logs should be delivered to an S3 bucket with Object Lock (WORM) enabled in a dedicated logging account

**VPC Flow Logs:**
- AgentCore Identity does not create ENIs in the customer's VPC; VPC Flow Logs are not applicable for Identity-specific traffic in the default configuration
- When PrivateLink is configured for the `bedrock-agentcore` data plane endpoint, the interface endpoint creates ENIs in the customer's subnets; VPC Flow Logs on those subnets will capture traffic from agent runtimes to the Identity PrivateLink endpoint, providing network-level visibility into token retrieval call volumes
- Outbound 3LO OAuth flows to external identity providers traverse the public internet and do not appear in customer VPC Flow Logs; CloudTrail data events and CloudWatch span data are the only audit records for these flows

**Compliance:**
- Amazon Bedrock AgentCore (including Identity) is in scope for: SOC 1 Type II, SOC 2 Type II, SOC 3, ISO 27001, ISO 27017, ISO 27018, PCI DSS Level 1, HIPAA eligibility, FedRAMP Moderate [11]
- Customer responsibilities not handled by AWS: enabling CloudTrail data event logging for all token retrieval operations (`GetWorkloadAccessToken`, `GetResourceOauth2Token`, `GetResourceApiKey`) to create an audit trail of credential access; enabling observability on workload identities and credential providers for CloudWatch span data; configuring PrivateLink for data-plane token retrieval in production; enforcing CMK encryption on token vault and Secrets Manager secrets; scoping `GetResourceOauth2Token` and `GetResourceApiKey` IAM permissions to specific workload identity ARNs; ensuring the `X-Amzn-Bedrock-AgentCore-Runtime-User-Id` header is derived from authenticated session context and not accepted as user input; registering only approved callback URLs with external OAuth providers; retaining CloudTrail logs for the period required by applicable regulations

---

## Sources

1. AWS Blog — Introducing Amazon Bedrock AgentCore Identity: Securing agentic AI at scale: https://aws.amazon.com/blogs/machine-learning/introducing-amazon-bedrock-agentcore-identity-securing-agentic-ai-at-scale
2. AWS Docs — Understanding workload identities: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/understanding-agent-identities.html
3. AWS Blog — Securing AI agents with Amazon Bedrock AgentCore Identity: https://aws.amazon.com/blogs/security/securing-ai-agents-with-amazon-bedrock-agentcore-identity/
4. AWS Docs — Features of AgentCore Identity: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/key-features-and-benefits.html
5. AWS Docs — Using service-linked roles for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/service-linked-roles.html
6. AWS Docs — Use interface VPC endpoints (PrivateLink) for AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc-interface-endpoints.html
7. AWS Docs — AWS managed policies for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-iam-awsmanpol.html
8. AWS Docs — AgentCore generated identity observability data: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-identity-metrics.html
9. AWS Docs — Authenticate and authorize with Inbound Auth and Outbound Auth: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-oauth.html
10. AWS Docs — Scope down access to credential providers by workload identity: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/scope-credential-provider-access.html
11. AWS What's New — AgentCore generally available (Oct 2025): https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-available
