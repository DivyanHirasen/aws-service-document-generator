# Amazon Bedrock AgentCore Gateway — Security Assessment

> Cloud Security Review Board | March 2026

---

## 1. Service Overview

Amazon Bedrock AgentCore Gateway is a fully managed, serverless service that converts existing REST APIs, AWS Lambda functions, Smithy models, and remote MCP servers into Model Context Protocol (MCP)-compatible tools, exposing them to AI agents through a single authenticated endpoint without requiring changes to backend systems [1]. It runs entirely in an AWS-managed service account with no customer-managed compute or storage to provision, and acts as the authorisation and routing layer between agents and their tools — enforcing OAuth-based inbound authentication and credential injection for outbound calls to targets [2]. For regulated workloads, the critical security consideration is that Gateway's data plane uses JWT/OAuth authentication rather than AWS SigV4, which limits the effectiveness of IAM-based network controls at the VPC endpoint layer [3].

---

## 2. Underlying Infrastructure & Service Substrate

- **Compute substrate:** Gateway's request routing, protocol translation (MCP ↔ REST/Lambda), and policy evaluation run on AWS-managed serverless compute in an AWS-managed service account — customers have no visibility into or control over the underlying compute layer. There is no per-session isolation model equivalent to Runtime's microVMs; Gateway is a shared, stateless routing plane [1]
- **Storage substrate:** Gateway configuration data (gateway definitions, target definitions, tool schemas, credential provider configurations) is stored in Amazon DynamoDB and Amazon S3 within an AWS-managed service account. Tool schema payloads up to 1 MB can be defined inline; larger schemas up to 10 MB are stored in customer-provided S3 buckets. Semantic search tool indexes are stored in S3 Vectors (AWS-managed). Customers cannot directly access the DynamoDB or S3 storage backing Gateway configuration [4]
- **AWS account boundary:** Gateway configuration and routing infrastructure run in an AWS-managed service account. The Gateway execution role, Lambda function targets, and credential secrets (stored in AWS Secrets Manager with the `bedrock-agentcore` prefix) are defined in and belong to the customer's account. Tool invocations cross the account boundary in both directions: inbound from agents to the Gateway service plane, and outbound from the Gateway service plane to Lambda functions or APIs in the customer's account [2]
- **VPC boundary:** Gateway itself runs outside the customer's VPC. Inbound agent-to-Gateway traffic can be routed privately via a dedicated PrivateLink endpoint (`com.amazonaws.region.bedrock-agentcore.gateway`), keeping agent requests within the AWS network. Outbound Gateway-to-target traffic (Lambda invocations, API calls) traverses the AWS network for Lambda targets but may reach the public internet for OpenAPI targets hosted externally. OAuth authentication flows (inbound token validation and outbound credential exchange with identity providers) require internet connectivity and cannot be fully privatised [3]
- **Multi-tenancy model:** Gateway is a shared service plane — there is no per-customer or per-session compute isolation equivalent to Firecracker microVMs. Logical isolation is enforced through IAM (execution role scoping), OAuth token validation, and Cedar policy enforcement. AWS does not publish the physical isolation model for the Gateway routing infrastructure [1]
- **Data residency:** Gateway resources are regional; tool definitions and routing configuration are stored in the AWS region where the Gateway is created. Outbound calls to OpenAPI targets or external MCP servers may reach endpoints outside the AWS region depending on where those targets are hosted — this is determined by the customer's target configuration, not by AWS. There is no cross-region inference component in Gateway (unlike Memory) [4]

---

## 3. AWS SBG Enabled Platform Controls

### 3a. Control Mapping

| Control Type | Control | Description |
|---|---|---|
| Detective | CloudTrail — management events | `CreateGateway`, `UpdateGateway`, `DeleteGateway`, `CreateGatewayTarget`, `UpdateGatewayTarget`, `DeleteGatewayTarget`, `GetGateway`, `ListGateways` are logged automatically as management events with no additional configuration [5] |
| Detective | CloudTrail — data events (`InvokeGateway`) | Tool invocations via Gateway are data events and are **not** logged by default; must be explicitly enabled via a CloudTrail trail with advanced event selectors for `AWS::BedrockAgentCore::Gateway`; additional cost applies. Note: data events capture JWT `sub` claims rather than IAM identity — PII must not be used as the `sub` value [5] |
| Detective | CloudWatch + X-Ray tracing | Gateway emits operational metrics to CloudWatch and supports X-Ray tracing for request routing and policy evaluation; used for latency monitoring, error rate alerting, and Cedar policy evaluation debugging [2] |
| Proactive | Service Quotas | Default limits on gateways per account (1,000), targets per gateway (100), tools per target (1,000), and concurrent tool-call connections (50 per gateway, 50 per account) prevent uncontrolled resource proliferation [4] |
| Proactive | Cedar Policy — `LOG_ONLY` mode | AgentCore Policy can be attached to Gateway in `LOG_ONLY` mode before switching to `ENFORCED`, allowing policy rules to be validated against real traffic without blocking requests — reduces risk of misconfiguration causing outages [2] |
| Preventative | OAuth inbound authorisation | Every Gateway requires an attached OAuth authoriser; all inbound agent requests must present a valid JWT bearer token validated against the configured identity provider (Cognito, Okta, Entra ID) before any tool invocation proceeds [1] |
| Preventative | Cedar Policy enforcement (`ENFORCED` mode) | AgentCore Policy (Cedar-based) can be attached to Gateway to enforce deterministic, per-tool access rules — defining which agents can invoke which tools under which conditions, independent of LLM reasoning [2] |
| Preventative | VPC endpoint policy | When PrivateLink is configured, a VPC endpoint policy can restrict which Gateway ARNs are accessible through the endpoint, limiting blast radius if an agent is compromised; note that `Principal` must be `*` due to JWT-based auth [3] |
| Responsive | Gateway and target deletion APIs | Gateways and individual targets can be deleted immediately via API to revoke agent access to all tools or specific integrations during incident response [4] |
| Responsive | Credential provider rotation | API key and OAuth credentials stored in Secrets Manager (`bedrock-agentcore-*` prefix) can be rotated independently of Gateway configuration, enabling rapid credential revocation without redeploying the Gateway [2] |

### 3b. Service Control Policy (SCP)

The following SCP is a production-ready starting point to be attached at the AWS Organizations OU level for accounts using AgentCore Gateway. Substitute `["us-east-1", "eu-west-1"]` with your organisation's approved region list before applying.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyGatewayCreationOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:CreateGateway",
        "bedrock-agentcore:UpdateGateway",
        "bedrock-agentcore:CreateGatewayTarget",
        "bedrock-agentcore:UpdateGatewayTarget"
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
      "Sid": "DenyDeletionOfGatewayAuditTrails",
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
      "Sid": "DenyGatewayCredentialSecretDeletion",
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
      "Sid": "DenyPassingUnboundedRolesToGateway",
      "Effect": "Deny",
      "Action": "iam:PassRole",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "bedrock-agentcore.amazonaws.com"
        },
        "ArnNotLike": {
          "iam:RoleArn": "arn:aws:iam::*:role/AgentCoreApprovedGatewayExecution*",
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyGatewayPolicyEngineDeletion",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:DeletePolicyEngine",
        "bedrock-agentcore:DeletePolicy"
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
      "Sid": "DenyLambdaTargetInvocationByUnauthorisedPrincipals",
      "Effect": "Deny",
      "Action": [
        "lambda:InvokeFunction"
      ],
      "Resource": "arn:aws:lambda:*:*:function:agentcore-*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/AgentCoreApprovedGatewayExecution*",
            "arn:aws:iam::*:role/BreakGlassAdmin"
          ]
        }
      }
    }
  ]
}
```

**SCP limitations — what this policy cannot enforce (must be handled at IAM or application layer):**

- Gateway's data plane uses JWT/OAuth authentication, not SigV4 — VPC endpoint policies cannot restrict inbound tool invocations by IAM principal; the `Principal` field in endpoint policies must be `*` for OAuth callers. Access control for inbound invocations must be enforced via OAuth token validation and Cedar policies at the application layer [3]
- The SCP cannot enforce that a Cedar Policy Engine is attached to a Gateway before it is used in production; this must be enforced via deployment pipeline controls or AWS Config rules
- The SCP cannot enforce that Gateway targets only point to approved internal endpoints — OpenAPI targets can reference any URL, including external internet endpoints. Target URL allowlisting must be enforced via code review and deployment pipeline controls
- VPC endpoint policy caching introduces up to a 15-minute delay before policy changes take effect; the SCP cannot compensate for this — schedule policy changes during maintenance windows [3]
- The SCP cannot prevent Gateway from making outbound calls to external OAuth identity providers for token validation; this internet dependency cannot be eliminated via SCP

---

## 4. AWS Identity & Access Management (IAM)

| Role / Policy | Purpose | Trust Relationship |
|---|---|---|
| `BedrockAgentCoreFullAccess` (AWS managed) | Broad admin access to all AgentCore resources including Gateway; includes Secrets Manager, KMS, S3, Lambda list permissions | Attached to IAM users/roles by account admin; not suitable for production |
| Gateway execution role (customer-managed) | Assumed by the Gateway service at runtime to invoke Lambda targets, evaluate Cedar policies, write CloudWatch logs and X-Ray traces, and access Secrets Manager for credential injection | Trusted by `bedrock-agentcore.amazonaws.com`; trust policy must include `aws:SourceAccount` and `aws:SourceArn` conditions scoped to the specific Gateway ARN to prevent confused deputy attacks [2] |
| Resource management role (customer-managed) | Used by administrators to create/update/delete Gateways, targets, Policy Engines, and Cedar policies; requires `iam:PassRole` scoped to approved execution role naming convention | Trusted by administrator IAM users/roles; separate from the execution role — must not be used at runtime |
| Credential provider role (customer-managed) | Holds API key or OAuth credentials in Secrets Manager (`bedrock-agentcore-*` prefix) for outbound authentication to OpenAPI targets; accessed by the Gateway execution role at invocation time | Accessed by the Gateway execution role via `secretsmanager:GetSecretValue` |

**Least-privilege guidance for production:**
- The Gateway execution role trust policy must include `aws:SourceAccount` and `aws:SourceArn` conditions to prevent any other service or account from assuming the role — this is critical given the role may have Lambda invocation permissions [2]
- Scope the execution role's `lambda:InvokeFunction` permission to specific approved Lambda function ARNs, not `arn:aws:lambda:*:*:function:*`
- Maintain strict separation between the resource management role (used for configuration) and the execution role (used at runtime) — they must never be the same role
- Apply `ManageResourceScopedPolicy` and `ManageAdminPolicy` permissions only to named administrators; these gates control whether Cedar policies can target specific gateways or use wildcards [2]
- Restrict `iam:PassRole` to roles matching an approved naming convention (e.g. `AgentCoreApprovedGatewayExecution*`) conditioned on `iam:PassedToService: bedrock-agentcore.amazonaws.com`

---

## 5. Data Protection

**Encryption at Rest:**
- Gateway configuration data (gateway definitions, target schemas, tool metadata) is stored in DynamoDB and S3 within the AWS-managed service account; encrypted with AWS-managed keys by default. Customer-managed KMS keys (CMK) are supported for the S3 storage layer via `kms:CreateGrant` on the Gateway execution role [4]
- Credential secrets (API keys, OAuth client secrets for outbound target authentication) are stored in AWS Secrets Manager in the customer's account under the `bedrock-agentcore-*` prefix; Secrets Manager supports CMK encryption and is recommended for regulated workloads
- Tool schema payloads stored in customer-provided S3 buckets (for schemas exceeding 1 MB) are encrypted according to the customer's S3 bucket encryption policy — CMK enforcement must be applied via S3 bucket policy
- FIPS 140-3 validated endpoints are available [4]

**Encryption in Transit:**
- All inbound agent-to-Gateway API calls use TLS; the Gateway endpoint URL format is `https://{gateway-id}.gateway.bedrock-agentcore.{region}.amazonaws.com` [3]
- Outbound Gateway-to-Lambda calls traverse the AWS internal network encrypted; outbound calls to external OpenAPI targets use HTTPS as defined in the OpenAPI specification — customers are responsible for ensuring target endpoints enforce TLS
- OAuth token validation calls (inbound auth) and outbound credential exchange with external identity providers traverse the public internet over TLS — these flows cannot be fully privatised via PrivateLink [3]
- No cross-region data movement occurs within Gateway itself; data residency is determined by where Lambda targets and external API endpoints are hosted

---

## 6. Network Security

- Gateway runs entirely in an AWS-managed service account; no compute or storage runs inside the customer's VPC
- PrivateLink is supported for the Gateway data plane via a dedicated endpoint: `com.amazonaws.region.bedrock-agentcore.gateway`; this routes inbound agent-to-Gateway tool invocation traffic privately without traversing the public internet [3]
- Control plane operations (`CreateGateway`, `UpdateGateway`, etc.) use the standard control plane endpoint (`bedrock-agentcore-control.<region>.amazonaws.com`); PrivateLink is not currently supported for Gateway control plane operations [3]
- VPC endpoint policy limitation: because Gateway uses JWT/OAuth authentication rather than SigV4, the `Principal` field in VPC endpoint policies must be set to `*` for OAuth-authenticated callers — IAM-based principal restriction at the network layer is not possible for OAuth flows. Restrict access by specifying the `Resource` field to specific Gateway ARNs instead [3]
- VPC endpoint policy changes are cached for up to 15 minutes before taking effect — factor this into incident response procedures [3]
- Outbound Gateway-to-target traffic: Lambda invocations use the AWS internal network; calls to external OpenAPI targets or remote MCP servers may traverse the public internet depending on where those targets are hosted — customers must ensure external targets enforce TLS and are hosted in approved regions
- OAuth authentication flows (inbound token validation against IdP, outbound credential exchange) require internet connectivity and cannot be routed through PrivateLink — this is an inherent architectural dependency
- Security groups and NACLs do not apply to the Gateway service itself; they apply only to the PrivateLink endpoint network interfaces in the customer's VPC and to Lambda function targets

---

## 7. Logging and Monitoring

**CloudTrail:**
- Management events (logged by default, no additional configuration): `CreateGateway`, `UpdateGateway`, `DeleteGateway`, `CreateGatewayTarget`, `UpdateGatewayTarget`, `DeleteGatewayTarget`, `GetGateway`, `GetGatewayTarget`, `ListGateways`, `ListGatewayTargets` [5]
- Data events (not logged by default — must be explicitly enabled via CloudTrail trail with advanced event selectors for `AWS::BedrockAgentCore::Gateway`; additional cost applies): `InvokeGateway` [5]
- Identity gap in data events: because Gateway uses JWT/OAuth rather than SigV4, data event logs capture the JWT `sub` claim rather than an IAM ARN. If the `sub` claim contains PII (e.g. email addresses), this creates a data handling issue in audit logs — AWS recommends using GUIDs or pairwise identifiers as `sub` values [5]
- Error information in data events is embedded in the `responseElements` field rather than top-level `errorCode`/`errorMessage` fields — SIEM parsing rules must account for this non-standard structure [5]
- CloudTrail logs should be delivered to an S3 bucket with Object Lock (WORM) enabled in a dedicated logging account; for high-volume gateways, data event logging can generate thousands of log entries per minute — storage costs and retention periods must be planned accordingly [5]

**VPC Flow Logs:**
- Gateway does not create ENIs in the customer's VPC by default; VPC Flow Logs are not applicable in the default configuration
- When PrivateLink is configured, the interface endpoint creates ENIs in the customer's subnets; VPC Flow Logs on those subnets will capture inbound traffic from agents to the Gateway PrivateLink endpoint, providing network-level visibility into which workloads are invoking Gateway tools
- Outbound Gateway-to-Lambda traffic and OAuth flows do not appear in customer VPC Flow Logs as they originate from the AWS-managed service account

**Compliance:**
- Amazon Bedrock AgentCore (including Gateway) is in scope for: SOC 1 Type II, SOC 2 Type II, SOC 3, ISO 27001, ISO 27017, ISO 27018, PCI DSS Level 1, HIPAA eligibility, FedRAMP Moderate [6]
- Customer responsibilities not handled by AWS: enabling CloudTrail data event logging for `InvokeGateway` audit trails; configuring PrivateLink for production inbound traffic; attaching Cedar Policy Engine in `ENFORCED` mode before production use; ensuring JWT `sub` claims do not contain PII; enforcing TLS on all external OpenAPI targets; scoping Gateway execution role to specific Lambda ARNs; rotating credentials in Secrets Manager on a defined schedule; retaining CloudTrail logs for the period required by applicable regulations

---

## Sources

1. AWS Docs — Core concepts for Amazon Bedrock AgentCore Gateway: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-core-concepts.html
2. AWS Docs — AgentCore Gateway and Policy IAM Permissions: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-permissions.html
3. AWS Blog — Secure ingress connectivity to AgentCore Gateway using VPC endpoints: https://aws.amazon.com/blogs/machine-learning/secure-ingress-connectivity-to-amazon-bedrock-agentcore-gateway-using-interface-vpc-endpoints/
4. AWS Docs — Quotas for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/bedrock-agentcore-limits.html
5. AWS Docs — AgentCore Gateway event types (CloudTrail): https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-event-types.html
6. AWS What's New — AgentCore generally available (Oct 2025): https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-available
