# Amazon Bedrock AgentCore Policy — Security Assessment

> Cloud Security Review Board | March 2026

---

## 1. Service Overview

Amazon Bedrock AgentCore Policy is a fully managed, serverless authorisation layer that intercepts every agent-to-tool request flowing through AgentCore Gateway and evaluates it against deterministic Cedar policies before allowing or denying tool access — operating entirely outside agent code [1]. Policies are stored in a Policy Engine (a named collection of Cedar policies) that is attached to one or more Gateways; the service supports two enforcement modes: `LOG_ONLY` (evaluate and log without blocking) and `ENFORCED` (evaluate and block on deny) [2]. The critical security characteristic for regulated workloads is that the natural language policy authoring feature invokes Amazon Bedrock foundation models via cross-region inference, meaning input prompts describing business rules may be processed in secondary AWS regions within the same geography — the same data residency consideration that applies to AgentCore Memory [3].

---

## 2. Underlying Infrastructure & Service Substrate

- **Compute substrate:** Policy evaluation runs on AWS-managed serverless compute in an AWS-managed service account — the same shared service plane as AgentCore Gateway. Cedar policy evaluation is loop-free and has no side effects (no file system access, no networking), so it can be evaluated without sandboxing; AWS does not publish the physical isolation model for the evaluation compute layer [2]
- **Storage substrate:** Policy Engines and Cedar policies are stored in AWS-managed backend storage (DynamoDB and S3) within the AWS-managed service account — the same storage substrate as Gateway configuration. Customers cannot directly access, query, or export the underlying policy store via DynamoDB console or S3. All access is exclusively through AgentCore Policy APIs (`CreatePolicyEngine`, `CreatePolicy`, `GetPolicy`, etc.) [1][4]
- **AWS account boundary:** The Policy service plane, policy storage, and evaluation compute all run in an AWS-managed service account. The customer's account boundary is the Policy API endpoint — policy definitions cross into the AWS service account on every `CreatePolicy` call and are retrieved on every `AuthorizeAction` evaluation. The Gateway execution role (defined in the customer's account) must have `bedrock-agentcore:AuthorizeAction`, `bedrock-agentcore:PartiallyAuthorizeActions`, and `bedrock-agentcore:GetPolicyEngine` permissions to call the Policy service at runtime [4]
- **VPC boundary:** AgentCore Policy has no compute or storage running inside the customer's VPC. Policy API calls (control-plane and data-plane) are made against public AWS endpoints by default. PrivateLink is supported for the data plane via the shared `com.amazonaws.region.bedrock-agentcore` endpoint; control-plane operations (`CreatePolicyEngine`, `CreatePolicy`, etc.) use `bedrock-agentcore-control.<region>.amazonaws.com`, for which PrivateLink is not currently supported [5]
- **Multi-tenancy model:** Policy Engines and Cedar policies are logically isolated per customer account and per Policy Engine ARN. Cedar evaluation is stateless and has no cross-customer data paths. AWS does not publish the physical storage isolation model; CMK encryption provides the strongest available data isolation guarantee for policy definitions stored in the AWS-managed service account [2]
- **Data residency:** Cedar policy definitions at rest are stored only in the primary AWS region where the Policy Engine is created. However, the natural language policy authoring feature (`StartPolicyGeneration`) invokes Bedrock foundation models via cross-region inference — input prompts (natural language rule descriptions) and generated Cedar output may be processed in secondary regions within the same geography (e.g. a US-primary Policy Engine may route inference to us-east-1, us-east-2, or us-west-2). CloudTrail and CloudWatch logs do not record which secondary region processed the inference. Customers requiring strict single-region processing must author policies directly in Cedar rather than using the natural language generation feature [3]

---

## 3. AWS Enabled Platform Controls

### 3a. Control Mapping

| Control Type | Control | Description |
|---|---|---|
| Detective | CloudTrail — management events | `CreatePolicyEngine`, `UpdatePolicyEngine`, `DeletePolicyEngine`, `ListPolicyEngines`, `GetPolicyEngine`, `CreatePolicy`, `UpdatePolicy`, `DeletePolicy`, `GetPolicy`, `ListPolicies`, `StartPolicyGeneration`, `GetPolicyGeneration` are logged automatically as management events with no additional configuration [6] |
| Detective | CloudTrail — data events (`AuthorizeAction`, `PartiallyAuthorizeActions`) | Policy evaluation calls are data-plane operations; they are **not** logged by default and require a manually configured CloudTrail trail with data event logging enabled — this is a material audit gap for regulated workloads where every policy decision must be auditable [6] |
| Detective | CloudWatch — policy evaluation metrics | Policy in AgentCore emits evaluation metrics (allow/deny counts, evaluation latency) to CloudWatch; alerts can be configured to detect anomalous denial rates, policy misconfiguration, or quota exhaustion [2] |
| Proactive | `LOG_ONLY` mode pre-production validation | Policy Engines can be attached to a Gateway in `LOG_ONLY` mode before switching to `ENFORCED`, allowing Cedar policies to be validated against real agent traffic without blocking requests — reduces risk of misconfiguration causing production outages [2] |
| Proactive | Automated reasoning analysis on policy generation | When using natural language authoring, the service runs automated reasoning checks on generated Cedar policies to surface overly permissive, overly restrictive, or unsatisfiable conditions before the policy is saved — preventing misconfigured policies from reaching production [1] |
| Preventative | Cedar default-deny + forbid-wins semantics | If no `permit` policy matches a request, it is denied by default; `forbid` rules always override `permit` rules regardless of evaluation order — providing deterministic, composable enforcement that cannot be bypassed by agent reasoning or prompt injection [2] |
| Preventative | Customer-managed KMS (CMK) | Policy Engine data (Cedar policy definitions) can be encrypted with a CMK; the KMS key policy must include `kms:ViaService` scoped to `bedrock-agentcore.<region>.amazonaws.com`, preventing key use outside the service boundary [7] |
| Preventative | `ManageResourceScopedPolicy` / `ManageAdminPolicy` permission gates | These IAM permission-only gates control whether an administrator can create Cedar policies targeting specific Gateway ARNs (`ManageResourceScopedPolicy`) or wildcard Gateway ARNs (`ManageAdminPolicy`) — limiting blast radius of misconfigured policies [4] |
| Responsive | `DeletePolicy` and `DeletePolicyEngine` APIs | Individual Cedar policies or entire Policy Engines can be deleted immediately via API to revoke enforcement rules during incident response; Gateway falls back to default-deny if the attached Policy Engine is removed [4] |
| Responsive | Mode switching (`LOG_ONLY` ↔ `ENFORCED`) | A Policy Engine can be switched from `ENFORCED` back to `LOG_ONLY` via `UpdateGateway` without deleting the policy, enabling rapid rollback of enforcement without losing policy definitions [2] |

### 3b. Service Control Policy (SCP)

The following SCP is a production-ready starting point to be attached at the AWS Organizations OU level for accounts using AgentCore Policy. Substitute `["us-east-1", "eu-west-1"]` with your organisation's approved region list before applying.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPolicyEngineCreationOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:CreatePolicyEngine",
        "bedrock-agentcore:UpdatePolicyEngine",
        "bedrock-agentcore:CreatePolicy",
        "bedrock-agentcore:UpdatePolicy"
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
      "Sid": "DenyPolicyEngineDeletionByUnauthorisedPrincipals",
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
      "Sid": "DenyNaturalLanguagePolicyGenerationOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:StartPolicyGeneration"
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
      "Sid": "DenyDeletionOfPolicyAuditTrails",
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
      "Sid": "DenyDeletionOfPolicyKMSGrants",
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
      "Sid": "DenyPassingUnboundedRolesToPolicyService",
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
      "Sid": "DenyDetachingPolicyEngineFromGateway",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:UpdateGateway"
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
    }
  ]
}
```

**SCP limitations — what this policy cannot enforce (must be handled at IAM or application layer):**

- The SCP cannot enforce that a Policy Engine is in `ENFORCED` mode (rather than `LOG_ONLY`) before a Gateway is used in production; mode enforcement must be implemented via deployment pipeline controls or AWS Config rules checking the Gateway's `policyEngineConfig.enforcementMode` attribute
- The SCP cannot prevent cross-region inference during natural language policy generation (`StartPolicyGeneration`) — this is an internal service behaviour; customers requiring strict single-region processing must author Cedar policies directly and prohibit use of `StartPolicyGeneration` via IAM deny, not SCP
- There is no SCP condition key to enforce CMK encryption on Policy Engine creation; CMK enforcement must be implemented via an AWS Config rule or deployment pipeline check that validates the `kmsKeyId` field is set on `CreatePolicyEngine` calls
- The `DenyDetachingPolicyEngineFromGateway` statement restricts all `UpdateGateway` calls to approved admins — this is intentionally broad because `UpdateGateway` is the same API used to detach a Policy Engine; teams must ensure the approved admin role list is tightly controlled
- The SCP cannot enforce that Cedar policies follow least-privilege principles (e.g. that `permit` rules are not overly broad); policy review must be enforced via code review, the automated reasoning analysis feature, and periodic policy audits
- `AuthorizeAction` and `PartiallyAuthorizeActions` are runtime evaluation calls made by the Gateway execution role — they cannot be meaningfully restricted by SCP without breaking Gateway functionality; access control for these calls must be enforced via IAM policy scoped to specific Policy Engine and Gateway ARNs [4]

---

## 4. AWS Identity & Access Management (IAM)

| Role / Policy | Purpose | Trust Relationship |
|---|---|---|
| `BedrockAgentCoreFullAccess` (AWS managed) | Broad admin access to all AgentCore resources including Policy; includes `bedrock-agentcore:*` wildcard — not suitable for production | Attached to IAM users/roles by account admin |
| Gateway execution role (customer-managed) | Assumed by AgentCore Gateway at runtime to evaluate Cedar policies; must include `bedrock-agentcore:AuthorizeAction`, `bedrock-agentcore:PartiallyAuthorizeActions`, `bedrock-agentcore:GetPolicyEngine` scoped to specific Policy Engine and Gateway ARNs | Trusted by `bedrock-agentcore.amazonaws.com`; trust policy must include `aws:SourceAccount` and `aws:SourceArn` conditions scoped to the specific Gateway ARN to prevent confused deputy attacks [4] |
| Resource management role (customer-managed) | Used by administrators to create/update/delete Policy Engines and Cedar policies; requires `bedrock-agentcore:CreatePolicyEngine`, `CreatePolicy`, `UpdatePolicy`, `DeletePolicy`, `StartPolicyGeneration`, `ManageResourceScopedPolicy`, `ManageAdminPolicy`, and `iam:PassRole` scoped to approved execution role naming convention | Trusted by administrator IAM users/roles; must be kept strictly separate from the Gateway execution role |
| KMS key grant role (customer-managed) | Required when using CMK for Policy Engine encryption; must include `kms:CreateGrant`, `kms:DescribeKey`, `kms:Decrypt`, `kms:GenerateDataKey` conditioned on `kms:ViaService: bedrock-agentcore.<region>.amazonaws.com` | Held by the Gateway execution role or resource management role depending on operation [7] |

**Least-privilege guidance for production:**
- The Gateway execution role's Policy permissions must be scoped to specific Policy Engine and Gateway ARNs — not wildcards; both `AuthorizeAction`/`PartiallyAuthorizeActions` and `GetPolicyEngine` require both the `policy-engine/<id>` and `gateway/<id>` ARNs in the `Resource` array [4]
- Missing any of the three required Policy permissions (`AuthorizeAction`, `PartiallyAuthorizeActions`, `GetPolicyEngine`) causes `InternalServerException` on policy evaluation and silent failures in `LOG_ONLY` mode — validate all three are present before switching to `ENFORCED` mode
- `ManageAdminPolicy` (allows wildcard Cedar policies) must be granted only to named senior administrators; `ManageResourceScopedPolicy` (allows resource-scoped Cedar policies) can be granted to a broader set of policy authors
- Maintain strict separation between the resource management role (policy authoring) and the Gateway execution role (runtime evaluation) — they must never be the same role, as the execution role has no need for `CreatePolicy` or `DeletePolicy` permissions

---

## 5. Data Protection

**Encryption at Rest:**
- Cedar policy definitions and Policy Engine configuration are stored in AWS-managed backend storage (DynamoDB and S3) within the AWS-managed service account; encrypted with AWS-managed KMS keys by default [7]
- Customer-managed KMS keys (CMK) are supported for Policy Engine data; the KMS key policy must grant the Gateway execution role `kms:CreateGrant`, `kms:DescribeKey`, `kms:Decrypt`, and `kms:GenerateDataKey`, conditioned on `kms:ViaService` scoped to `bedrock-agentcore.<region>.amazonaws.com` [7]
- CMK encryption is the primary mechanism for ensuring AWS cannot access plaintext Cedar policy definitions without explicit key grants — this is relevant because Cedar policies may encode sensitive business rules (e.g. transaction limits, data access boundaries)
- Natural language policy generation inputs (plain English rule descriptions submitted via `StartPolicyGeneration`) are processed by Bedrock foundation models; these inputs are not persisted beyond the generation request but may traverse secondary regions during cross-region inference [3]
- FIPS 140-3 validated endpoints are available for environments with FIPS compliance requirements [5]

**Encryption in Transit:**
- All API communication (control-plane and data-plane) uses TLS 1.2 minimum; TLS 1.3 is recommended [5]
- During natural language policy generation, input prompts and generated Cedar output are transmitted between AWS regions within the same geography over Amazon's internal encrypted network — this traffic does not traverse the public internet but does cross regional boundaries [3]
- CloudTrail and CloudWatch logs do not record which secondary region processed cross-region inference during policy generation, creating a gap in the audit trail for data movement [3]
- PrivateLink endpoints are available for Policy data-plane operations via `com.amazonaws.region.bedrock-agentcore`; control-plane operations (`CreatePolicyEngine`, `CreatePolicy`, etc.) do not currently support PrivateLink and must traverse the public internet or be routed via NAT [5]

---

## 6. Network Security

- AgentCore Policy has no compute or storage running inside the customer's VPC; it is a fully managed service operating in an AWS-managed service account
- PrivateLink is supported for Policy data-plane operations (runtime `AuthorizeAction` and `PartiallyAuthorizeActions` calls made by the Gateway execution role) via the shared `com.amazonaws.region.bedrock-agentcore` endpoint [5]
- Control-plane operations (`CreatePolicyEngine`, `CreatePolicy`, `UpdatePolicy`, `DeletePolicy`, `StartPolicyGeneration`) use `bedrock-agentcore-control.<region>.amazonaws.com`; PrivateLink is not currently supported for these endpoints — they require internet connectivity or a NAT Gateway [5]
- VPC endpoint policy consideration: Policy data-plane APIs support both SigV4 and OAuth Bearer Token authentication; VPC endpoint policies can only restrict access based on IAM principals — OAuth-authenticated requests require the endpoint policy `Principal` to be set to `*`, which means OAuth callers cannot be restricted at the VPC endpoint layer [5]
- Security groups and NACLs do not apply to the Policy service itself; they apply only to the PrivateLink endpoint network interfaces created in the customer's VPC
- Cross-region inference for natural language policy generation is automatic when `StartPolicyGeneration` is called; it cannot be disabled via network controls — customers requiring strict single-region processing must author Cedar policies directly and deny `StartPolicyGeneration` via IAM policy [3]
- Internet access is not required for Policy data-plane calls (runtime evaluation) when PrivateLink is configured; control-plane calls (policy management) require internet connectivity until PrivateLink support is extended to the control plane

---

## 7. Logging and Monitoring

**CloudTrail:**
- Management events (logged by default, no additional configuration): `CreatePolicyEngine`, `UpdatePolicyEngine`, `DeletePolicyEngine`, `GetPolicyEngine`, `ListPolicyEngines`, `CreatePolicy`, `UpdatePolicy`, `DeletePolicy`, `GetPolicy`, `ListPolicies`, `StartPolicyGeneration`, `GetPolicyGeneration`, `ListPolicyGenerations`, `ListPolicyGenerationAssets`
- Data events (not logged by default — must be explicitly enabled via a CloudTrail trail with data event logging; additional cost applies): `AuthorizeAction`, `PartiallyAuthorizeActions` — these are the runtime policy evaluation calls that represent every allow/deny decision made by the Policy Engine
- Critical gap: without data event logging enabled for `AuthorizeAction`, there is no audit trail of individual policy decisions — which agent invoked which tool, what the Cedar evaluation result was, and what context was evaluated. This is a material compliance gap for regulated workloads where auditability of access control decisions is required
- Additional gap: CloudTrail does not record which AWS region processed cross-region inference during `StartPolicyGeneration`; the audit trail shows the API call was made but not where the model inference occurred [3]
- CloudTrail logs should be delivered to an S3 bucket with Object Lock (WORM) enabled in a dedicated logging account; for high-volume gateways with Policy attached, data event logging for `AuthorizeAction` can generate very high log volumes — storage costs and retention periods must be planned accordingly

**VPC Flow Logs:**
- AgentCore Policy does not create ENIs in the customer's VPC; VPC Flow Logs are not applicable for Policy-specific traffic
- When PrivateLink is configured for the `bedrock-agentcore` data plane endpoint, the interface endpoint creates ENIs in the customer's subnets; VPC Flow Logs on those subnets will capture traffic from the Gateway execution role to the Policy evaluation endpoint, providing network-level visibility into evaluation call volumes
- Control-plane policy management calls (over the public internet) do not appear in customer VPC Flow Logs; CloudTrail management events are the only audit record for policy authoring activity

**Compliance:**
- Amazon Bedrock AgentCore (including Policy) is in scope for: SOC 1 Type II, SOC 2 Type II, SOC 3, ISO 27001, ISO 27017, ISO 27018, PCI DSS Level 1, HIPAA eligibility, FedRAMP Moderate [8]
- Customer responsibilities not handled by AWS: enabling CloudTrail data event logging for `AuthorizeAction` and `PartiallyAuthorizeActions` to create an audit trail of policy decisions; configuring PrivateLink for data-plane evaluation calls in production; enforcing CMK encryption on Policy Engine creation; switching Policy Engines from `LOG_ONLY` to `ENFORCED` before production use; authoring Cedar policies directly (rather than via natural language generation) for workloads with strict single-region data processing requirements; periodically reviewing Cedar policies for over-permissiveness using the automated reasoning analysis feature; retaining CloudTrail logs for the period required by applicable regulations

---

## Sources

1. AWS Docs — Policy in Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy.html
2. AWS Blog — Secure AI agents with Policy in Amazon Bedrock AgentCore: https://aws.amazon.com/blogs/machine-learning/secure-ai-agents-with-policy-in-amazon-bedrock-agentcore/
3. AWS Docs — Cross-region inference in AgentCore Memory, Policy, and Evaluations: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/cross-region-inference.html
4. AWS Docs — AgentCore Gateway and Policy IAM Permissions: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-permissions.html
5. AWS Docs — Use interface VPC endpoints (PrivateLink) for AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc-interface-endpoints.html
6. AWS Docs — AgentCore Gateway event types (CloudTrail): https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-event-types.html
7. AWS Docs — Encrypt your AgentCore gateway with a customer-managed KMS key: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-encryption.html
8. AWS What's New — Policy in Amazon Bedrock AgentCore generally available (March 2026): https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/
