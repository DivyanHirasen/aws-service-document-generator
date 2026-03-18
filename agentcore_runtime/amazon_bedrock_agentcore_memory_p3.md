# Amazon Bedrock AgentCore Memory — Security Assessment

> Cloud Security Review Board | March 2026

---

## 1. Service Overview

Amazon Bedrock AgentCore Memory is a fully managed, serverless service that provides AI agents with persistent context across sessions through two distinct pipelines: short-term memory (synchronous, within-session event storage) and long-term memory (asynchronous extraction of insights and summaries into a managed vector store) [1]. All data is stored in AWS-managed backend infrastructure within the customer's chosen region; customers do not provision or manage the underlying storage layer. The critical data residency consideration for regulated workloads is that long-term memory extraction uses cross-region inference by default — input prompts and model outputs may traverse secondary AWS regions within the same geography during the extraction process [2].

---

## 2. Underlying Infrastructure & Service Substrate

- **Compute substrate:** Memory's extraction and consolidation pipeline runs on AWS-managed compute in the service account — customers have no visibility into or control over the compute layer. The extraction process invokes Amazon Bedrock foundation models (via the `AmazonBedrockAgentCoreMemoryBedrockModelInferenceExecutionRolePolicy`) to process raw events into long-term memory records; this is the only compute surface [3]
- **Storage substrate:** Short-term memory events and long-term memory records are stored in AWS-managed backend storage (documented as DynamoDB for structured event data and a managed vector store for long-term semantic records). This storage runs in an AWS-managed service account — customers cannot directly access, query, or export the underlying storage via S3, DynamoDB console, or any direct storage API. All access is exclusively through AgentCore Memory APIs [1][4]
- **AWS account boundary:** The Memory service plane, storage, and extraction compute all run in an AWS-managed service account. The customer's account boundary is the Memory API endpoint — data crosses into the AWS service account on every `CreateEvent` call and returns on every `RetrieveMemoryRecords` call. The execution role used for model inference (`AmazonBedrockAgentCoreMemoryBedrockModelInferenceExecutionRolePolicy`) is defined in the customer account but assumed by the service [3]
- **VPC boundary:** AgentCore Memory has no compute or storage running inside the customer's VPC. Memory API calls (both control-plane and data-plane) are made against public AWS endpoints by default. PrivateLink is supported for both data-plane and control-plane Memory endpoints, enabling API calls to be routed privately without traversing the public internet [5]
- **Multi-tenancy model:** Logical namespace isolation per actor/user — each user's memory is stored in a separate logical namespace (e.g. `user/alice/preferences`). Memory stores can be configured to be shared across agents within the same account if explicitly configured. AWS does not publish the physical storage isolation model (shared vs. dedicated tables/indices per customer); encryption with CMK provides the strongest available data isolation guarantee [4]
- **Data residency:** Memory records at rest are stored only in the primary AWS region where the Memory resource is created. However, during long-term memory extraction, input prompts and model outputs may be routed to secondary regions within the same geography (e.g. a US-primary resource may route inference to us-east-1, us-east-2, or us-west-2). CloudTrail and CloudWatch logs do not record which secondary region processed the inference. Customers requiring strict single-region data processing must use a `built-in with overrides` strategy to control model selection and disable automatic cross-region routing [2]

---

## 3. AWS SBG Enabled Platform Controls

### 3a. Control Mapping

| Control Type | Control | Description |
|---|---|---|
| Detective | AWS CloudTrail — management events | `CreateMemory`, `GetMemory`, `UpdateMemory`, `DeleteMemory`, `ListMemories` are logged automatically as management events with no additional configuration [6] |
| Detective | AWS CloudTrail — data events | `CreateEvent`, `RetrieveMemoryRecords`, `DeleteEvent`, `ListMemoryRecords` are data-plane operations; they are **not** logged by default and require a manually configured CloudTrail trail with data event logging enabled — this is a material audit gap for regulated workloads [6] |
| Detective | CloudWatch metrics — `Bedrock-AgentCore` namespace | `TokenCount` metric tracks token consumption for long-term memory extraction per account per region; alerts can be configured to detect anomalous extraction activity or quota exhaustion [7] |
| Proactive | Service Quotas | Default limits on Memory resources per account (150), strategies per memory (6), and API TPS rates prevent uncontrolled resource creation; increases require explicit support ticket [7] |
| Proactive | Memory strategy configuration | Retention periods on memory strategies (7–365 days for event expiration) enforce data minimisation at the service level, limiting how long sensitive data persists in the memory store [1] |
| Preventative | Customer-managed KMS (CMK) | All memory data can be encrypted with a CMK; the KMS key policy must include `kms:ViaService` condition scoped to `bedrock-agentcore.<region>.amazonaws.com`, preventing key use outside the service boundary [8] |
| Preventative | IAM resource-based policies | Access to individual Memory resources can be restricted via resource-based policies (max 20 KB, 100 statements), enabling explicit deny of cross-account access and restricting which agents or principals can read/write memory [6] |
| Preventative | Amazon Bedrock Guardrails | Guardrails can be applied to prompts sent to or from Memory to block prompt injection and memory poisoning — the injection of false or harmful data into long-term memory stores [8] |
| Responsive | `DeleteEvent` and memory deletion APIs | Specific memory events or entire memory stores can be deleted programmatically in response to data subject requests, incident response, or compliance obligations [1] |

### 3b. Service Control Policy (SCP)

The following SCP is a production-ready starting point to be attached at the AWS Organizations OU level for accounts using AgentCore Memory. Substitute `["us-east-1", "eu-west-1"]` with your organisation's approved region list before applying.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyMemoryCreationOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:CreateMemory",
        "bedrock-agentcore:UpdateMemory"
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
      "Sid": "DenyMemoryDataPlaneOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:CreateEvent",
        "bedrock-agentcore:RetrieveMemoryRecords",
        "bedrock-agentcore:ListMemoryRecords",
        "bedrock-agentcore:DeleteEvent"
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
      "Sid": "DenyMemoryWithoutCMKEncryption",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:CreateMemory"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "bedrock-agentcore:KmsKeyId": "true"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyDeletionOfMemoryAuditTrails",
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
      "Sid": "DenyDeletionOfMemoryKMSGrants",
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
      "Sid": "DenyPassingUnboundedRolesToMemoryService",
      "Effect": "Deny",
      "Action": "iam:PassRole",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "bedrock-agentcore.amazonaws.com"
        },
        "ArnNotLike": {
          "iam:RoleArn": "arn:aws:iam::*:role/AgentCoreApprovedMemoryExecution*",
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    }
  ]
}
```

**SCP limitations — what this policy cannot enforce (must be handled at IAM or application layer):**

- The SCP cannot prevent cross-region inference during long-term memory extraction — this is an internal service behaviour controlled by the `built-in with overrides` strategy configuration, not an IAM-enforceable action; customers requiring single-region processing must configure this at the application layer [2]
- There is no SCP condition key to verify that Bedrock Guardrails are attached to Memory prompts; Guardrail enforcement must be implemented in agent application code
- The SCP cannot enforce data event logging for Memory data-plane APIs (`CreateEvent`, `RetrieveMemoryRecords`); CloudTrail trail configuration with data events must be enforced via AWS Config rules or account-level automation
- Memory poisoning (injection of false data via `CreateEvent`) cannot be blocked at the SCP layer — input validation and Guardrails must be applied at the application level
- Cross-agent memory sharing (where one agent reads another agent's memory namespace) is controlled by IAM policy on the Memory resource ARN, not by SCP; this must be enforced via resource-based policies on each Memory resource

---

## 4. AWS Identity & Access Management (IAM)

| Role / Policy | Purpose | Trust Relationship |
|---|---|---|
| `BedrockAgentCoreFullAccess` (AWS managed) | Broad admin access to all AgentCore resources including Memory; includes `kms:Decrypt`, `kms:GenerateDataKey` for CMK operations | Attached to IAM users/roles by account admin; not scoped to Memory only — not suitable for production |
| `AmazonBedrockAgentCoreMemoryBedrockModelInferenceExecutionRolePolicy` (AWS managed) | Allows the Memory service to invoke Bedrock foundation models (`bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`) for long-term memory extraction and consolidation | Trusted by `bedrock-agentcore.amazonaws.com`; passed to the service at Memory resource creation via `iam:PassRole` |
| Agent execution role (customer-managed) | Assumed by the agent at runtime to call Memory data-plane APIs (`CreateEvent`, `RetrieveMemoryRecords`, etc.); must be scoped to specific Memory resource ARNs | Trusted by the agent runtime or calling application; customer-defined |
| KMS key grant role (customer-managed) | Required when using CMK; must include `kms:CreateGrant`, `kms:Decrypt`, `kms:GenerateDataKey`, `kms:DescribeKey`, `kms:ReEncrypt*` | Conditioned on `kms:ViaService: bedrock-agentcore.<region>.amazonaws.com` to restrict key usage to the service [8] |

**Least-privilege guidance for production:**
- Do not use `BedrockAgentCoreFullAccess` in production; create a custom policy scoped to specific Memory resource ARNs and the minimum required actions (`CreateEvent`, `RetrieveMemoryRecords` for agents; `CreateMemory`, `DeleteMemory` for administrators)
- Restrict `iam:PassRole` to roles matching an approved naming convention (e.g. `AgentCoreApprovedMemoryExecution*`) conditioned on `iam:PassedToService: bedrock-agentcore.amazonaws.com`
- Apply resource-based policies on each Memory resource to explicitly deny access from any principal outside the approved agent set, preventing cross-agent memory access unless explicitly intended [6]
- Scope the model inference execution role's `bedrock:InvokeModel` permission to specific approved foundation model ARNs rather than the wildcard `arn:aws:bedrock:*::foundation-model/*`

---

## 5. Data Protection

**Encryption at Rest:**
- All memory data (short-term events and long-term records) is encrypted at rest by default using AWS-managed KMS keys; no customer action is required for baseline encryption [8]
- Customer-managed KMS keys (CMK) are supported and strongly recommended for workloads handling sensitive data; CMK usage requires the calling IAM identity to have `kms:CreateGrant`, `kms:Decrypt`, `kms:GenerateDataKey`, `kms:DescribeKey`, and `kms:ReEncrypt*` permissions, conditioned on `kms:ViaService` scoped to the AgentCore service endpoint [8]
- The underlying storage (managed vector store and event store) runs in an AWS-managed service account; customers cannot directly access, audit, or independently verify the physical storage — CMK encryption is the primary mechanism for ensuring AWS cannot access plaintext data without explicit key grants
- FIPS 140-3 validated endpoints are available for environments with FIPS compliance requirements [6]
- Customer responsibility: preventing memory poisoning (injection of false data into long-term memory stores) is an application-level concern under the AWS Shared Responsibility Model; AWS secures the infrastructure but does not validate the semantic integrity of data written via `CreateEvent` [8]

**Encryption in Transit:**
- All API communication uses TLS 1.2 minimum; TLS 1.3 is recommended [6]
- During long-term memory extraction, input prompts and model outputs are transmitted between AWS regions within the same geography over Amazon's internal encrypted network — this traffic does not traverse the public internet but does cross regional boundaries [2]
- CloudTrail and CloudWatch logs do not record which secondary region processed cross-region inference requests, creating a gap in the audit trail for data movement [2]
- PrivateLink endpoints are available for both Memory data-plane (`com.amazonaws.region.bedrock-agentcore`) and control-plane (`com.amazonaws.region.bedrock-agentcore-control`), enabling fully private API connectivity from a customer VPC [5]

---

## 6. Network Security

- AgentCore Memory has no compute or storage running inside the customer's VPC; it is a fully managed service operating in an AWS-managed service account
- No ENIs are created in the customer's VPC for Memory operations — VPC connectivity for Memory is achieved exclusively via PrivateLink interface endpoints, not via service-linked role ENIs (unlike AgentCore Runtime)
- PrivateLink is supported for both Memory data-plane and control-plane endpoints; this is the recommended configuration for production workloads to eliminate public internet exposure of API calls [5]
- VPC endpoint policy consideration: Memory data-plane APIs support both SigV4 and OAuth Bearer Token authentication; VPC endpoint policies can only restrict access based on IAM principals — OAuth-authenticated requests require the endpoint policy `Principal` to be set to `*`, which means OAuth callers cannot be restricted at the VPC endpoint layer [5]
- Security groups and NACLs do not apply to the Memory service itself; they apply only to the PrivateLink endpoint network interfaces created in the customer's VPC
- Cross-region inference for long-term memory extraction is automatic and enabled by default; it cannot be disabled via network controls — it must be managed through memory strategy configuration (`built-in with overrides`) [2]
- Internet access is not required for Memory API calls when PrivateLink is configured; no NAT Gateway or internet gateway is needed for Memory-specific connectivity

---

## 7. Logging and Monitoring

**CloudTrail:**
- Management events (logged by default): `CreateMemory`, `GetMemory`, `UpdateMemory`, `DeleteMemory`, `ListMemories`
- Data events (not logged by default — must be explicitly enabled via a CloudTrail trail with data event logging; additional cost applies): `CreateEvent`, `RetrieveMemoryRecords`, `DeleteEvent`, `ListMemoryRecords`
- Critical gap: without data event logging enabled, there is no audit trail of what data was written into or read from memory stores — this is a material compliance gap for regulated workloads where auditability of data access is required
- Additional gap: CloudTrail does not record which AWS region processed cross-region inference during long-term memory extraction; the audit trail shows the API call was made but not where the model inference occurred [2]
- CloudTrail logs should be delivered to an S3 bucket with Object Lock (WORM) enabled in a dedicated logging account

**VPC Flow Logs:**
- AgentCore Memory does not create ENIs in the customer's VPC by default; VPC Flow Logs are not applicable in the default configuration
- When PrivateLink is configured, the interface endpoint creates ENIs in the customer's subnets; VPC Flow Logs on those subnets will capture traffic to and from the Memory PrivateLink endpoint, providing network-level visibility into which workloads are calling Memory APIs
- For non-PrivateLink deployments, network-level visibility is limited to CloudTrail API logs and CloudWatch metrics; there is no equivalent of VPC Flow Logs for Memory API traffic over the public internet

**Compliance:**
- Amazon Bedrock AgentCore (including Memory) is in scope for: SOC 1 Type II, SOC 2 Type II, SOC 3, ISO 27001, ISO 27017, ISO 27018, PCI DSS Level 1, HIPAA eligibility, FedRAMP Moderate [9]
- Customer responsibilities not handled by AWS: enabling CloudTrail data event logging for Memory data-plane audit trails; configuring PrivateLink for production workloads; enforcing CMK encryption at Memory resource creation; implementing `built-in with overrides` strategy to control cross-region inference for data residency compliance; applying Bedrock Guardrails to prevent memory poisoning; retaining CloudTrail logs for the period required by applicable regulations; implementing data minimisation via memory strategy retention period configuration

---

## Sources

1. AWS Docs — Add memory to your AgentCore agent: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/memory.html
2. AWS Docs — Cross-region inference in AgentCore Memory: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/cross-region-inference.html
3. AWS Docs — AWS managed policies for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-iam-awsmanpol.html
4. AWS re:Invent 2025 — Deep Dive into AgentCore Memory Architecture: https://www.yopa.page/blog/2025-12-09-deep-dive-into-agentcore-memory-architecture.html
5. AWS Docs — Use interface VPC endpoints (PrivateLink) for AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc-interface-endpoints.html
6. AWS Docs — Data protection in Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-protection.html
7. AWS Docs — Quotas for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/bedrock-agentcore-limits.html
8. AWS Docs — Encrypt your Amazon Bedrock AgentCore Memory: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/storage-encryption.html
9. AWS What's New — AgentCore generally available (Oct 2025): https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-available
