# Amazon Bedrock AgentCore Runtime — Security Assessment

> Cloud Security Review Board | March 2026

---

## 1. Service Overview

Amazon Bedrock AgentCore Runtime is a fully managed, serverless execution environment for deploying and operating AI agents and tools at scale, with no customer-managed compute infrastructure [1]. Each user session runs inside a dedicated Firecracker microVM — isolated CPU, memory, and filesystem — that is fully terminated and memory-sanitised on session completion, providing deterministic security boundaries even for non-deterministic AI workloads [2]. The service is framework-agnostic and model-agnostic, supporting any open-source agent framework and any LLM in or outside Amazon Bedrock.

---

## 2. Underlying Infrastructure & Service Substrate

- **Compute substrate:** Firecracker microVMs — the same open-source VMM used by AWS Lambda and AWS Fargate. Each session receives a dedicated microVM; compute is not shared between sessions or customers. The microVM is ephemeral: it is created on first invocation and destroyed on session termination or timeout [2][3]
- **Storage substrate:** Agent code is stored in Amazon ECR (container image deployments, up to 2 GB) or Amazon S3 (direct code deployments, up to 250 MB compressed). Both are AWS-managed storage services within the customer's own AWS account. Session state is held in-memory within the microVM only — it is not persisted to any external store. For durable context, state must be explicitly externalised to AgentCore Memory or another store [3]
- **AWS account boundary:** The Runtime service plane (scaling, session orchestration, microVM lifecycle) runs in an AWS-managed service account. The customer's container image is pulled from ECR in the customer's account. The execution role assumed by the agent at runtime is defined in and belongs to the customer's account. API calls (control-plane and data-plane) are made against AWS-managed endpoints [1]
- **VPC boundary:** By default, Runtime microVMs run outside the customer's VPC. VPC connectivity is opt-in: when configured, AWS creates Elastic Network Interfaces (ENIs) in the customer's specified subnets via the `AWSServiceRoleForBedrockAgentCoreNetwork` service-linked role, enabling the microVM to reach private VPC resources. The VPC configuration covers outbound connectivity from the microVM to VPC resources — it does not place the microVM itself inside the VPC [4]
- **Multi-tenancy model:** Hardware-level isolation per session via Firecracker microVM. Each session has isolated CPU, memory, and filesystem. After session termination, the entire microVM is destroyed and memory is sanitised — no residual state can persist to a subsequent session or customer [2]
- **Data residency:** Runtime resources are regional; agent code and session execution remain within the AWS region where the Runtime is created. Cross-region inference is not a feature of Runtime itself (it applies to AgentCore Memory's extraction pipeline). Customers must create Runtime resources only in approved regions to enforce data residency [1]

---

## 3. AWS SBG Enabled Platform Controls

### 3a. Control Mapping

| Control Type | Control | Description |
|---|---|---|
| Detective | AWS CloudTrail — management events | All control-plane API calls (`CreateAgentRuntime`, `UpdateAgentRuntime`, `DeleteAgentRuntime`, `CreateAgentRuntimeEndpoint`, etc.) are logged automatically as management events in CloudTrail with no additional configuration required [5] |
| Detective | AWS CloudTrail — data events | `InvokeAgentRuntime`, `InvokeAgentRuntimeCommand`, and `InvokeAgentRuntimeWithWebSocketStream` are data-plane events; they are **not** logged by default and require a manually configured CloudTrail trail with data event logging enabled — this incurs additional cost [6] |
| Detective | Amazon CloudWatch metrics + X-Ray tracing | Runtime emits agent-specific metrics to the `bedrock-agentcore` CloudWatch namespace and supports X-Ray tracing for reasoning steps and tool invocations; alerts can be configured on invocation rates, error rates, and session counts [7] |
| Proactive | AWS Service Quotas | Default limits on active sessions (1,000 in us-east-1/us-west-2; 500 elsewhere), agents per account (1,000), and TPS per endpoint (25) prevent uncontrolled resource proliferation; quota increases require explicit support ticket approval [8] |
| Proactive | IAM `iam:PassRole` restriction | The execution role passed to AgentCore Runtime at creation can be restricted via IAM condition (`iam:RoleSessionName`, `iam:PassedToService`) to prevent developers from passing overly permissive roles to agent runtimes [7] |
| Preventative | IAM resource-based policies | Access to individual Runtime resources can be scoped via resource-based policies (max 20 KB, 100 statements), enabling explicit deny of cross-account access and restricting invocation to approved principals [7] |
| Preventative | VPC + Security Groups | When VPC mode is enabled, outbound traffic from the microVM is governed by security group rules on the ENIs created in the customer's VPC, enforcing network-level access control to downstream resources [4] |
| Responsive | Runtime versioning + endpoint rollback | Immutable version snapshots and named endpoints allow immediate rollback to a known-good version without downtime if a deployed agent version exhibits unexpected behaviour [3] |
| Responsive | Session termination APIs | Sessions can be terminated programmatically; the microVM is destroyed and memory sanitised immediately, providing a responsive control for incident containment [2] |

### 3b. Service Control Policy (SCP)

The following SCP is a production-ready starting point to be attached at the AWS Organizations OU level for accounts using AgentCore Runtime. Substitute `["us-east-1", "eu-west-1"]` with your organisation's approved region list before applying.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAgentCoreRuntimeOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:CreateAgentRuntime",
        "bedrock-agentcore:UpdateAgentRuntime",
        "bedrock-agentcore:CreateAgentRuntimeEndpoint",
        "bedrock-agentcore:InvokeAgentRuntime",
        "bedrock-agentcore:InvokeAgentRuntimeCommand",
        "bedrock-agentcore:InvokeAgentRuntimeWithWebSocketStream"
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
      "Sid": "DenyAgentCoreRuntimeDeletionOfAuditConfig",
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
      "Sid": "DenyAgentCoreRuntimeWithoutExecutionRole",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:CreateAgentRuntime"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "bedrock-agentcore:ExecutionRoleArn": "true"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyCodeInterpreterInvocationByUnauthorisedPrincipals",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:InvokeCodeInterpreter",
        "bedrock-agentcore:StartCodeInterpreterSession"
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
    },
    {
      "Sid": "DenyPassingUnboundedRolesToAgentCore",
      "Effect": "Deny",
      "Action": "iam:PassRole",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "bedrock-agentcore.amazonaws.com"
        },
        "ArnNotLike": {
          "iam:RoleArn": "arn:aws:iam::*:role/AgentCoreApprovedExecution*",
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyDeletionOfAgentCoreServiceLinkedRoles",
      "Effect": "Deny",
      "Action": [
        "iam:DeleteServiceLinkedRole"
      ],
      "Resource": [
        "arn:aws:iam::*:role/aws-service-role/network.bedrock-agentcore.amazonaws.com/*",
        "arn:aws:iam::*:role/aws-service-role/runtime-identity.bedrock-agentcore.amazonaws.com/*"
      ],
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    }
  ]
}
```

**SCP limitations — what this policy cannot enforce (must be handled at IAM or application layer):**

- AgentCore Runtime does not currently support resource-based policies, so per-resource invocation restrictions cannot be enforced at the resource level — the Code Interpreter SCP statement above is the only centralised mechanism to restrict invocation access [6]
- There is no SCP condition key to enforce CMK encryption on Runtime deployments; CMK usage for any persisted artefacts (ECR images, S3 code packages) must be enforced via S3 bucket policies and ECR repository policies in the customer account
- `InvokeAgentRuntime` data-plane events are not logged by default — CloudTrail data event logging must be enabled separately via account-level configuration; the SCP cannot enforce this
- The SCP cannot restrict which container images or agent frameworks are deployed into a Runtime; image signing (ECR image signing with AWS Signer) and admission controls must be enforced at the CI/CD pipeline level

---

## 4. AWS Identity & Access Management (IAM)

| Role / Policy | Purpose | Trust Relationship |
|---|---|---|
| `BedrockAgentCoreFullAccess` (AWS managed) | Broad admin access to all AgentCore resources; suitable for initial setup only — not for production | Attached to IAM users/roles by account admin; not scoped to Runtime only |
| Agent execution role (customer-managed) | Assumed by AgentCore Runtime to run the agent; requires permissions for CloudWatch Logs, X-Ray, CloudWatch metrics, and Bedrock model invocation | Trusted by `bedrock-agentcore.amazonaws.com`; scoped to the specific Runtime ARN via trust policy condition |
| `AWSServiceRoleForBedrockAgentCoreNetwork` (service-linked) | Created automatically when VPC mode is enabled; allows AgentCore to create and manage ENIs in the customer VPC | Trusted by `network.bedrock-agentcore.amazonaws.com`; cannot be assumed by customer principals |
| `BedrockAgentCoreRuntimeIdentityServiceRolePolicy` (service-linked) | Allows AgentCore to manage workload identity access tokens and OAuth credentials for inbound/outbound auth | Trusted by `runtime-identity.bedrock-agentcore.amazonaws.com` |

**Least-privilege guidance for production:**
- Do not use `BedrockAgentCoreFullAccess` in production; create a custom policy scoped to specific Runtime ARNs and required actions only
- Scope the execution role's `bedrock:InvokeModel` permission to specific approved foundation model ARNs — not `arn:aws:bedrock:*::foundation-model/*`
- Restrict `iam:PassRole` to roles matching a naming convention (e.g. `AgentCoreApprovedExecution*`) and conditioned on `iam:PassedToService: bedrock-agentcore.amazonaws.com`
- Apply resource-based policies on Runtime resources to explicitly deny invocation from any principal outside the approved set [7]

---

## 5. Data Protection

**Encryption at Rest:**
- Agent container images stored in Amazon ECR are encrypted using AWS-managed KMS keys by default; customer-managed KMS keys (CMK) are supported at the ECR repository level and are recommended for regulated workloads
- Direct code deployment packages are stored in S3 (`bedrock-agentcore-runtime-*` prefix buckets); S3 server-side encryption applies; CMK enforcement can be applied via S3 bucket policy requiring `aws:kms` encryption
- Session state is held exclusively in-memory within the Firecracker microVM for the duration of the session — it is not written to any persistent store and is destroyed when the microVM terminates; there is no customer-accessible persistent session storage to encrypt
- There is no AWS-provided CMK condition key for Runtime resource creation itself; encryption enforcement for artefacts must be applied at the ECR and S3 layer [5]

**Encryption in Transit:**
- All API communication (control-plane and data-plane) uses TLS 1.2 minimum; TLS 1.3 is recommended [5]
- FIPS 140-3 validated endpoints are available for environments with FIPS compliance requirements
- Internal communication between the Runtime service plane and the customer's VPC resources (when VPC mode is enabled) traverses the ENI within the AWS network — not the public internet
- AgentCore Runtime does not perform cross-region data movement; session execution and artefact storage remain in the region where the Runtime is created

---

## 6. Network Security

- Runtime microVMs run in an AWS-managed service account by default — they are not inside the customer's VPC and are not subject to customer-managed security groups or NACLs in the default configuration
- VPC connectivity is opt-in: configured by specifying subnet IDs and security group IDs at Runtime creation; AWS creates ENIs in the customer's subnets via the `AWSServiceRoleForBedrockAgentCoreNetwork` service-linked role; ENIs persist up to 8 hours after agent deletion [4]
- VPC mode covers outbound connectivity from the microVM to private VPC resources only; it does not place the microVM inside the VPC or restrict inbound invocation traffic
- PrivateLink (VPC interface endpoint) is supported for data-plane inbound API calls when the calling application is hosted inside a customer VPC; control-plane endpoints do not currently support PrivateLink [4]
- Internet access from a VPC-connected Runtime requires a NAT Gateway in a public subnet; connecting to a public subnet directly does not provide internet access
- Security groups and NACLs do not apply to the Runtime microVM itself — they apply only to the ENIs created in the customer's VPC for outbound connectivity; inbound invocation access is controlled entirely via IAM and OAuth
- Required VPC endpoints for air-gapped deployments (no internet): `ecr.dkr`, `ecr.api`, `s3` (gateway), `logs` (CloudWatch) [4]

---

## 7. Logging and Monitoring

**CloudTrail:**
- Management events (logged by default, no additional configuration): `CreateAgentRuntime`, `UpdateAgentRuntime`, `DeleteAgentRuntime`, `CreateAgentRuntimeEndpoint`, `DeleteAgentRuntimeEndpoint`, `ListAgentRuntimes`, `GetAgentRuntime`
- Data events (not logged by default — must be explicitly enabled via a CloudTrail trail; additional cost applies): `InvokeAgentRuntime`, `InvokeAgentRuntimeCommand`, `InvokeAgentRuntimeWithWebSocketStream`
- Gap: Code Interpreter invocations (`InvokeCodeInterpreter`) are also data events and are not logged by default; this is a material audit gap given the privilege escalation risk associated with custom Code Interpreters — data event logging must be enabled and monitored [6]
- CloudTrail logs should be delivered to an S3 bucket with Object Lock (WORM) enabled and access restricted to a dedicated logging account to prevent tampering

**VPC Flow Logs:**
- AgentCore Runtime does not create ENIs in the customer VPC by default; VPC Flow Logs are therefore not applicable in the default (non-VPC) configuration
- When VPC mode is enabled, ENIs are created in the customer's subnets and VPC Flow Logs will capture outbound traffic from the Runtime to VPC resources — this provides network-level visibility into which internal endpoints the agent is communicating with
- For non-VPC deployments, network-level visibility is limited to CloudTrail API logs and CloudWatch metrics; there is no equivalent of VPC Flow Logs for traffic between the Runtime service plane and external endpoints

**Compliance:**
- Amazon Bedrock (and AgentCore as a sub-service) is in scope for: SOC 1 Type II, SOC 2 Type II, SOC 3, ISO 27001, ISO 27017, ISO 27018, PCI DSS Level 1, HIPAA eligibility, FedRAMP Moderate [1]
- Customer responsibilities not handled by AWS: enabling CloudTrail data event logging for invocation audit trails; enforcing CMK encryption on ECR and S3 artefacts; configuring VPC PrivateLink for production workloads to eliminate public internet exposure; implementing AgentCore Policy (Cedar guardrails) for deterministic tool-call enforcement; ensuring agent execution roles follow least-privilege; retaining CloudTrail logs for the period required by applicable regulations

---

## Sources

1. AWS What's New — AgentCore generally available (Oct 2025): https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-available
2. AWS Docs — Host agent or tools with AgentCore Runtime: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agents-tools-runtime.html
3. AWS Docs — How AgentCore Runtime works: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-how-it-works.html
4. AWS Docs — Configure AgentCore Runtime for VPC: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html
5. AWS Docs — Data protection in Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-protection.html
6. Sonrai Security — AWS AgentCore privilege escalation and SCP guidance (May 2026): https://sonraisecurity.com/blog/aws-agentcore-privilege-escalation-bedrock-scp-fix/
7. AWS Docs — IAM Permissions for AgentCore Runtime: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-permissions.html
8. AWS Docs — Quotas for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/bedrock-agentcore-limits.html
