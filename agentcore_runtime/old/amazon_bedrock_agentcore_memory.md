# Amazon Bedrock AgentCore Memory — Service Assessment

> Banking / Financial Services Risk & Compliance | March 2026

---

## 1. Service Overview

Amazon Bedrock AgentCore Memory is a fully managed service that enables AI agents to retain context across interactions through both short-term (within-session) and long-term (cross-session) memory, without requiring customers to build or manage memory infrastructure [1]. It addresses the fundamental statelessness problem in agentic AI by automatically extracting, storing, and retrieving key insights, user preferences, and session summaries — making it directly relevant to regulated workloads where auditability of agent context and data persistence controls are required [2].

---

## 2. AWS SBG Enabled Platform Controls

| Control Type | Control | Description |
|---|---|---|
| Detective | CloudTrail logging | All Memory API calls (CreateMemory, CreateEvent, RetrieveMemoryRecords, etc.) are logged via AWS CloudTrail for audit and forensic review [3] |
| Detective | CloudWatch metrics | Token usage and memory operation metrics emitted to the `Bedrock-AgentCore` CloudWatch namespace; alerting can be configured on anomalous usage [4] |
| Proactive | Service Quotas | Default limits on memory resources (150 per account), strategies (6 per memory), and TPS rates prevent runaway resource creation [4] |
| Proactive | KMS key policy enforcement | IAM conditions (`kms:ViaService`) restrict KMS key usage to the AgentCore service endpoint only, preventing misuse outside the service boundary [5] |
| Preventative | IAM resource-based policies | Access to individual Memory resources can be scoped via resource-based policies (max 20 KB, 100 statements); supports least-privilege per-memory access control [3] |
| Preventative | Customer-managed KMS (CMK) | Customers can enforce CMK encryption on all stored memory data, blocking AWS from accessing plaintext without explicit key grants [5] |
| Preventative | Amazon Bedrock Guardrails integration | Guardrails can be applied to prompts sent to or from Memory to block prompt injection and memory poisoning attempts [5] |
| Responsive | Memory record deletion APIs | `DeleteEvent` and memory management APIs allow immediate removal of specific memory records in response to data subject requests or incident response [4] |

---

## 3. AWS Identity & Access Management (IAM)

**Required roles and identities:**

| Role / Policy | Purpose | Trust Relationship |
|---|---|---|
| `BedrockAgentCoreFullAccess` (AWS managed) | Grants full access to all AgentCore resources including Memory; used for admin/developer identities during setup | Attached to IAM users, groups, or roles by account administrators |
| `AmazonBedrockAgentCoreMemoryBedrockModelInferenceExecutionRolePolicy` (AWS managed) | Allows the Memory service to invoke Bedrock foundation models for long-term memory extraction and consolidation | Trusted by `bedrock-agentcore.amazonaws.com`; attached to the execution role passed at memory creation |
| Agent execution role (customer-managed) | IAM role assumed by the agent at runtime to call Memory data-plane APIs (`CreateEvent`, `RetrieveMemoryRecords`, etc.) | Trusted by the agent runtime or calling application; must include `bedrock-agentcore:*` permissions scoped to specific memory resource ARNs |
| KMS key grant role (customer-managed) | Required when using CMK encryption; must have `kms:CreateGrant`, `kms:Decrypt`, `kms:GenerateDataKey`, `kms:DescribeKey`, `kms:ReEncrypt*` | Conditioned on `kms:ViaService: bedrock-agentcore.<region>.amazonaws.com` to restrict key usage to the service [5] |

**Key IAM considerations for regulated environments:**
- Production deployments should use custom least-privilege policies rather than `BedrockAgentCoreFullAccess`, scoping permissions to specific memory resource ARNs
- The `iam:PassRole` permission is required to pass the execution role to the Memory service; restrict this with a condition on role name prefix (e.g., `BedrockAgentCore*`)
- Memory resources support resource-based policies, enabling cross-account access patterns to be explicitly denied at the resource level [3]

---

## 4. Data Protection

**Encryption at Rest:**
- All memory data is encrypted at rest by default using AWS-managed KMS keys
- Customer-managed KMS keys (CMK) are supported and recommended for regulated workloads handling PII or financial data; CMK usage requires explicit key policy grants and IAM permissions on the calling identity [5]
- Memory data (short-term events and long-term records) is stored in AWS-managed backend storage; customers do not have direct access to the underlying storage layer
- FIPS 140-3 validated endpoints are available for environments requiring FIPS-compliant cryptographic modules [3]
- Customers are responsible for preventing memory poisoning — the injection of false or harmful data into long-term memory stores — as this is an application-level concern under the AWS Shared Responsibility Model [5]

**Encryption in Transit:**
- All API communication with AgentCore Memory endpoints is encrypted using TLS 1.2 minimum; TLS 1.3 is recommended [3]
- Data in transit between the Memory service and Bedrock foundation models (used for extraction/consolidation) is encrypted within the AWS network
- Cross-region inference is supported for Memory extraction; data may traverse AWS regions — customers in data-residency-constrained environments should review cross-region inference configuration [3]

---

## 5. Network Security

- AgentCore Memory is a fully managed service with no customer-managed compute; there are no VPC-hosted Memory endpoints to configure
- API calls to Memory control-plane and data-plane endpoints traverse the public internet by default over TLS; AWS PrivateLink is not currently documented as supported for the Memory service specifically
- Customers hosting applications inside a VPC should route Memory API calls via VPC interface endpoints for the `bedrock-agentcore` service where available, or via NAT Gateway for outbound connectivity
- Cross-region inference for memory extraction means data may be processed in a secondary AWS region; customers with strict data residency requirements (e.g., EU data sovereignty) should validate region configuration before enabling long-term memory strategies [3]
- Network access to Memory APIs is controlled entirely through IAM; there are no security group or NACL controls applicable to the Memory service itself

---

## 6. Logging and Monitoring

**CloudTrail:**
- All AgentCore Memory control-plane API calls are recorded in AWS CloudTrail as management events: `CreateMemory`, `GetMemory`, `UpdateMemory`, `DeleteMemory`, `ListMemories` [3]
- Data-plane operations (`CreateEvent`, `RetrieveMemoryRecords`, `DeleteEvent`) are also logged, providing a full audit trail of what data was written to and read from memory stores
- CloudTrail logs should be delivered to an immutable S3 bucket with Object Lock enabled for compliance retention in regulated environments

**VPC Flow Logs:**
- Not directly applicable to the Memory service as it does not run within a customer VPC; VPC Flow Logs on the customer application's VPC will capture outbound API calls to Memory endpoints at the network level

**Compliance:**
- AgentCore Memory inherits Amazon Bedrock's compliance posture; Amazon Bedrock is covered under SOC 1/2/3, ISO 27001, PCI DSS, HIPAA eligibility, and FedRAMP Moderate [6]
- Customers are responsible for ensuring that data written into Memory stores (events, extracted records) complies with applicable data retention, minimisation, and residency obligations
- CloudWatch metrics in the `Bedrock-AgentCore` namespace (e.g., `TokenCount` for long-term memory extraction) should be monitored and alerted on to detect anomalous agent behaviour or quota exhaustion [4]
- Amazon Macie can be used to scan S3 buckets used by adjacent AgentCore services (e.g., Gateway) for sensitive data discovery; Memory's internal storage is not directly accessible via S3 [3]

---

## Sources

1. AWS Docs — Add memory to your AgentCore agent: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/memory.html
2. AWS Blog — Building smarter AI agents: AgentCore long-term memory deep dive: https://aws.amazon.com/blogs/machine-learning/building-smarter-ai-agents-agentcore-long-term-memory-deep-dive/
3. AWS Docs — Data protection in Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-protection.html
4. AWS Docs — Quotas for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/bedrock-agentcore-limits.html
5. AWS Docs — Encrypt your Amazon Bedrock AgentCore Memory: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/storage-encryption.html
6. AWS Docs — AWS managed policies for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-iam-awsmanpol.html
