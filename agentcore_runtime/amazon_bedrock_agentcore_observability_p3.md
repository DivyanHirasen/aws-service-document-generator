# Amazon Bedrock AgentCore Observability — Security Assessment

> Cloud Security Review Board | March 2026

---

## 1. Service Overview

Amazon Bedrock AgentCore Observability is a fully managed, serverless monitoring capability within the AgentCore platform that provides end-to-end tracing, metrics, and logging for AI agent workloads deployed on AgentCore Runtime or on external infrastructure (EC2, EKS, Lambda, third-party cloud) [1][2]. It is built on Amazon CloudWatch (metrics, logs, GenAI Observability dashboard) and AWS X-Ray (distributed tracing via CloudWatch Transaction Search), and emits telemetry in OpenTelemetry (OTEL)-compatible format using the AWS Distro for OpenTelemetry (ADOT) SDK [3][4]. The critical security characteristic for regulated workloads is that all telemetry data — including agent inputs, outputs, tool invocations, and reasoning traces — flows into customer-owned CloudWatch log groups and X-Ray trace stores; the customer is responsible for controlling access to this data, which may contain sensitive business information or PII from agent interactions [2][5].

---

## 2. Underlying Infrastructure & Service Substrate

- **Compute substrate:** AgentCore Observability is not a standalone compute service — it is a telemetry pipeline and dashboard layer. The ADOT SDK runs inside the customer's agent execution environment (AgentCore Runtime microVM, EC2, EKS pod, Lambda function, etc.). The CloudWatch and X-Ray backends that receive and store telemetry are AWS-managed, multi-tenant, serverless services running on AWS-owned infrastructure. No dedicated compute is provisioned per customer for the observability function itself [1][3]
- **Storage substrate:** All telemetry data is persisted in AWS-managed storage within the customer's account: structured logs and OTEL spans are written to CloudWatch Logs log groups (under `/aws/bedrock-agentcore/runtimes/<agent-id>/`); traces and spans are stored in X-Ray via CloudWatch Transaction Search (stored in the `/aws/spans/default` log group in the customer's account); metrics are written to the `bedrock-agentcore` CloudWatch namespace. For memory and gateway resources, logs can additionally be delivered to customer-specified S3 buckets or Amazon Data Firehose streams [2][6]. All storage is in the customer's AWS account — AWS does not retain a separate copy
- **AWS account boundary:** All telemetry data lands in the customer's AWS account (CloudWatch Logs, X-Ray, CloudWatch Metrics). The ADOT SDK running inside the agent execution environment makes outbound API calls to CloudWatch and X-Ray endpoints using the agent execution role's credentials. No telemetry data crosses into an AWS-managed service account [2][3]
- **VPC boundary:** The ADOT SDK exports telemetry over HTTPS to CloudWatch Logs, X-Ray, and CloudWatch Metrics endpoints. For agents running in AgentCore Runtime (microVM), these calls traverse the AWS network. For agents running in a customer VPC (EC2, EKS), the telemetry export traffic can be routed through VPC interface endpoints (PrivateLink) for CloudWatch Logs (`com.amazonaws.<region>.logs`) and X-Ray (`com.amazonaws.<region>.xray`) to avoid traversing the public internet [7]. The GenAI Observability dashboard in the CloudWatch console is a control-plane UI and does not require VPC configuration
- **Multi-tenancy model:** The CloudWatch and X-Ray backends are shared multi-tenant AWS services. Tenant isolation is enforced at the AWS account boundary via IAM — each customer's telemetry data is logically isolated in their own account's CloudWatch log groups and X-Ray trace store. There is no hardware-level isolation between customers' telemetry data in the CloudWatch/X-Ray backend [3][7]
- **Data residency:** Telemetry data is written to CloudWatch Logs and X-Ray in the AWS region where the agent is running. CloudWatch Transaction Search stores indexed spans in the `/aws/spans/default` log group in the same region. There is no automatic cross-region replication of observability data. For agents running outside AgentCore Runtime, the customer configures the target region via `AWS_DEFAULT_REGION` and `AWS_REGION` environment variables — the customer is responsible for ensuring these point to an approved region [2][6]

---

## 3. AWS Enabled Platform Controls

### 3a. Control Mapping

| Control Type | Control | Description |
|---|---|---|
| Detective | CloudWatch GenAI Observability dashboard | Provides real-time visibility into agent sessions, traces, latency, token usage (input/output/total), error rates, and tool invocation patterns via the CloudWatch console's Bedrock AgentCore tab. Requires CloudWatch Transaction Search to be enabled (one-time per-account setup) [1][4] |
| Detective | CloudWatch Transaction Search (X-Ray spans) | Indexes OTEL spans and traces in `/aws/spans/default`; enables search and filtering by service name, session ID, trace ID, and custom baggage attributes. Supports configurable sampling percentage (1% at no cost; higher percentages incur additional charges) [3][6] |
| Detective | CloudWatch Logs — agent execution logs | AgentCore Runtime automatically creates a CloudWatch log group (`/aws/bedrock-agentcore/runtimes/<agent-id>-<endpoint-name>/`) for stdout/stderr and OTEL structured logs. For memory and gateway resources, log destinations must be manually configured [2] |
| Proactive | IAM condition keys on CloudWatch/X-Ray write permissions | The execution role policy for AgentCore Runtime scopes `cloudwatch:PutMetricData` to the `bedrock-agentcore` namespace via a condition key (`cloudwatch:namespace`), preventing the execution role from writing metrics to arbitrary namespaces [8] |
| Proactive | CloudWatch resource policies for Transaction Search | A CloudWatch resource policy must be explicitly created to grant `xray.amazonaws.com` permission to write spans to the `/aws/spans/default` log group — this is a required one-time setup and provides an explicit authorisation boundary for span ingestion [6] |
| Preventative | IAM access control on CloudWatch log groups | Customer-managed IAM policies control which principals can read (`logs:GetLogEvents`, `logs:FilterLogEvents`) or delete (`logs:DeleteLogGroup`, `logs:DeleteLogStream`) agent telemetry log groups. Restricting these actions prevents unauthorised access to agent interaction data [7] |
| Preventative | CloudWatch Logs encryption with CMK | CloudWatch log groups can be encrypted with a customer-managed KMS key (CMK) via `logs:AssociateKmsKey`. This encrypts all agent telemetry data at rest with a key the customer controls, enabling key revocation as a data access termination mechanism [7] |
| Responsive | CloudWatch Alarms | Alarms can be configured on `bedrock-agentcore` namespace metrics (error rate, latency, session count) to trigger SNS notifications or Lambda remediation functions when thresholds are breached [1][4] |
| Responsive | `logs:DeleteLogGroup` / `logs:DeleteLogStream` | Log groups and streams can be deleted to purge telemetry data in response to a data handling incident; combined with S3 Object Lock on CloudTrail logs, this provides a targeted data removal capability without affecting audit trails [7] |

### 3b. Service Control Policy (SCP)

The following SCP is a production-ready starting point to be attached at the AWS Organizations OU level for accounts using AgentCore Observability. Substitute `["us-east-1", "eu-west-1"]` with your organisation's approved region list before applying.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyObservabilitySetupOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": [
        "logs:CreateLogGroup",
        "logs:PutDeliverySource",
        "logs:PutDeliveryDestination",
        "logs:CreateDelivery",
        "xray:UpdateTraceSegmentDestination",
        "xray:UpdateIndexingRule"
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
      "Sid": "DenyDeletionOfAgentCoreLogGroups",
      "Effect": "Deny",
      "Action": [
        "logs:DeleteLogGroup",
        "logs:DeleteLogStream",
        "logs:DisassociateKmsKey"
      ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/*",
        "arn:aws:logs:*:*:log-group:/aws/spans/default",
        "arn:aws:logs:*:*:log-group:/aws/vendedlogs/bedrock-agentcore/*"
      ],
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyDisablingTransactionSearch",
      "Effect": "Deny",
      "Action": [
        "xray:UpdateTraceSegmentDestination"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "xray:Destination": "XRay"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyRemovalOfKMSEncryptionFromLogGroups",
      "Effect": "Deny",
      "Action": [
        "logs:DisassociateKmsKey"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyPublicAccessToObservabilityBuckets",
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketPublicAccessBlock",
        "s3:DeletePublicAccessBlock"
      ],
      "Resource": "arn:aws:s3:::bedrock-agentcore-*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyDeletionOfCloudTrailAuditTrails",
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
      "Sid": "DenyUnencryptedLogGroupCreation",
      "Effect": "Deny",
      "Action": [
        "logs:CreateLogGroup"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/*",
      "Condition": {
        "Null": {
          "logs:kmsKeyId": "true"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    }
  ]
}
```

**SCP limitations — what this policy cannot enforce (must be handled at IAM or application layer):**

- The SCP `DenyUnencryptedLogGroupCreation` statement applies to explicit `CreateLogGroup` calls. AgentCore Runtime automatically creates the log group `/aws/bedrock-agentcore/runtimes/<agent-id>/` on first deployment — this auto-creation may bypass the SCP condition if the service-side call does not pass a KMS key ID. CMK association must be applied post-creation via `logs:AssociateKmsKey` and enforced via AWS Config rule (`cloudwatch-log-group-encrypted`)
- The SCP cannot prevent the ADOT SDK from exporting telemetry to CloudWatch endpoints outside the approved region if the agent execution environment's `AWS_REGION` environment variable is misconfigured — this must be enforced at the container/runtime configuration layer
- The SCP cannot enforce that sensitive data (PII, credentials, business data) is filtered from agent traces and logs before export. The AWS documentation explicitly recommends filtering sensitive data from observability attributes and payloads — this is entirely the customer's responsibility at the application layer [5]
- The SCP cannot prevent a principal with `logs:GetLogEvents` or `logs:FilterLogEvents` from reading agent interaction data from CloudWatch log groups. Access to telemetry data must be restricted via IAM identity-based policies scoped to specific log group ARNs
- The SCP cannot enforce sampling rates for CloudWatch Transaction Search — a misconfigured 100% sampling rate will significantly increase costs and may expose more interaction data than intended. Sampling configuration must be managed via `xray:UpdateIndexingRule` and governed by IAM
- Resource-based policies are supported for AgentCore Runtime and Gateway resources but not for CloudWatch log groups or X-Ray directly; cross-account access to observability data must be controlled via CloudWatch Observability Access Manager (OAM) and IAM, not via SCP

---

## 4. AWS Identity & Access Management (IAM)

| Role / Policy | Purpose | Trust Relationship |
|---|---|---|
| `BedrockAgentCoreFullAccess` (AWS managed) | Broad admin access to all AgentCore resources; includes `xray:*`, `cloudwatch:*`, `logs:*` for observability setup — not suitable for production | Attached to IAM users/roles by account admin |
| AgentCore Runtime execution role (customer-managed) | Assumed by the agent runtime container; must include `xray:PutTraceSegments`, `xray:PutTelemetryRecords`, `xray:GetSamplingRules`, `xray:GetSamplingTargets`, `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` (scoped to `/aws/bedrock-agentcore/runtimes/*`), and `cloudwatch:PutMetricData` (conditioned on `cloudwatch:namespace: bedrock-agentcore`) [8] | Trusted by `bedrock-agentcore.amazonaws.com`; passed at runtime creation via `iam:PassRole` |
| Observability read role (customer-managed) | Used by security/operations teams to query CloudWatch logs, X-Ray traces, and the GenAI Observability dashboard; must include `logs:GetLogEvents`, `logs:FilterLogEvents`, `xray:GetTraceSummaries`, `xray:BatchGetTraces`, `cloudwatch:GetMetricData` scoped to AgentCore log groups and namespaces | Trusted by approved IAM users/roles; must not be granted to agent execution roles |
| CloudWatch delivery role (customer-managed) | Required for memory and gateway resources to deliver logs to CloudWatch Logs, S3, or Firehose; created by the customer and passed to the `logs:PutDeliverySource` / `logs:CreateDelivery` API calls [2] | Trusted by `logs.amazonaws.com` |
| `AWSServiceRoleForApplicationSignals` (service-linked) | Created automatically when CloudWatch Application Signals is enabled; allows Application Signals to read CloudWatch metrics and traces for service health dashboards | Trusted by `application-signals.cloudwatch.amazonaws.com`; cannot be assumed by customer principals |

**Least-privilege guidance for production:**
- The execution role's `logs:PutLogEvents` permission must be scoped to the specific log group ARN for the agent (`arn:aws:logs:<region>:<account>:log-group:/aws/bedrock-agentcore/runtimes/<agent-id>*:log-stream:*`) — not a wildcard
- `cloudwatch:PutMetricData` must be conditioned on `cloudwatch:namespace: bedrock-agentcore` to prevent the execution role from writing to arbitrary metric namespaces
- `xray:PutTraceSegments` and `xray:PutTelemetryRecords` cannot be scoped to specific resources (X-Ray does not support resource-level permissions for these actions) — this is a known IAM limitation; the execution role should have no other X-Ray permissions
- Separate the observability read role from the execution role — principals that need to query traces and logs should not have write permissions to the agent runtime
- Restrict `logs:AssociateKmsKey` to the specific CMK ARN approved for AgentCore log groups to prevent key substitution attacks
- Do not grant `logs:DeleteLogGroup` or `logs:DeleteLogStream` to the execution role — log deletion should require a separate privileged role

---

## 5. Data Protection

**Encryption at Rest:**
- CloudWatch Logs log groups are encrypted by default using an AWS-managed key (`aws/logs`). CMK encryption is supported via `logs:AssociateKmsKey` — the customer must explicitly associate a CMK with each log group; this is not done automatically by AgentCore [7]
- X-Ray trace data stored via CloudWatch Transaction Search (in the `/aws/spans/default` log group) is subject to the same CloudWatch Logs encryption model — AWS-managed key by default, CMK supported via `logs:AssociateKmsKey`
- CloudWatch Metrics (the `bedrock-agentcore` namespace) are stored in AWS-managed infrastructure and cannot be encrypted with a CMK — this is a platform limitation of CloudWatch Metrics that applies to all AWS services
- For memory and gateway resources where logs are delivered to S3, CMK encryption must be enforced at the S3 bucket level via bucket policy requiring `aws:kms` — this is the customer's responsibility
- Agent interaction data (prompts, responses, tool inputs/outputs) may appear in CloudWatch Logs as part of OTEL structured log entries if the agent framework emits them — customers must implement payload filtering in the ADOT SDK configuration or agent code to prevent sensitive data from being written to logs in plaintext [5]
- FIPS 140-3 validated endpoints are available for CloudWatch Logs and X-Ray in supported regions for environments with FIPS compliance requirements [7]

**Encryption in Transit:**
- All ADOT SDK telemetry export calls (to CloudWatch Logs, X-Ray, CloudWatch Metrics) use HTTPS with TLS 1.2 minimum; TLS 1.3 is supported [7]
- For agents running in a customer VPC, telemetry export traffic can be routed through VPC interface endpoints (PrivateLink) for CloudWatch Logs and X-Ray, keeping traffic on the AWS private network and avoiding the public internet
- The CloudWatch console (GenAI Observability dashboard) is accessed over HTTPS; no additional network configuration is required for console access
- There is no cross-region data movement in the default configuration — telemetry is written to the region where the agent runs. If CloudWatch cross-account observability (OAM) is configured to share data with a monitoring account, data may traverse region boundaries depending on the OAM sink configuration — this must be reviewed against data residency requirements

---

## 6. Network Security

- AgentCore Observability does not create any compute resources or ENIs in the customer's VPC — it is a telemetry pipeline to CloudWatch and X-Ray endpoints
- For agents running in AgentCore Runtime (microVM), ADOT telemetry export calls traverse the AWS network to CloudWatch and X-Ray regional endpoints; these calls do not pass through the customer's VPC by default
- For agents running in a customer VPC (EC2, EKS, Lambda with VPC config), telemetry export traffic can be routed through VPC interface endpoints: `com.amazonaws.<region>.logs` (CloudWatch Logs) and `com.amazonaws.<region>.xray` (X-Ray) — this prevents telemetry data from traversing the public internet [7]
- PrivateLink is supported for CloudWatch Logs and X-Ray data-plane endpoints; the CloudWatch console (control plane) does not support PrivateLink and requires internet access or AWS Direct Connect
- The GenAI Observability dashboard in the CloudWatch console is a read-only UI; it does not expose any inbound network surface to the customer's environment
- Security groups and NACLs do not apply to the observability pipeline itself; they apply to the VPC interface endpoints if configured, and to the agent execution environment (EC2, EKS nodes, etc.)
- There are no inbound internet access requirements for AgentCore Observability; outbound HTTPS access to CloudWatch Logs and X-Ray endpoints is required from the agent execution environment (or routed via PrivateLink)
- For non-AgentCore-hosted agents, the customer is responsible for ensuring that the OTEL exporter environment variables (`OTEL_EXPORTER_OTLP_LOGS_HEADERS`, `OTEL_EXPORTER_OTLP_PROTOCOL`) point to approved regional endpoints and that outbound traffic is routed through approved network paths

---

## 7. Logging and Monitoring

**CloudTrail:**
- Management events (logged by default): `CreateDelivery`, `DeleteDelivery`, `PutDeliverySource`, `DeleteDeliverySource`, `PutDeliveryDestination`, `DeleteDeliveryDestination` (CloudWatch Logs delivery configuration APIs); `UpdateTraceSegmentDestination`, `UpdateIndexingRule` (X-Ray Transaction Search configuration). These capture changes to the observability pipeline configuration itself [9]
- Data events (not logged by default — must be explicitly enabled): `logs:GetLogEvents`, `logs:FilterLogEvents` (CloudWatch Logs data access); `xray:BatchGetTraces`, `xray:GetTraceSummaries` (X-Ray trace retrieval). Without data event logging, there is no audit trail of which principals read agent interaction data from CloudWatch Logs or X-Ray — this is a material gap for regulated workloads where agent interactions may contain sensitive data
- Critical gap: AgentCore Observability does not have its own CloudTrail event namespace — observability configuration changes are logged under `logs.*` and `xray.*` event sources. SIEM rules must be configured to alert on unexpected modifications to AgentCore-related log groups and X-Ray configuration
- CloudTrail logs should be delivered to an S3 bucket with Object Lock (WORM) enabled in a dedicated logging account, separate from the account running the agents

**VPC Flow Logs:**
- AgentCore Observability does not create ENIs in the customer's VPC; VPC Flow Logs are not applicable to the observability pipeline itself
- For agents running in a customer VPC with PrivateLink endpoints for CloudWatch Logs and X-Ray, VPC Flow Logs on the endpoint subnets will capture telemetry export traffic — providing network-level evidence that telemetry is being sent to approved endpoints only
- For agents running in AgentCore Runtime (outside the customer VPC), there is no VPC Flow Log visibility into telemetry export traffic; CloudTrail data events on CloudWatch Logs are the only available audit mechanism for telemetry data access

**Compliance:**
- Amazon Bedrock AgentCore (including Observability) is in scope for: SOC 1 Type II, SOC 2 Type II, SOC 3, ISO 27001, ISO 27017, ISO 27018, PCI DSS Level 1, HIPAA eligibility, FedRAMP Moderate [10]
- Amazon CloudWatch and AWS X-Ray (the underlying storage and processing services) are independently in scope for the same compliance programmes [7]
- Customer responsibilities not handled by AWS: enabling CMK encryption on all AgentCore CloudWatch log groups (AWS creates log groups with AWS-managed keys by default); enabling CloudWatch Logs data event logging in CloudTrail to audit read access to agent interaction data; implementing payload filtering in agent code or ADOT SDK configuration to prevent PII and sensitive data from appearing in traces and logs; configuring VPC interface endpoints for CloudWatch Logs and X-Ray if agents run in a customer VPC and public internet egress is not permitted; ensuring `AWS_REGION` environment variables in agent execution environments point to approved regions; configuring CloudWatch Alarms on error rate and latency metrics for production alerting; reviewing CloudWatch Transaction Search sampling rates to balance visibility with cost and data minimisation requirements; retaining CloudWatch Logs and X-Ray data for the period required by applicable regulations (CloudWatch Logs retention must be explicitly configured — default is indefinite retention)

---

## Sources

1. AWS Docs — Observe your agent applications on Amazon Bedrock AgentCore Observability: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability.html
2. AWS Docs — Add observability to your Amazon Bedrock AgentCore resources: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-configure.html
3. AWS Blog — Build trustworthy AI agents with Amazon Bedrock AgentCore Observability (Aug 2025): https://aws.amazon.com/blogs/machine-learning/build-trustworthy-ai-agents-with-amazon-bedrock-agentcore-observability/
4. AWS Blog — Launching Amazon CloudWatch generative AI observability (Preview): https://aws.amazon.com/blogs/mt/launching-amazon-cloudwatch-generative-ai-observability-preview/
5. AWS Docs — Observability best practices (AgentCore): https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-configure.html#observability-best-practices
6. AWS Docs — Get started with AgentCore Observability: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/observability-get-started.html
7. AWS Docs — Data protection in Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-protection.html
8. AWS Docs — IAM Permissions for AgentCore Runtime: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-permissions.html
9. AWS Docs — AWS managed policies for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-iam-awsmanpol.html
10. AWS What's New — AgentCore generally available (Oct 2025): https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-available
