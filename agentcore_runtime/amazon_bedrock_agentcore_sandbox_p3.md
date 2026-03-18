# Amazon Bedrock AgentCore Agent Sandbox (Code Interpreter & Browser Tool) — Security Assessment

> Cloud Security Review Board | March 2026

---

## 1. Service Overview

Amazon Bedrock AgentCore Agent Sandbox encompasses two fully managed, serverless built-in tools — Code Interpreter and Browser Tool — that provide AI agents with isolated execution environments for running AI-generated code (Python, JavaScript, TypeScript) and interacting with web applications respectively [1][2]. Both tools implement a strict one-session-one-microVM isolation model using Firecracker, with sessions lasting up to 8 hours and all state destroyed on termination [3]. The critical security consideration for regulated workloads is that both tools expose the MicroVM Metadata Service (MMDS) at `169.254.254.169.254` by default, making the execution role's temporary credentials accessible from within the sandbox — meaning the IAM execution role attached to a Code Interpreter or Browser session is the effective security boundary, not the network mode [4].

---

## 2. Underlying Infrastructure & Service Substrate

- **Compute substrate:** Both Code Interpreter and Browser Tool run on Firecracker microVMs — the same open-source VMM used by AWS Lambda and Fargate. Each session receives a dedicated microVM with isolated CPU, memory, and filesystem; compute is not shared between sessions or customers. The microVM is ephemeral: created on session start and fully destroyed on session termination or timeout [3]
- **Storage substrate:** Session-local filesystem is ephemeral and exists only within the microVM for the duration of the session — no data persists after session termination. Files can be uploaded inline (up to 100 MB) or referenced from customer-owned S3 buckets (up to 5 GB via AWS CLI commands within the sandbox). Browser Tool session recordings (DOM changes, user actions, console logs, network events) are stored in a customer-specified S3 bucket in the customer's account. There is no AWS-managed persistent storage for sandbox session data [1][2]
- **AWS account boundary:** The sandbox service plane (session orchestration, microVM lifecycle) runs in an AWS-managed service account. The execution role, S3 buckets for file operations, and S3 buckets for Browser session recordings are defined in and belong to the customer's account. The execution role's temporary credentials are accessible from within the microVM via MMDS at `169.254.169.254` — this is by design and confirmed by AWS as expected behaviour [4]
- **VPC boundary:** By default, Code Interpreter and Browser Tool microVMs run outside the customer's VPC. VPC connectivity is opt-in: when configured, AWS creates ENIs in the customer's specified subnets via the `AWSServiceRoleForBedrockAgentCoreNetwork` service-linked role, enabling the microVM to reach private VPC resources. Three network modes are available for Code Interpreter: **Sandbox** (S3 access + DNS resolution only, no general internet), **Public** (full internet access), and **VPC** (private VPC resources, no public internet). Browser Tool requires internet access by design and does not support a fully isolated network mode [1][5]
- **Multi-tenancy model:** Hardware-level isolation per session via Firecracker microVM — each session has isolated CPU, memory, and filesystem. After session termination the entire microVM is destroyed and memory sanitised; no residual state can persist to a subsequent session or customer. This is the same isolation model as AgentCore Runtime [3]
- **Data residency:** Sandbox resources are regional; session execution remains within the AWS region where the Code Interpreter or Browser resource is created. Browser session recordings stored in customer S3 buckets are subject to the bucket's region configuration — customers must ensure recording buckets are in approved regions. There is no cross-region inference component in either tool [1][2]

---

## 3. AWS Enabled Platform Controls

### 3a. Control Mapping

| Control Type | Control | Description |
|---|---|---|
| Detective | CloudTrail — management events | `CreateCodeInterpreter`, `DeleteCodeInterpreter`, `GetCodeInterpreter`, `ListCodeInterpreters`, `CreateBrowser`, `DeleteBrowser`, `GetBrowser`, `ListBrowsers` are logged automatically as management events with no additional configuration [6] |
| Detective | CloudTrail — data events (`InvokeCodeInterpreter`, `StartCodeInterpreterSession`, `StopCodeInterpreterSession`, `InvokeBrowser`, `StartBrowserSession`, `StopBrowserSession`) | All session invocation and management operations are data-plane events; they are **not** logged by default and require a manually configured CloudTrail trail with data event logging enabled — this is a material audit gap, particularly given the credential exfiltration risk via MMDS [4][6] |
| Detective | CloudWatch metrics | Both tools emit operational metrics to CloudWatch; Browser Tool additionally supports live view (real-time session monitoring) and session replay (recorded DOM changes, user actions, console logs, network events stored in customer S3) [2] |
| Proactive | IAM condition keys for VPC enforcement | `bedrock-agentcore:subnets` and `bedrock-agentcore:securityGroups` condition keys can be used in IAM policies to deny `CreateCodeInterpreter` and `CreateBrowser` operations that do not specify approved VPC subnets and security groups — enforcing VPC mode at the IAM layer [5] |
| Proactive | Service Quotas | Default limits on concurrent sessions per account and per tool prevent uncontrolled resource proliferation; quota increases require explicit support ticket approval [7] |
| Preventative | VPC mode network isolation | When VPC mode is configured, the microVM's outbound traffic is governed by security group rules on the ENIs created in the customer's VPC — providing network-level access control to downstream resources and blocking public internet access [5] |
| Preventative | Sandbox mode partial isolation | Sandbox mode blocks general internet access but permits S3 API calls and DNS resolution; this is the default for the system-managed Code Interpreter ARN (`aws.codeinterpreter.v1`) and provides a reduced attack surface compared to Public mode — but does not prevent MMDS credential access or DNS-based exfiltration [1][4] |
| Preventative | Execution role scoping | The IAM execution role attached to a Code Interpreter or Browser resource defines the blast radius of any credential exfiltration from MMDS; scoping this role to the minimum required permissions (e.g. specific S3 bucket ARNs only) is the primary defence against privilege escalation from within the sandbox [4] |
| Responsive | Session termination APIs | `StopCodeInterpreterSession` and `StopBrowserSession` terminate the microVM immediately, destroying all session state and revoking the session's access to the execution role credentials [1][2] |
| Responsive | `DeleteCodeInterpreter` / `DeleteBrowser` | Entire tool resources can be deleted to prevent any further session creation; combined with SCP-level restrictions, this provides a rapid containment mechanism [1] |

### 3b. Service Control Policy (SCP)

The following SCP is a production-ready starting point to be attached at the AWS Organizations OU level for accounts using AgentCore Code Interpreter and Browser Tool. Substitute `["us-east-1", "eu-west-1"]` with your organisation's approved region list before applying.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenySandboxCreationOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:CreateCodeInterpreter",
        "bedrock-agentcore:CreateBrowser"
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
      "Sid": "DenyCodeInterpreterWithoutVPC",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:CreateCodeInterpreter"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "bedrock-agentcore:subnets": "true",
          "bedrock-agentcore:securityGroups": "true"
        },
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyBrowserWithoutVPC",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:CreateBrowser"
      ],
      "Resource": "*",
      "Condition": {
        "Null": {
          "bedrock-agentcore:subnets": "true",
          "bedrock-agentcore:securityGroups": "true"
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
      "Sid": "DenyBrowserInvocationByUnauthorisedPrincipals",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:InvokeBrowser",
        "bedrock-agentcore:StartBrowserSession"
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
      "Sid": "DenyDeletionOfSandboxAuditTrails",
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
      "Sid": "DenyDeletionOfNetworkServiceLinkedRole",
      "Effect": "Deny",
      "Action": [
        "iam:DeleteServiceLinkedRole"
      ],
      "Resource": "arn:aws:iam::*:role/aws-service-role/network.bedrock-agentcore.amazonaws.com/*",
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

- The SCP `DenyCodeInterpreterWithoutVPC` and `DenyBrowserWithoutVPC` statements prevent creation of new custom resources without VPC configuration, but they do **not** prevent use of the system-managed Code Interpreter ARN (`arn:aws:bedrock-agentcore:<region>:aws:code-interpreter/aws.codeinterpreter.v1`), which runs in Sandbox mode by default. If the system ARN must be blocked, add an explicit deny on `InvokeCodeInterpreter` for that specific ARN
- The SCP cannot prevent MMDS credential access from within a running sandbox session — this is confirmed AWS-intended behaviour. The execution role's permissions are the only effective control; the SCP cannot enforce that execution roles are least-privilege
- The SCP cannot prevent DNS-based data exfiltration from Sandbox mode — AWS has confirmed that DNS resolution is permitted in Sandbox mode and recommends Route 53 Resolver DNS Firewall as the mitigation; this must be configured at the VPC or account level, not via SCP [4]
- Resource-based policies are not currently supported for any AgentCore resources; the `InvokeCodeInterpreter` restriction above uses principal-based SCP conditions as the only available centralised mechanism [4]
- The SCP cannot enforce that Browser session recording S3 buckets are in approved regions or have CMK encryption enabled; this must be enforced via S3 bucket policies and AWS Config rules
- The SCP cannot prevent a Code Interpreter from being used to pivot to other AWS services using exfiltrated MMDS credentials outside the sandbox — post-exfiltration activity is attributed to the execution role identity in CloudTrail, not the human actor

---

## 4. AWS Identity & Access Management (IAM)

| Role / Policy | Purpose | Trust Relationship |
|---|---|---|
| `BedrockAgentCoreFullAccess` (AWS managed) | Broad admin access to all AgentCore resources including Code Interpreter and Browser; includes `bedrock-agentcore:*` — not suitable for production | Attached to IAM users/roles by account admin |
| Code Interpreter execution role (customer-managed) | Assumed by the Code Interpreter microVM at runtime via MMDS; defines what AWS resources the sandbox can access (S3 buckets, Bedrock models, etc.); this role's credentials are accessible from within the sandbox via MMDS and represent the primary privilege escalation surface | Trusted by `bedrock-agentcore.amazonaws.com`; passed at `CreateCodeInterpreter` time via `iam:PassRole` |
| Browser Tool execution role (customer-managed) | Assumed by the Browser microVM at runtime; defines what AWS resources the browser session can access (S3 for session recordings, etc.); same MMDS exposure as Code Interpreter | Trusted by `bedrock-agentcore.amazonaws.com`; passed at `CreateBrowser` time via `iam:PassRole` |
| `AWSServiceRoleForBedrockAgentCoreNetwork` (service-linked) | Created automatically when VPC mode is configured; allows AgentCore to create and manage ENIs in the customer's VPC for sandbox outbound connectivity | Trusted by `network.bedrock-agentcore.amazonaws.com`; cannot be assumed by customer principals [8] |
| Invoking role (customer-managed) | The IAM role used by the agent or application to call `StartCodeInterpreterSession`, `InvokeCodeInterpreter`, `StartBrowserSession`, `InvokeBrowser`; separate from the execution role | Trusted by the agent runtime or calling application; must have `bedrock-agentcore:InvokeCodeInterpreter` / `InvokeBrowser` scoped to specific resource ARNs |

**Least-privilege guidance for production:**
- The execution role is the most critical control surface — it must be scoped to the absolute minimum permissions required. If the Code Interpreter only needs to read from a specific S3 bucket, the execution role should have `s3:GetObject` on that bucket ARN only. Any permission granted to the execution role is effectively grantable to any code the agent generates and executes [4]
- Do not attach `BedrockAgentCoreFullAccess` or any broad AWS managed policy to the execution role; create a custom policy with only the specific actions and resource ARNs required
- Restrict `iam:PassRole` to roles matching an approved naming convention (e.g. `AgentCoreApprovedSandboxExecution*`) conditioned on `iam:PassedToService: bedrock-agentcore.amazonaws.com`
- Scope `InvokeCodeInterpreter` and `InvokeBrowser` permissions on the invoking role to specific Code Interpreter and Browser resource ARNs — not wildcards
- Use IAM condition keys `bedrock-agentcore:subnets` and `bedrock-agentcore:securityGroups` in the invoking role's policy to enforce VPC mode at the IAM layer in addition to the SCP [5]

---

## 5. Data Protection

**Encryption at Rest:**
- Session-local filesystem data within the microVM is ephemeral and destroyed on session termination; there is no persistent storage to encrypt at the session layer
- Files uploaded to the sandbox inline (up to 100 MB) are held in the microVM's ephemeral filesystem for the session duration only; they are not written to any persistent AWS-managed store
- Files referenced from or written to customer S3 buckets are encrypted according to the S3 bucket's encryption policy; CMK enforcement must be applied via S3 bucket policy requiring `aws:kms` encryption — this is the customer's responsibility
- Browser Tool session recordings stored in customer S3 buckets are encrypted according to the bucket's encryption policy; CMK enforcement must be applied at the S3 bucket level
- FIPS 140-3 validated endpoints are available for environments with FIPS compliance requirements [9]

**Encryption in Transit:**
- All API communication (control-plane and data-plane) uses TLS 1.2 minimum; TLS 1.3 is recommended [9]
- Internal communication between the sandbox microVM and customer VPC resources (when VPC mode is enabled) traverses the ENI within the AWS network
- Browser Tool sessions communicate with external websites over HTTPS as determined by the target site; the service does not enforce TLS on external web targets — agents browsing HTTP sites will transmit data unencrypted
- MMDS credential retrieval within the microVM uses the link-local address `169.254.169.254` over HTTP (not HTTPS) — this is an internal-only path within the microVM and does not traverse any network boundary, but the credentials retrieved are transmitted in plaintext within the sandbox environment

---

## 6. Network Security

- Both Code Interpreter and Browser Tool microVMs run in an AWS-managed service account by default; they are not inside the customer's VPC and are not subject to customer-managed security groups or NACLs in the default configuration
- Three network modes for Code Interpreter [1]:
  - **Sandbox mode** (default for system ARN): blocks general internet access; permits S3 API calls and DNS resolution. DNS resolution is not blocked — this is a documented gap that enables DNS-based C2 and data exfiltration even in "isolated" mode [4]
  - **Public mode**: full internet access; highest risk; not recommended for workloads handling sensitive data
  - **VPC mode**: outbound traffic governed by customer security groups on ENIs in customer subnets; no public internet access; recommended for regulated workloads
- Browser Tool requires internet access by design (it browses the web); VPC mode can be configured to route browser traffic through a customer-controlled proxy or NAT Gateway, but the browser will still reach external internet destinations
- PrivateLink is supported for Code Interpreter and Browser Tool data-plane API calls via the shared `com.amazonaws.region.bedrock-agentcore` endpoint; control-plane operations (`CreateCodeInterpreter`, `CreateBrowser`) use `bedrock-agentcore-control.<region>.amazonaws.com` for which PrivateLink is not currently supported [10]
- VPC mode requires the `AWSServiceRoleForBedrockAgentCoreNetwork` service-linked role; ENIs created in the customer's subnets persist up to 8 hours after session termination
- Security groups and NACLs apply to the ENIs created in the customer's VPC for VPC-mode outbound connectivity; they do not apply to the microVM itself in non-VPC modes
- Route 53 Resolver DNS Firewall is the AWS-recommended mitigation for DNS-based exfiltration from Sandbox mode; this must be configured at the VPC level and is the customer's responsibility [4]

---

## 7. Logging and Monitoring

**CloudTrail:**
- Management events (logged by default, no additional configuration): `CreateCodeInterpreter`, `DeleteCodeInterpreter`, `GetCodeInterpreter`, `ListCodeInterpreters`, `CreateBrowser`, `DeleteBrowser`, `GetBrowser`, `ListBrowsers`
- Data events (not logged by default — must be explicitly enabled via a CloudTrail trail with data event logging; additional cost applies): `StartCodeInterpreterSession`, `InvokeCodeInterpreter`, `StopCodeInterpreterSession`, `StartBrowserSession`, `InvokeBrowser`, `StopBrowserSession`
- Critical gap: without data event logging enabled, there is no audit trail of which agent invoked which sandbox, what code was executed, or what browser actions were taken. Given that MMDS credential exfiltration is possible from within the sandbox, `InvokeCodeInterpreter` data events are essential for detecting abuse — any management plane actions performed using exfiltrated credentials will be attributed to the execution role identity, not the human actor, making post-incident attribution difficult [4]
- Post-exfiltration detection: if MMDS credentials are exfiltrated and used outside the sandbox, the resulting CloudTrail events will show the execution role's ARN as the principal — not the attacker's identity. SIEM rules must alert on unexpected management plane calls from execution role ARNs (e.g. `sts:AssumeRole`, `iam:*`, `ec2:*`) that are inconsistent with the role's intended purpose
- CloudTrail logs should be delivered to an S3 bucket with Object Lock (WORM) enabled in a dedicated logging account

**VPC Flow Logs:**
- Code Interpreter and Browser Tool do not create ENIs in the customer's VPC by default; VPC Flow Logs are not applicable in the default (non-VPC) configuration
- When VPC mode is enabled, ENIs are created in the customer's subnets; VPC Flow Logs on those subnets will capture outbound traffic from the sandbox to VPC resources — providing network-level visibility into which internal endpoints the sandbox is communicating with
- For Sandbox and Public mode deployments, network-level visibility is limited to CloudTrail API logs and CloudWatch metrics; there is no equivalent of VPC Flow Logs for traffic between the sandbox microVM and external endpoints

**Compliance:**
- Amazon Bedrock AgentCore (including Code Interpreter and Browser Tool) is in scope for: SOC 1 Type II, SOC 2 Type II, SOC 3, ISO 27001, ISO 27017, ISO 27018, PCI DSS Level 1, HIPAA eligibility, FedRAMP Moderate [11]
- Customer responsibilities not handled by AWS: enabling CloudTrail data event logging for all sandbox invocation events; configuring VPC mode for all production Code Interpreter deployments handling sensitive data; deploying Route 53 Resolver DNS Firewall to block DNS-based exfiltration from Sandbox mode; scoping execution roles to the minimum required permissions (the primary defence against MMDS credential abuse); enforcing VPC mode via IAM condition keys (`bedrock-agentcore:subnets`, `bedrock-agentcore:securityGroups`); applying CMK encryption to S3 buckets used for file operations and Browser session recordings; ensuring Browser session recording S3 buckets are in approved regions; retaining CloudTrail logs for the period required by applicable regulations

---

## Sources

1. AWS Docs — Execute code and analyze data using Amazon Bedrock AgentCore Code Interpreter: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/code-interpreter-tool.html
2. AWS Docs — Interact with web applications using Amazon Bedrock AgentCore Browser: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-tool.html
3. AWS Docs — How AgentCore Tools session isolation works: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/built-in-tools-how-it-works.html
4. Sonrai Security — Sandboxed to Compromised: Credential Exfiltration Paths in AWS Code Interpreters (Feb 2026): https://sonraisecurity.com/blog/sandboxed-to-compromised-new-research-exposes-credential-exfiltration-paths-in-aws-code-interpreters/
5. AWS Docs — Use IAM condition keys with AgentCore Runtime and built-in tools VPC settings: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-vpc-condition.html
6. AWS Blog — Introducing the Amazon Bedrock AgentCore Code Interpreter: https://aws.amazon.com/blogs/machine-learning/introducing-the-amazon-bedrock-agentcore-code-interpreter/
7. AWS Docs — Quotas for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/bedrock-agentcore-limits.html
8. AWS Docs — Using service-linked roles for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/service-linked-roles.html
9. AWS Docs — Data protection in Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-protection.html
10. AWS Docs — Use interface VPC endpoints (PrivateLink) for AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc-interface-endpoints.html
11. AWS What's New — AgentCore generally available (Oct 2025): https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-available
