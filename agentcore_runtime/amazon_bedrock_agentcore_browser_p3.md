# Amazon Bedrock AgentCore Browser Tool — Security Assessment

> Cloud Security Review Board | March 2026

---

## 1. Service Overview

Amazon Bedrock AgentCore Browser Tool is a fully managed, serverless cloud-based browser that enables AI agents to interact with websites and web applications through a secure, isolated Firecracker microVM environment [1][2]. Each browser session runs in a dedicated microVM with isolated CPU, memory, and filesystem; sessions can last up to 8 hours and all state is destroyed on termination [3]. The critical security consideration for regulated workloads is that Browser Tool requires internet access by design (it browses the web), exposes the execution role's temporary credentials via the MicroVM Metadata Service (MMDS) at `169.254.169.254`, and can persist authentication state across sessions via browser profiles — meaning the execution role's permissions, the proxy configuration, and the browser profile storage location are the primary security boundaries, not network isolation [4][5].

---

## 2. Underlying Infrastructure & Service Substrate

- **Compute substrate:** Browser Tool runs on Firecracker microVMs — the same open-source VMM used by AWS Lambda and Fargate. Each session receives a dedicated microVM with an isolated Chromium browser instance; compute is not shared between sessions or customers. The microVM is ephemeral: created on session start and fully destroyed on session termination or timeout. Live view streaming is powered by AWS DCV (Desktop Cloud Visualization) running within the microVM [2][3][6]
- **Storage substrate:** Session-local browser state (cookies, local storage, DOM) is ephemeral and exists only within the microVM for the session duration — no data persists after session termination unless explicitly saved. Browser profiles (cookies, local storage) can be persisted to a customer-managed browser profile resource for reuse across sessions. Session recordings (DOM changes, user actions, console logs, network events, CDP events) are stored in a customer-specified S3 bucket in the customer's account. There is no AWS-managed persistent storage for browser session data [1][7][8]
- **AWS account boundary:** The Browser Tool service plane (session orchestration, microVM lifecycle, DCV streaming) runs in an AWS-managed service account. The execution role, S3 buckets for session recordings, and browser profile resources are defined in and belong to the customer's account. The execution role's temporary credentials are accessible from within the microVM via MMDS at `169.254.169.254` — this is by design and confirmed by AWS as expected behaviour [4]
- **VPC boundary:** By default, Browser Tool microVMs run outside the customer's VPC with public internet access. VPC connectivity is opt-in: when configured, AWS creates ENIs in the customer's specified subnets via the `AWSServiceRoleForBedrockAgentCoreNetwork` service-linked role, enabling the microVM to route browser traffic through customer-controlled network infrastructure (proxy, NAT Gateway). Unlike Code Interpreter, Browser Tool does not support a fully isolated "Sandbox" mode — it requires internet access to browse websites [1][9]
- **Multi-tenancy model:** Hardware-level isolation per session via Firecracker microVM — each session has isolated CPU, memory, and filesystem. After session termination the entire microVM is destroyed and memory sanitised; no residual state can persist to a subsequent session or customer. This is the same isolation model as AgentCore Runtime and Code Interpreter [3]
- **Data residency:** Browser Tool resources are regional; session execution remains within the AWS region where the Browser resource is created. Session recordings stored in customer S3 buckets are subject to the bucket's region configuration — customers must ensure recording buckets are in approved regions. Browser profile data is stored regionally. External websites accessed by the browser may be hosted anywhere globally — the browser's outbound traffic traverses the public internet (or customer proxy) to reach target sites [1][7]

---

## 3. AWS Enabled Platform Controls

### 3a. Control Mapping

| Control Type | Control | Description |
|---|---|---|
| Detective | CloudTrail — management events | `CreateBrowser`, `DeleteBrowser`, `GetBrowser`, `ListBrowsers`, `CreateBrowserProfile`, `DeleteBrowserProfile`, `GetBrowserProfile`, `ListBrowserProfiles` are logged automatically as management events with no additional configuration [10] |
| Detective | CloudTrail — data events (`StartBrowserSession`, `StopBrowserSession`, `ConnectBrowserAutomationStream`, `ConnectBrowserLiveViewStream`) | All session invocation and streaming operations are data-plane events; they are **not** logged by default and require a manually configured CloudTrail trail with data event logging enabled — this is a material audit gap for tracking which agents accessed which websites [4][10] |
| Detective | Session recording and replay | Custom Browser resources can be configured to record all browser interactions (DOM changes, user actions, console logs, network events, CDP events) to a customer-specified S3 bucket. Recordings can be replayed via the AWS Console or standalone viewer for debugging, auditing, and compliance review. Session data has a 30-day TTL retention policy [7][8] |
| Detective | Live view | Real-time streaming of the browser session via AWS DCV allows human operators to observe agent actions as they occur; accessible via WebSocket at `/browser-streams/{browser-id}/sessions/{session-id}/live-view` with IAM SigV4 authentication [6][11] |
| Detective | CloudWatch metrics | Browser Tool emits operational metrics (latency, resource usage, session count) to CloudWatch for real-time performance monitoring [1][11] |
| Proactive | IAM condition keys for VPC enforcement | `bedrock-agentcore:subnets` and `bedrock-agentcore:securityGroups` condition keys can be used in IAM policies to deny `CreateBrowser` operations that do not specify approved VPC subnets and security groups — enforcing VPC mode at the IAM layer [9] |
| Proactive | Service Quotas | Default limit of 500 concurrent sessions per Browser resource prevents uncontrolled resource proliferation; quota increases require explicit support ticket approval [3] |
| Preventative | VPC mode with proxy routing | When VPC mode is configured, browser traffic can be routed through a customer-controlled proxy server, enabling URL filtering, content inspection, and egress control. Proxy configuration supports HTTP/HTTPS proxies with optional authentication [5][9] |
| Preventative | Execution role scoping | The IAM execution role attached to a Browser resource defines the blast radius of any credential exfiltration from MMDS; scoping this role to the minimum required permissions (e.g. specific S3 bucket ARNs for session recordings only) is the primary defence against privilege escalation from within the browser session [4] |
| Preventative | Browser profile isolation | Browser profiles (persisted cookies, local storage) are stored as separate resources with their own IAM permissions (`CreateBrowserProfile`, `GetBrowserProfile`, `DeleteBrowserProfile`, `SaveBrowserProfile`, `LoadBrowserProfile`); access to authentication state can be restricted to specific principals [8] |
| Responsive | Session termination APIs | `StopBrowserSession` terminates the microVM immediately, destroying all session state and revoking the session's access to the execution role credentials [1][3] |
| Responsive | `DeleteBrowser` / `DeleteBrowserProfile` | Entire Browser resources and profile resources can be deleted to prevent any further session creation or authentication state reuse; combined with SCP-level restrictions, this provides a rapid containment mechanism [1][8] |

### 3b. Service Control Policy (SCP)

The following SCP is a production-ready starting point to be attached at the AWS Organizations OU level for accounts using AgentCore Browser Tool. Substitute `["us-east-1", "eu-west-1"]` with your organisation's approved region list before applying.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyBrowserCreationOutsideApprovedRegions",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:CreateBrowser",
        "bedrock-agentcore:CreateBrowserProfile"
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
      "Sid": "DenyBrowserInvocationByUnauthorisedPrincipals",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:StartBrowserSession",
        "bedrock-agentcore:ConnectBrowserAutomationStream",
        "bedrock-agentcore:ConnectBrowserLiveViewStream"
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
      "Sid": "DenyBrowserProfileAccessByUnauthorisedPrincipals",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:SaveBrowserProfile",
        "bedrock-agentcore:LoadBrowserProfile",
        "bedrock-agentcore:GetBrowserProfile"
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
      "Sid": "DenyUseOfSystemBrowserARN",
      "Effect": "Deny",
      "Action": [
        "bedrock-agentcore:StartBrowserSession"
      ],
      "Resource": "arn:aws:bedrock-agentcore:*:aws:browser/aws.browser.v1",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/BreakGlassAdmin"
        }
      }
    },
    {
      "Sid": "DenyDeletionOfBrowserAuditTrails",
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
      "Sid": "DenyDeletionOfSessionRecordingBuckets",
      "Effect": "Deny",
      "Action": [
        "s3:DeleteBucket",
        "s3:DeleteObject",
        "s3:DeleteObjectVersion"
      ],
      "Resource": [
        "arn:aws:s3:::*-browser-recordings*",
        "arn:aws:s3:::*-browser-recordings*/*"
      ],
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

- The SCP `DenyBrowserWithoutVPC` statement prevents creation of new custom Browser resources without VPC configuration, but it does **not** prevent use of the system-managed Browser ARN (`arn:aws:bedrock-agentcore:<region>:aws:browser/aws.browser.v1`), which has public internet access by default. The `DenyUseOfSystemBrowserARN` statement blocks this, but must be explicitly included
- The SCP cannot prevent MMDS credential access from within a running browser session — this is confirmed AWS-intended behaviour. The execution role's permissions are the only effective control; the SCP cannot enforce that execution roles are least-privilege
- The SCP cannot prevent the browser from accessing arbitrary websites on the public internet — even with VPC mode enabled, the browser requires internet access to function. URL filtering must be implemented via a customer-managed proxy server configured in the Browser resource [5]
- The SCP cannot prevent sensitive data (credentials, PII, session tokens) from being captured in session recordings — customers must implement application-layer controls to mask or exclude sensitive data from recordings, or disable recording for sessions handling sensitive data
- The SCP cannot enforce that session recording S3 buckets are in approved regions or have CMK encryption enabled; this must be enforced via S3 bucket policies and AWS Config rules
- The SCP cannot prevent browser profiles from storing authentication credentials (cookies, tokens) for external websites — profile data is stored in the customer's account but may contain third-party credentials; access to profile resources must be tightly controlled via IAM
- The SCP cannot prevent a browser session from being used to pivot to other AWS services using exfiltrated MMDS credentials — post-exfiltration activity is attributed to the execution role identity in CloudTrail, not the human actor
- Resource-based policies are not currently supported for Browser or BrowserProfile resources; the SCP uses principal-based conditions as the only available centralised mechanism [4]

---

## 4. AWS Identity & Access Management (IAM)

| Role / Policy | Purpose | Trust Relationship |
|---|---|---|
| `BedrockAgentCoreFullAccess` (AWS managed) | Broad admin access to all AgentCore resources including Browser; includes `bedrock-agentcore:*` — not suitable for production | Attached to IAM users/roles by account admin |
| Browser execution role (customer-managed) | Assumed by the Browser microVM at runtime via MMDS; defines what AWS resources the browser session can access (S3 for session recordings, Secrets Manager for proxy credentials, etc.); this role's credentials are accessible from within the browser via MMDS and represent the primary privilege escalation surface | Trusted by `bedrock-agentcore.amazonaws.com`; passed at `CreateBrowser` time via `iam:PassRole` |
| Invoking role (customer-managed) | The IAM role used by the agent or application to call `StartBrowserSession`, `ConnectBrowserAutomationStream`, `ConnectBrowserLiveViewStream`; separate from the execution role | Trusted by the agent runtime or calling application; must have browser actions scoped to specific Browser resource ARNs |
| `AWSServiceRoleForBedrockAgentCoreNetwork` (service-linked) | Created automatically when VPC mode is configured; allows AgentCore to create and manage ENIs in the customer's VPC for browser outbound connectivity | Trusted by `network.bedrock-agentcore.amazonaws.com`; cannot be assumed by customer principals [12] |

**Required IAM permissions for Browser Tool:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BrowserManagement",
      "Effect": "Allow",
      "Action": [
        "bedrock-agentcore:CreateBrowser",
        "bedrock-agentcore:ListBrowsers",
        "bedrock-agentcore:GetBrowser",
        "bedrock-agentcore:DeleteBrowser",
        "bedrock-agentcore:StartBrowserSession",
        "bedrock-agentcore:ListBrowserSessions",
        "bedrock-agentcore:GetBrowserSession",
        "bedrock-agentcore:StopBrowserSession",
        "bedrock-agentcore:UpdateBrowserStream",
        "bedrock-agentcore:ConnectBrowserAutomationStream",
        "bedrock-agentcore:ConnectBrowserLiveViewStream"
      ],
      "Resource": "arn:aws:bedrock-agentcore:<region>:<account>:browser/*"
    },
    {
      "Sid": "BrowserProfileManagement",
      "Effect": "Allow",
      "Action": [
        "bedrock-agentcore:CreateBrowserProfile",
        "bedrock-agentcore:ListBrowserProfiles",
        "bedrock-agentcore:GetBrowserProfile",
        "bedrock-agentcore:DeleteBrowserProfile",
        "bedrock-agentcore:SaveBrowserProfile",
        "bedrock-agentcore:LoadBrowserProfile"
      ],
      "Resource": "arn:aws:bedrock-agentcore:<region>:<account>:browser-profile/*"
    }
  ]
}
```

**Execution role permissions for session recording:**

```json
{
  "Sid": "SessionRecordingS3Access",
  "Effect": "Allow",
  "Action": [
    "s3:PutObject",
    "s3:ListMultipartUploadParts",
    "s3:AbortMultipartUpload"
  ],
  "Resource": "arn:aws:s3:::<recording-bucket>/<prefix>/*",
  "Condition": {
    "StringEquals": {
      "aws:ResourceAccount": "<account-id>"
    }
  }
}
```

**Least-privilege guidance for production:**
- The execution role is the most critical control surface — it must be scoped to the absolute minimum permissions required. If the browser only needs to write session recordings to a specific S3 bucket, the execution role should have `s3:PutObject` on that bucket ARN only. Any permission granted to the execution role is effectively grantable to any script or extension running in the browser [4]
- Do not attach `BedrockAgentCoreFullAccess` or any broad AWS managed policy to the execution role; create a custom policy with only the specific actions and resource ARNs required
- Restrict `iam:PassRole` to roles matching an approved naming convention (e.g. `AgentCoreBrowserExecution*`) conditioned on `iam:PassedToService: bedrock-agentcore.amazonaws.com`
- Scope `StartBrowserSession` and streaming permissions on the invoking role to specific Browser resource ARNs — not wildcards
- Separate browser profile management permissions from session invocation permissions — principals that can start sessions should not necessarily be able to create or delete profiles containing authentication state
- Use IAM condition keys `bedrock-agentcore:subnets` and `bedrock-agentcore:securityGroups` in the invoking role's policy to enforce VPC mode at the IAM layer in addition to the SCP [9]

---

## 5. Data Protection

**Encryption at Rest:**
- Session-local browser state within the microVM is ephemeral and destroyed on session termination; there is no persistent storage to encrypt at the session layer
- Browser profile data (cookies, local storage) persisted via `SaveBrowserProfile` is stored in AWS-managed storage; encryption details are not publicly documented — customers should treat profile data as potentially containing sensitive authentication credentials and restrict access via IAM
- Session recordings stored in customer S3 buckets are encrypted according to the S3 bucket's encryption policy; CMK enforcement must be applied via S3 bucket policy requiring `aws:kms` encryption — this is the customer's responsibility
- Session recordings may contain sensitive data visible in the browser (credentials entered in forms, PII displayed on pages, session tokens in URLs) — customers must implement application-layer controls to mask sensitive data or disable recording for sensitive sessions
- FIPS 140-3 validated endpoints are available for environments with FIPS compliance requirements [13]

**Encryption in Transit:**
- All API communication (control-plane and data-plane) uses TLS 1.2 minimum; TLS 1.3 is recommended [13]
- WebSocket connections for automation (`ConnectBrowserAutomationStream`) and live view (`ConnectBrowserLiveViewStream`) use WSS (WebSocket Secure) with TLS
- Live view streaming via AWS DCV uses encrypted transport; authentication is handled via IAM SigV4-signed query parameters [6]
- Browser sessions communicate with external websites over HTTPS as determined by the target site; the service does not enforce TLS on external web targets — agents browsing HTTP sites will transmit data unencrypted over the public internet
- Proxy connections (when configured) support HTTPS proxies; proxy authentication credentials can be stored in AWS Secrets Manager and referenced by the Browser resource [5]
- MMDS credential retrieval within the microVM uses the link-local address `169.254.169.254` over HTTP (not HTTPS) — this is an internal-only path within the microVM and does not traverse any network boundary, but the credentials retrieved are transmitted in plaintext within the browser environment

---

## 6. Network Security

- Browser Tool microVMs run in an AWS-managed service account by default; they are not inside the customer's VPC and are not subject to customer-managed security groups or NACLs in the default configuration
- Browser Tool requires internet access by design — it cannot operate in a fully isolated mode like Code Interpreter's "Sandbox" mode. Two network configurations are available [1][9]:
  - **Public mode** (default): full internet access; browser can reach any website; highest risk for data exfiltration
  - **VPC mode**: outbound traffic routed through customer VPC via ENIs; browser traffic can be directed through a customer-managed proxy for URL filtering, content inspection, and egress control; recommended for regulated workloads
- Proxy configuration supports [5]:
  - HTTP and HTTPS proxy servers
  - Proxy authentication via username/password (credentials can be stored in Secrets Manager)
  - Proxy bypass lists for specific domains
  - IP stability for websites that enforce IP-based access controls
- PrivateLink is supported for Browser Tool data-plane API calls via the shared `com.amazonaws.<region>.bedrock-agentcore` endpoint; control-plane operations (`CreateBrowser`) use `bedrock-agentcore-control.<region>.amazonaws.com` for which PrivateLink is not currently supported [14]
- VPC mode requires the `AWSServiceRoleForBedrockAgentCoreNetwork` service-linked role; ENIs created in the customer's subnets persist up to 8 hours after session termination
- Security groups and NACLs apply to the ENIs created in the customer's VPC for VPC-mode outbound connectivity; they do not apply to the microVM itself in non-VPC mode
- The system-managed Browser ARN (`aws.browser.v1`) has public internet access and cannot be configured with VPC mode or proxy settings — it should be blocked via SCP for regulated workloads
- Browser extensions can be loaded into sessions to customise browser behaviour; extensions have access to the browser's network stack and can make arbitrary HTTP requests — only trusted, reviewed extensions should be permitted [5]

---

## 7. Logging and Monitoring

**CloudTrail:**
- Management events (logged by default, no additional configuration): `CreateBrowser`, `DeleteBrowser`, `GetBrowser`, `ListBrowsers`, `CreateBrowserProfile`, `DeleteBrowserProfile`, `GetBrowserProfile`, `ListBrowserProfiles`
- Data events (not logged by default — must be explicitly enabled via a CloudTrail trail with data event logging; additional cost applies): `StartBrowserSession`, `StopBrowserSession`, `ConnectBrowserAutomationStream`, `ConnectBrowserLiveViewStream`, `SaveBrowserProfile`, `LoadBrowserProfile`
- Critical gap: without data event logging enabled, there is no audit trail of which agent started which browser session, which websites were accessed, or when authentication profiles were loaded. Given that MMDS credential exfiltration is possible from within the browser, `StartBrowserSession` data events are essential for detecting abuse [4]
- Post-exfiltration detection: if MMDS credentials are exfiltrated and used outside the browser, the resulting CloudTrail events will show the execution role's ARN as the principal — not the attacker's identity. SIEM rules must alert on unexpected management plane calls from execution role ARNs (e.g. `sts:AssumeRole`, `iam:*`, `ec2:*`) that are inconsistent with the role's intended purpose
- CloudTrail logs should be delivered to an S3 bucket with Object Lock (WORM) enabled in a dedicated logging account

**Session Recording:**
- Session recordings provide a comprehensive audit trail of browser activity: DOM changes, user actions (clicks, scrolls, form interactions), console logs, network events, and CDP events [7]
- Recordings are stored in customer-specified S3 buckets and can be replayed via the AWS Console or standalone viewer
- Session data has a 30-day TTL retention policy — customers requiring longer retention must copy recordings to a separate archive bucket
- Recordings may contain sensitive data (credentials, PII, session tokens) visible in the browser — access to recording buckets must be tightly controlled via S3 bucket policies and IAM

**VPC Flow Logs:**
- Browser Tool does not create ENIs in the customer's VPC by default; VPC Flow Logs are not applicable in the default (public) configuration
- When VPC mode is enabled, ENIs are created in the customer's subnets; VPC Flow Logs on those subnets will capture outbound traffic from the browser to the proxy or NAT Gateway — providing network-level visibility into egress patterns
- For public mode deployments, network-level visibility is limited to CloudTrail API logs, CloudWatch metrics, and session recordings; there is no equivalent of VPC Flow Logs for traffic between the browser microVM and external websites

**Compliance:**
- Amazon Bedrock AgentCore (including Browser Tool) is in scope for: SOC 1 Type II, SOC 2 Type II, SOC 3, ISO 27001, ISO 27017, ISO 27018, PCI DSS Level 1, HIPAA eligibility, FedRAMP Moderate [15]
- Customer responsibilities not handled by AWS: enabling CloudTrail data event logging for all browser session events; configuring VPC mode with proxy routing for all production Browser deployments handling sensitive data; implementing URL filtering via proxy to restrict accessible websites; scoping execution roles to the minimum required permissions (the primary defence against MMDS credential abuse); enforcing VPC mode via IAM condition keys (`bedrock-agentcore:subnets`, `bedrock-agentcore:securityGroups`); applying CMK encryption to S3 buckets used for session recordings; ensuring session recording S3 buckets are in approved regions; implementing application-layer controls to mask sensitive data in session recordings; restricting access to browser profile resources containing authentication state; reviewing and approving browser extensions before deployment; retaining CloudTrail logs and session recordings for the period required by applicable regulations

---

## Sources

1. AWS Docs — Interact with web applications using Amazon Bedrock AgentCore Browser: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-tool.html
2. AWS Blog — Introducing Amazon Bedrock AgentCore Browser Tool (Jul 2025): https://aws.amazon.com/blogs/machine-learning/introducing-amazon-bedrock-agentcore-browser-tool/
3. AWS Docs — Resource and session management (Browser): https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-resource-session-management.html
4. Sonrai Security — Sandboxed to Compromised: Credential Exfiltration Paths in AWS Code Interpreters (Feb 2026): https://sonraisecurity.com/blog/sandboxed-to-compromised-new-research-exposes-credential-exfiltration-paths-in-aws-code-interpreters/
5. AWS Blog — Customize AI agent browsing with proxies, profiles, and extensions in Amazon Bedrock AgentCore Browser (Feb 2026): https://aws.amazon.com/blogs/ai/customize-ai-agent-browsing-with-proxies-profiles-and-extensions-in-amazon-bedrock-agentcore-browser/
6. AWS Docs — Rendering live view using AWS DCV Web Client: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-dcv-integration.html
7. AWS Docs — Browser session recording and replay: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-session-replay.html
8. AWS Docs — Browser profiles: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-profiles.html
9. AWS Docs — Use IAM condition keys with AgentCore Runtime and built-in tools VPC settings: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/security-vpc-condition.html
10. AWS Docs — Logging Gateway API calls with CloudTrail: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-cloudtrail.html
11. AWS Docs — Observability and session replay (Browser): https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/browser-observability.html
12. AWS Docs — Using service-linked roles for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/service-linked-roles.html
13. AWS Docs — Data protection in Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/data-protection.html
14. AWS Docs — Use interface VPC endpoints (PrivateLink) for AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/vpc-interface-endpoints.html
15. AWS What's New — AgentCore generally available (Oct 2025): https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-available
