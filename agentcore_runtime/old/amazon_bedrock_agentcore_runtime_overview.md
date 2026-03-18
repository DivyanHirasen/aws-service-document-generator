# Amazon Bedrock AgentCore Runtime — Service Approval / Risk Assessment

> Prepared for: Banking / Financial Services Risk & Compliance Review
> Document Date: March 2026
> Service Assessed: Amazon Bedrock AgentCore Runtime

---

## Service Description

Amazon Bedrock AgentCore Runtime is a secure, fully managed, serverless execution environment purpose-built for deploying and operating AI agents and tools at enterprise scale [1][2]. It sits within the broader Amazon Bedrock AgentCore platform — AWS's strategic answer to the "prototype-to-production" gap in agentic AI — and abstracts away all infrastructure management including compute provisioning, session lifecycle, scaling, and security isolation. The defining architectural pattern is per-session microVM isolation: each user session runs inside a dedicated Firecracker microVM with isolated CPU, memory, and filesystem, which is fully terminated and memory-sanitised upon session completion [3]. This delivers deterministic security guarantees even when the underlying AI reasoning process is non-deterministic. Runtime is framework-agnostic and model-agnostic, supporting popular open-source frameworks (LangGraph, CrewAI, LlamaIndex, Google ADK, OpenAI Agents SDK, Strands Agents), any foundation model in or outside Amazon Bedrock (Anthropic Claude, Amazon Nova, OpenAI, Google Gemini, Meta Llama, Mistral), and standard agentic protocols including Model Context Protocol (MCP) and Agent-to-Agent (A2A) [1][4]. For regulated and enterprise workloads, Runtime provides built-in identity integration with corporate IdPs, agent-specific observability via OpenTelemetry, VPC connectivity, and consumption-based pricing that charges only for active compute — not idle I/O wait time. It is the foundational hosting layer within AgentCore, complemented by Memory, Gateway, Identity, Observability, Policy, Code Interpreter, Browser, and Evaluations capabilities.

---

## Core Capabilities

- Per-session microVM isolation (Firecracker): dedicated CPU, memory, and filesystem per session; full teardown and memory sanitisation on session end [3]
- Extended execution: supports both synchronous real-time interactions (up to 15-minute request timeout) and asynchronous long-running workloads up to 8 hours [5]
- Framework and model agnostic: works with any open-source agent framework and any LLM, including models outside Amazon Bedrock [1]
- Protocol support: MCP (Model Context Protocol) and A2A (Agent-to-Agent) for inter-agent and tool communication [4]
- Built-in inbound authentication: integrates with corporate IdPs (Okta, Microsoft Entra ID, Amazon Cognito) via AgentCore Identity; supports OAuth and API key outbound auth flows [3]
- VPC connectivity: agents can connect to private VPC resources (databases, internal APIs) via ENIs managed by a service-linked role; VPC PrivateLink supported for data-plane inbound calls [6]
- Bidirectional streaming: supports HTTP API and persistent WebSocket connections for real-time streaming responses [3]
- 100 MB payload support: handles multimodal inputs (text, images, audio, video) and large datasets [3]
- Agent-specific observability: built-in tracing of reasoning steps, tool invocations, and model interactions; OTEL-compatible; integrates with CloudWatch, Datadog, Dynatrace, Langfuse, LangSmith [4]
- Consumption-based pricing: charges only for active CPU and memory usage; I/O wait time (LLM response latency) is not billed [7]
- Versioning and endpoints (aliases): up to 1,000 versions per agent; up to 10 endpoints (aliases) per agent for blue/green or canary deployments [5]
- Resource-based policies and IAM: fine-grained access control via IAM and resource-based policies (up to 20 KB policy size, 100 statements) [5]
- CloudFormation, CDK, and Terraform support for IaC-driven deployments [4][8]
- Direct code deployment or container (Docker image) deployment options [5]

---

## API / SDK Support

- AWS CLI support: Yes. The AgentCore starter toolkit provides a dedicated `agentcore` CLI for configuring, launching, and managing agents and gateways [9]. Standard AWS CLI (`aws bedrock-agentcore`) also supports control-plane operations.
  ```bash
  # Example: invoke an agent runtime endpoint
  aws bedrock-agentcore invoke-agent-runtime \
    --agent-runtime-id <runtime-id> \
    --endpoint-id <endpoint-id> \
    --body '{"input": "What is my account balance?"}' \
    --region us-east-1
  ```
- Official SDKs: Python (boto3 / `bedrock-agentcore` PyPI package), with CDK support in Python, TypeScript/JavaScript, Java, and other CDK-supported languages [8][10]
- Key control-plane APIs:
  - `CreateAgentRuntime` — provision a new runtime (5 TPS)
  - `UpdateAgentRuntime` — update runtime configuration (5 TPS)
  - `DeleteAgentRuntime` — remove a runtime (5 TPS)
  - `GetAgentRuntime` / `ListAgentRuntimes` — describe runtimes (50 / 5 TPS)
  - `CreateAgentRuntimeEndpoint` / `DeleteAgentRuntimeEndpoint` — manage endpoints (5 TPS)
  - `ListAgentRuntimeVersions` — list versions (5 TPS)
- Key data-plane APIs:
  - `InvokeAgentRuntime` — synchronous invocation (25 TPS per agent)
  - `InvokeAgentRuntimeCommand` — command execution with configurable timeout (25 TPS per agent; command size 1 byte–64 KB)
  - `InvokeAgentRuntimeWithWebSocketStream` — bidirectional WebSocket streaming (25 TPS per agent)
- IaC support:
  - CloudFormation: `AWS::BedrockAgentCore::Runtime` resource type (GA); supports `AgentRuntimeArtifact`, `NetworkConfiguration`, `AuthorizerConfiguration`, `LifecycleConfiguration`, `ProtocolConfiguration` [8]
  - CDK: `aws_cdk.aws_bedrock_agentcore_alpha` construct library (Python, TypeScript) [10]
  - Terraform: AWS provider support available via standard Terraform AWS provider

---

## Service Architecture

**Deployment model:** Regional, serverless/managed. No EC2 instances to provision or manage. Available in 14 AWS Regions as of March 2026: US East (N. Virginia), US East (Ohio), US West (Oregon), Asia Pacific (Mumbai), Asia Pacific (Seoul), Asia Pacific (Singapore), Asia Pacific (Sydney), Asia Pacific (Tokyo), Europe (Frankfurt), Europe (Ireland), Europe (London), Europe (Paris), Europe (Stockholm), Canada (Central) [11].

**Core architectural concepts:**

| Concept | Description |
|---|---|
| Agent Runtime | The top-level resource representing a deployed agent or tool. Backed by a Docker container image (up to 2 GB) or a direct code deployment package (up to 250 MB compressed / 750 MB uncompressed). |
| Version | An immutable snapshot of an agent runtime. Up to 1,000 versions per agent; inactive versions are deleted after 45 days. |
| Endpoint (Alias) | A named pointer to a specific version, used for routing (e.g., `prod`, `staging`). Up to 10 endpoints per agent. |
| Session | A per-user execution context backed by a dedicated Firecracker microVM. Fully isolated CPU, memory, and filesystem. |
| Asynchronous Job | A long-running execution within a session, supporting up to 8 hours of continuous operation. |
| Protocol | The communication protocol for the runtime: HTTP, MCP, or A2A. Configured at endpoint level. |

**Session / job lifecycle:**

- Session creation: microVM is provisioned on first invocation; fast cold-start optimised for real-time interactions
- Idle timeout: 15 minutes of inactivity (configurable via `idleRuntimeSessionTimeout` in `LifecycleConfiguration`)
- Maximum session duration: 8 hours (configurable via `maxLifetime` in `LifecycleConfiguration`)
- Session termination: entire microVM is destroyed; memory is sanitised; no state persists in the execution environment (state must be externalised to AgentCore Memory or other stores)
- Synchronous request timeout: 15 minutes
- Streaming connection maximum duration: 60 minutes
- Asynchronous job maximum duration: 8 hours

**Networking:**

- Public endpoint: by default, Runtime exposes a public HTTPS endpoint; inbound calls are authenticated via AgentCore Identity (OAuth / IAM)
- VPC connectivity: agents can be configured with VPC subnets and security groups; AWS creates ENIs in the customer VPC via the `AWSServiceRoleForBedrockAgentCoreNetwork` service-linked role; ENIs persist up to 8 hours after agent deletion [6]
- VPC PrivateLink: supported for data-plane (inbound) API calls when the application is hosted inside a customer VPC; control-plane endpoints do not currently support PrivateLink [12]
- Internet access from VPC: requires NAT Gateway in a public subnet; direct public subnet attachment does not provide internet access [6]
- Required VPC endpoints for air-gapped deployments: `ecr.dkr`, `ecr.api`, `s3` (gateway), `logs` (CloudWatch) [6]

**Quotas and limits (Runtime):**

| Limit | Default Value | Adjustable |
|---|---|---|
| Active session workloads per account | 1,000 (us-east-1, us-west-2); 500 (other regions) | Yes |
| Total agents per account | 1,000 | Yes |
| Versions per agent | 1,000 | Yes |
| Endpoints (aliases) per agent | 10 | Yes |
| Max Docker image size | 2 GB | No |
| Max direct code package (compressed) | 250 MB | No |
| Max direct code package (uncompressed) | 750 MB | No |
| Max hardware per session | 2 vCPU / 8 GB RAM | No |
| Synchronous request timeout | 15 minutes | No |
| Max payload size | 100 MB | No |
| Streaming chunk size | 10 MB | No |
| Streaming max duration | 60 minutes | No |
| Async job max duration | 8 hours | No |
| InvokeAgentRuntime TPS (per agent) | 25 | Yes |
| New sessions per endpoint per minute (container) | 100 TPM | Yes |
| WebSocket frame size | 32 KB | No |
| WebSocket frame rate per connection | 250 fps | No |

---

## Risk Classification

- Internet-Facing: Conditional — by default, Runtime endpoints are publicly accessible over HTTPS and require authentication (OAuth tokens or IAM SigV4). VPC PrivateLink can be configured for data-plane calls to eliminate public internet traversal for inbound traffic. Outbound internet access from within a VPC-connected runtime requires a NAT Gateway.
- Handles PCI Data: Possible — agents deployed on Runtime can process any data passed in session payloads, including payment card data. PCI DSS applicability depends entirely on what data the customer chooses to send to the agent.
- Handles PII: Possible — session payloads, tool call inputs/outputs, and agent reasoning traces may contain PII depending on the use case. Customers are responsible for data minimisation and ensuring PII is not unnecessarily logged or persisted.
- Handles Regulated Data: Possible — applicable to any regulated data category (financial, health, personal) depending on the workload deployed.
- Classification: High
- Justification: AgentCore Runtime introduces a novel execution model for AI agents that combines several risk dimensions relevant to regulated financial institutions. First, the non-deterministic nature of LLM-driven reasoning means agent outputs and tool invocations cannot be fully predicted or audited in advance, requiring compensating controls such as AgentCore Policy (Cedar-based deterministic guardrails) and comprehensive observability. Second, agents can be granted outbound authentication credentials (OAuth tokens, API keys) to access third-party services and internal systems, creating a broad potential blast radius if an agent is compromised or behaves unexpectedly. Third, while per-session microVM isolation provides strong compute-level separation, the data-plane endpoint is internet-accessible by default, requiring explicit VPC PrivateLink configuration to eliminate public exposure. Fourth, session payloads of up to 100 MB can contain sensitive financial data, and customers must ensure encryption in transit (TLS enforced by AWS) and at rest (KMS-managed keys for any persisted state). Mitigating factors include: mandatory IAM/OAuth authentication on all endpoints, per-session microVM isolation with memory sanitisation, VPC and PrivateLink support, CloudTrail auditability of all control-plane API calls, OTEL-compatible observability for agent reasoning traces, Cedar-based Policy enforcement for deterministic tool-call guardrails, and consumption-based pricing that avoids persistent always-on compute surfaces. Organisations should implement least-privilege IAM roles for agent runtimes, enable VPC PrivateLink for all production workloads, enforce AgentCore Policy rules for all tool interactions, and ensure all agent traces are retained in CloudWatch for audit purposes.

---

## Roadmap & Maturity

- GA Date: October 13, 2025 (Preview announced July 16, 2025 at AWS Summit New York) [2][4]
- Maturity: Maturing — the service reached GA in October 2025 after a ~3-month public preview. Core Runtime capabilities are stable; several adjacent capabilities (Evaluations) remain in preview as of March 2026.
- Recent Feature Additions:
  - July 2025 (Preview): Initial launch of AgentCore Runtime with microVM session isolation, 8-hour async execution, framework/model agnosticism, MCP support [2]
  - October 2025 (GA): VPC support, AWS PrivateLink (data plane), CloudFormation resource (`AWS::BedrockAgentCore::Runtime`), resource tagging, A2A protocol support added to Runtime [4]
  - October 2025 (GA): AgentCore Policy (Cedar-based deterministic guardrails), AgentCore Identity with identity-aware authorisation and OAuth vault storage [4]
  - October 2025 (GA): AgentCore Observability with CloudWatch dashboards, OTEL compatibility, integrations with Datadog, Dynatrace, Langfuse, LangSmith, Arize Phoenix [4]
  - November–December 2025 (re:Invent 2025): Expanded A2A protocol support across AgentCore services; AGUI server deployment support; stateful MCP server features; re:Invent keynote featured AgentCore as a flagship agentic AI offering [13]
  - March 2026: AgentCore Policy reached GA across 14 regions; additional region expansion (Seoul, London, Paris, Stockholm, Canada Central) [11]
- Active Development Signals: Featured prominently in AWS re:Invent 2025 keynote; active AWS Machine Learning Blog cadence (multiple posts per month); rapid regional expansion from 9 regions at GA to 14 regions by March 2026; customer references from Thomson Reuters and Epsilon published at launch; dedicated starter toolkit on GitHub with active commits; PyPI package (`bedrock-agentcore`) with regular releases [2][13]
- Deprecation Risk: None — AgentCore Runtime is a net-new service with no predecessor to deprecate; it is central to AWS's stated agentic AI strategy and received significant re:Invent 2025 investment
- Strategic Alignment: Core to AWS's current AI/ML frontier strategy. AgentCore represents AWS's primary platform bet for enterprise agentic AI, positioned as the production-grade infrastructure layer for AI agents across all industries. It is tightly integrated with the broader Amazon Bedrock ecosystem (foundation models, Knowledge Bases, Guardrails) and is the recommended path for customers moving agent workloads from prototype to production on AWS.

---

## Sources

1. AWS Documentation — What is Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html
2. AWS Blog — Introducing Amazon Bedrock AgentCore (Preview, July 2025): https://aws.amazon.com/blogs/aws/introducing-amazon-bedrock-agentcore-securely-deploy-and-operate-ai-agents-at-any-scale/
3. AWS Documentation — Host agent or tools with AgentCore Runtime: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agents-tools-runtime.html
4. AWS What's New — Amazon Bedrock AgentCore is now generally available (October 2025): https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-available
5. AWS Documentation — Quotas for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/bedrock-agentcore-limits.html
6. AWS Documentation — Configure AgentCore Runtime and tools for VPC: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html
7. AWS — Amazon Bedrock AgentCore Pricing: https://aws.amazon.com/bedrock/agentcore/pricing/
8. AWS CloudFormation Template Reference — AWS::BedrockAgentCore::Runtime: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bedrockagentcore-runtime.html
9. AWS GitHub — AgentCore Starter Toolkit CLI: https://aws.github.io/bedrock-agentcore-starter-toolkit/api-reference/cli.html
10. AWS CDK — aws_cdk.aws_bedrock_agentcore_alpha: https://docs.aws.amazon.com/cdk/api/v2/python/aws_cdk.aws_bedrock_agentcore_alpha/README.html
11. AWS What's New — Policy in Amazon Bedrock AgentCore is now generally available (March 2026): https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/
12. AWS GitHub — AgentCore Starter Toolkit — VPC Interface Endpoints: https://aws.github.io/bedrock-agentcore-starter-toolkit/user-guide/security/vpc-interface-endpoints.html
13. AWS Blog — Make agents a reality with Amazon Bedrock AgentCore: Now generally available (October 2025): https://aws.amazon.com/blogs/machine-learning/amazon-bedrock-agentcore-is-now-generally-available/
