# Amazon Bedrock AgentCore Runtime — Service Snapshot

> Banking / Financial Services Risk & Compliance | March 2026

---

## Service Description

Amazon Bedrock AgentCore Runtime is a fully managed, serverless execution environment for deploying and operating AI agents at enterprise scale, with no infrastructure management required [1]. Its defining differentiator for regulated workloads is per-session Firecracker microVM isolation — each session runs in a dedicated VM that is fully terminated and memory-sanitised on completion, delivering deterministic security guarantees even for non-deterministic AI workloads [2].

---

## Core Capabilities

- Per-session microVM isolation: dedicated CPU, memory, and filesystem; full teardown and memory sanitisation on session end [2]
- Extended execution: synchronous requests up to 15 minutes; asynchronous jobs up to 8 hours [3]
- Framework and model agnostic: LangGraph, CrewAI, LlamaIndex, Strands, OpenAI Agents SDK; any LLM in or outside Bedrock [1]
- Built-in inbound auth: integrates with Okta, Microsoft Entra ID, Amazon Cognito via AgentCore Identity; supports OAuth and API key outbound flows [2]
- VPC connectivity + PrivateLink: agents connect to private VPC resources via managed ENIs; PrivateLink supported for data-plane inbound calls [4]
- OTEL-compatible observability: agent reasoning traces, tool calls, and model interactions captured; integrates with CloudWatch, Datadog, Dynatrace, Langfuse [5]
- Consumption-based pricing: billed on active CPU and memory only — I/O wait time (LLM latency) is not charged [6]

---

## API / SDK Support

- AWS CLI: Yes (`aws bedrock-agentcore`); dedicated `agentcore` CLI via starter toolkit for deploy/manage workflows [7]
- SDKs: Python (boto3 + `bedrock-agentcore` PyPI package); CDK constructs available (`aws_cdk.aws_bedrock_agentcore_alpha`) [8]
- Key control-plane APIs: `CreateAgentRuntime`, `UpdateAgentRuntime`, `DeleteAgentRuntime`, `CreateAgentRuntimeEndpoint`
- Key data-plane APIs: `InvokeAgentRuntime` (sync), `InvokeAgentRuntimeCommand` (async), `InvokeAgentRuntimeWithWebSocketStream` (bidirectional)
- IaC: CloudFormation (`AWS::BedrockAgentCore::Runtime`), CDK (alpha construct), Terraform (AWS provider) [9]

---

## Service Architecture

- Deployment model: regional, serverless; available in 14 AWS Regions as of March 2026 [5]
- Agent Runtime: top-level resource; deployed via Docker image (≤2 GB) or direct code package (≤250 MB compressed)
- Version / Endpoint: immutable version snapshots (up to 1,000); named endpoints/aliases for routing (up to 10 per agent)
- Session lifecycle: idle timeout 15 min (configurable); max duration 8 hours (configurable); microVM destroyed and memory wiped on termination
- Networking: public HTTPS endpoint by default (auth required); VPC via service-linked role ENIs; PrivateLink for data-plane; NAT Gateway required for outbound internet from VPC [4]
- Hard limits (non-adjustable): 2 vCPU / 8 GB RAM per session; 100 MB max payload; 32 KB WebSocket frame; 2 GB max image size
- Default soft limits: 1,000 active sessions (us-east-1/us-west-2), 500 other regions; 25 TPS per endpoint (all adjustable via support) [3]

---

## Risk Classification

- Internet-Facing: Conditional
- Handles PCI Data: Possible
- Handles PII: Possible
- Handles Regulated Data: Possible
- Classification: High
- Justification: By default, Runtime endpoints are publicly accessible over HTTPS and require OAuth or IAM authentication — VPC PrivateLink must be explicitly configured to eliminate public internet exposure for production workloads. Agents can hold outbound OAuth credentials to access third-party systems, creating a broad blast radius if agent behaviour is unexpected or credentials are misused. The non-deterministic nature of LLM reasoning requires compensating controls: AgentCore Policy (Cedar-based guardrails) for deterministic tool-call enforcement, full CloudTrail auditability of control-plane operations, and OTEL trace retention in CloudWatch for agent reasoning audit trails. Key mitigations — microVM memory sanitisation, least-privilege IAM roles, KMS encryption for persisted state, VPC isolation, and Policy enforcement — must all be explicitly configured; they are not on by default.

---

## Roadmap & Maturity

- GA Date: October 2025 (Preview: July 2025)
- Maturity: Maturing
- Key Recent Changes:
  - Oct 2025 (GA): VPC, PrivateLink, CloudFormation, resource tagging, A2A protocol support added [5]
  - Oct–Dec 2025: AgentCore Policy (Cedar guardrails) GA; AGUI and stateful MCP server support; re:Invent 2025 keynote feature [10]
  - Mar 2026: Policy GA across 14 regions; regional expansion to Seoul, London, Paris, Stockholm, Canada Central [11]
- Deprecation Risk: None — net-new service with no predecessor; central to AWS's agentic AI platform strategy
- Strategic Alignment: AWS's primary production infrastructure layer for enterprise agentic AI, tightly integrated with the broader Amazon Bedrock ecosystem.

---

## Sources

1. AWS Docs — What is Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/what-is-bedrock-agentcore.html
2. AWS Docs — Host agent or tools with AgentCore Runtime: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agents-tools-runtime.html
3. AWS Docs — Quotas for Amazon Bedrock AgentCore: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/bedrock-agentcore-limits.html
4. AWS Docs — Configure AgentCore Runtime for VPC: https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agentcore-vpc.html
5. AWS What's New — AgentCore generally available (Oct 2025): https://aws.amazon.com/about-aws/whats-new/2025/10/amazon-bedrock-agentcore-available
6. AWS — AgentCore Pricing: https://aws.amazon.com/bedrock/agentcore/pricing/
7. AWS GitHub — AgentCore Starter Toolkit CLI: https://aws.github.io/bedrock-agentcore-starter-toolkit/api-reference/cli.html
8. PyPI — bedrock-agentcore: https://pypi.org/project/bedrock-agentcore/
9. AWS CloudFormation — AWS::BedrockAgentCore::Runtime: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-bedrockagentcore-runtime.html
10. AWS Blog — AgentCore now generally available: https://aws.amazon.com/blogs/machine-learning/amazon-bedrock-agentcore-is-now-generally-available/
11. AWS What's New — Policy in AgentCore GA (Mar 2026): https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/
