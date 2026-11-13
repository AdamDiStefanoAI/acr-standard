# Curated ACR resources

A short reading list for evaluating the standard and building integrations. External
links checked 2026-11-13; these are references, not endorsements or conformance
certificates. Framework documentation may describe newer APIs than the versions
pinned by ACR examples; use each example's requirements and safety notes.

1. [ACR Standard v1.2.0 PDF](https://runtimecontrol.io/downloads/ACR_Standard_v1.2.0.pdf) — Normative requirements, including trust-path, policy, evidence, and human-authority obligations.
2. [ACR standard publication page](https://runtimecontrol.io/standard) — Publisher's artifact/version history and scope, separate from software releases.
3. [LangGraph overview](https://docs.langchain.com/oss/python/langgraph/overview) — Understand the compiled state graphs used in ACR's deterministic agent examples.
4. [CrewAI documentation](https://docs.crewai.com/) — Reference for crew/tool integration boundaries; ACR examples do not imply framework-wide enforcement.
5. [AutoGen documentation](https://microsoft.github.io/autogen/stable/) — Agent and tool orchestration concepts relevant to identifying where a guard must run.
6. [OPA policy language](https://www.openpolicyagent.org/docs/policy-language) — Rego rules and data semantics behind the reference policy engine; ACR currently pins OPA 0.70.0, so check version-specific syntax.
7. [OPA policy testing](https://www.openpolicyagent.org/docs/policy-testing) — How to write and run executable policy regression cases.
8. [MCP specification](https://modelcontextprotocol.io/specification/latest) — Protocol and authorization context for reviewing agent/tool integrations; a protocol connection alone does not enforce ACR.
9. [OpenTelemetry documentation](https://opentelemetry.io/docs/) — Tracing and instrumentation concepts useful when following a decision across services.
10. [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) — Organizational risk context for ACR's informative governance mappings.

A companion book or community article/video is not listed until its exact title,
public destination, and relevance can be verified. This list intentionally avoids
inventing a publication or treating vendor promotion as independent validation.

[Back to documentation](README.md)
