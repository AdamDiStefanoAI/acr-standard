# ACR Standard Documentation

This directory contains implementation guidance for ACR (Agentic Control at Runtime), a reference architecture for governing autonomous AI systems at runtime.

## Normative source and document versions

The publisher's current normative artifact is the [ACR Runtime Control Plane Standard v1.2.0 PDF](https://runtimecontrol.io/downloads/ACR_Standard_v1.2.0.pdf), dated 2026-11-07 (cover and publication page verified 2026-11-13). It supersedes v1.0.2. The [published standard page](https://runtimecontrol.io/standard) and PDF take precedence over repository guidance where they differ. Repository examples and recommended patterns do not add to or waive requirements, or demonstrate implementation conformance.

The repository specification label is also 1.2.0. This is distinct from the reference implementation's software releases, currently v1.3.1, and from unreleased changes on `main`. The downloaded PDF §6 pins incorporated repository materials to release v1.2.0. The website currently states v1.3.1 instead (checked 2026-11-13), so this incorporation pin is disputed across publisher sources. Do not claim the newer release is incorporated or infer conformance until the publisher reconciles that discrepancy; cite the exact PDF and commit assessed. Later `main` commits are not silently incorporated.

Some detailed guides were originally written against v1.0.1 and retain that historical baseline explicitly. They have not all been re-audited against the complete v1.2.0 artifact. Treat those summaries as informative, consult the current PDF for requirements, and do not infer conformance from a version-label update. Historical changelog entries describe the state when written, not today's normative publication status.

“ACR Framework v1.0” and telemetry schema version `1.0` in older guidance identify those documents or formats; they are not the normative PDF version or a software release identifier. Cite the exact artifact and version assessed. See the [adoption guide](../ADOPTION.md#citation).

Section 21 intentionally covers both operational attack surfaces and the canonical STRIKE taxonomy. Preserve both views when mapping threats; one does not replace the other. Conformance claims follow §23 and must state their scope. Level 1 observability alone does not establish controlled execution or full runtime control-plane compliance.

## Get Started by Role

Choose a path based on your role. Each path is 3–5 steps to the most relevant docs.

| Role | Goal | Path |
|------|------|------|
| **Architect** | Design runtime governance into your AI systems | [Control Plane Architecture](architecture/acr-control-plane-architecture.md) → [Runtime Architecture](architecture/acr-runtime-architecture.md) → [Implementation Guide](guides/acr-implementation-guide.md) → [Telemetry Schema](specifications/telemetry-schema.md) |
| **Security** | Understand threats and controls | [STRIKE Threat Model](security/acr-strike-threat-model.md) → [Behavioral Policy Enforcement](pillars/02-behavioral-policy-enforcement.md) → [Self-Healing & Containment](pillars/05-self-healing-containment.md) → [Identity & Purpose Binding](pillars/01-identity-purpose-binding.md) |
| **Compliance** | Map ACR to frameworks and audits | [NIST AI RMF Mapping](compliance/acr-nist-ai-rmf-mapping.md) → [Execution Observability](pillars/04-execution-observability.md) → [Human Authority](pillars/06-human-authority.md) → [SOC 2 / ISO placeholders](compliance/) |
| **Implementer** | Build or integrate ACR-aligned controls | [Implementation Guide](guides/acr-implementation-guide.md) → [Use Cases](guides/acr-use-cases.md) → [Telemetry Schema](specifications/telemetry-schema.md) → [Pillars](pillars/README.md) |
| **Evaluator** | Assess adoption or vendor alignment | [Adoption & Maturity](../ADOPTION.md) → [Pillars Overview](pillars/README.md) → [STRIKE Summary](security/acr-strike-threat-model.md#strike-summary-matrix) |

## Quick Links

| Section | Description |
|--------|--------------|
| [Pillars](pillars/README.md) | Overview of the six control layers |
| [Architecture](architecture/) | Control plane, runtime, and production lifecycle |
| [Specifications](specifications/) | Telemetry schema and future specs |
| [Compliance](compliance/) | NIST AI RMF and other mappings |
| [Security](security/) | STRIKE threat model and glossary |
| [Guides](guides/) | Implementation guide, use cases, FAQ |

## Pillar Specifications

1. [Identity & Purpose Binding](pillars/01-identity-purpose-binding.md)
2. [Behavioral Policy Enforcement](pillars/02-behavioral-policy-enforcement.md)
3. [Autonomy Drift Detection](pillars/03-autonomy-drift-detection.md)
4. [Execution Observability](pillars/04-execution-observability.md)
5. [Self-Healing & Containment](pillars/05-self-healing-containment.md)
6. [Human Authority](pillars/06-human-authority.md)

## Key Documents

- [Decision walkthrough](decisions-explained.md) — Plain-language explanation of the guarded-tool decision pipeline
- [Telemetry Schema](specifications/telemetry-schema.md) — JSON schema for observability events
- [Implementation Guide](guides/acr-implementation-guide.md) — Deployment patterns and reference architectures
- [STRIKE Threat Model](security/acr-strike-threat-model.md) — AI-specific runtime threats
- [NIST AI RMF Mapping](compliance/acr-nist-ai-rmf-mapping.md) — Compliance alignment
- [FAQ](guides/FAQ.md) — Frequently asked questions
- [Adoption & maturity levels](../ADOPTION.md) — How to adopt and claim alignment

---

[← Back to ACR Standard](../README.md)
