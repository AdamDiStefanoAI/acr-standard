# ACR Standard — Adoption and Implementation

This document explains how to adopt the ACR Framework, how to claim alignment, how to be listed as an implementation, and how to cite and use ACR branding. The goal is to make ACR a recognizable, credible standard for runtime AI governance—similar in adoption and trust to OWASP, MITRE ATT&CK, and NIST frameworks.

---

## Who Should Adopt ACR?

- **Enterprises** running autonomous AI systems (agents, copilots, workflow automation) who need runtime governance
- **Vendors** building AI governance, observability, or policy enforcement products
- **Auditors and compliance teams** who need a technical control framework aligned to NIST AI RMF, ISO 42001, SOC 2
- **Researchers and standards bodies** working on AI safety, accountability, and operational control

---

## ACR Conformance Levels

> For current conformance requirements, use §23 of the [published v1.2.0 standard](https://runtimecontrol.io/downloads/ACR_Standard_v1.2.0.pdf). This guide is informative; a checklist is not a conformance assessment.
> Conformance is cumulative: each level builds on the previous one. A system claiming
> Level 3 must satisfy all requirements from all three levels. These summaries do not replace the normative PDF; see [source precedence and document versions](docs/README.md#normative-source-and-document-versions).

| Level | Name | Criteria |
|-------|------|----------|
| **Level 1** | Observability | Action and decision logging; correlation identifiers; agent identity and purpose records; policy decision records; audit export capability; minimum retention enforcement. |
| **Level 2** | Enforcement | Level 1 plus mandatory pre-execution control; deny-by-default behavior; identity and purpose binding; executor-side verification; containment with kill path. |
| **Level 3** | Full Runtime Control Plane Compliance | Levels 1–2 plus three-boundary enforcement; four-state decision model (ALLOW, DENY, MODIFY, ESCALATE); drift detection with thresholded response; STRIKE traceability matrix; quarterly containment testing. |

**Claiming a level:** A claim MUST identify the evaluated system boundary, protected execution scope, covered agents and action classes, conformance level, and the date and version of the evaluated implementation. The claimant MUST retain the complete supporting evidence package. The criteria above are a summary; assess the applicable normative requirements and verification criteria, not this table alone.

**Level 1 limitation:** Level 1 does not require mandatory pre-execution blocking for all protected actions, but the claim MUST identify every execution path outside enforcement scope. An observability-only Level 1 claim does not establish controlled execution or Level 3 full runtime control-plane compliance.

Implementation details can vary (see [Implementation Guide](docs/guides/acr-implementation-guide.md)), but implementation choices cannot waive the applicable normative requirements.

---

## What "ACR-Aligned" Means

- **Aligned:** Your design and controls map to ACR pillars and intent; you implement a subset or full set of the control layers and follow the architectural patterns (control plane, telemetry, policy enforcement, etc.).
- **Not a certification:** ACR does not currently offer formal certification. Alignment is self-assessed. We recommend documenting your mapping (e.g. which pillars, which STRIKE threats you address).
- **Not a trademark claim:** "ACR" and "ACR Framework" refer to this open framework. You may describe your product or system as "ACR-aligned" or "implementing ACR patterns" in a truthful, non-misleading way.

---

## Listing Your Implementation

The [reference implementation directory](implementations/) currently contains this project's own demonstration implementation, not an independently verified adoption registry. To propose an external implementation listing:

1. **Open a pull request** proposing a clearly labeled external-implementation entry and stating whether it is open source, commercial, or research.
2. **Include:**
   - Name and short description
   - Which ACR pillars you implement (and conformance level if applicable)
   - Deployment pattern(s): e.g. API Gateway, SDK, Sidecar, Control Plane Service
   - Link to documentation or product page
3. **Acceptance:** Maintainers will review for relevance and accuracy. Listing does not imply endorsement of your product—only that you have stated alignment with ACR.

**Template for listing:**

```markdown
- **[Your Name](https://...)** — Short description. Pillars: 1, 2, 4 (Level 1). Pattern: API Gateway. [Docs](https://...)
```

---

## Badge and Logo Usage

### Badge (Markdown)

You may use this badge in READMEs or docs to indicate ACR alignment:

```markdown
[![ACR Aligned](https://img.shields.io/badge/ACR-Aligned-blue)](https://github.com/AdamDiStefanoAI/acr-standard)
```

Optional: specify level (e.g. "ACR Level 2 Aligned") in your own text; the badge links to the framework repo.

### Logo

If we release an official logo (e.g. in `docs/images/` or a branding repo), you may use it to link to the ACR Framework or to indicate alignment, provided you do not imply endorsement or certification. Do not modify the logo in a way that suggests official partnership unless agreed.

### Guidelines

- Use the badge/logo in a way that is accurate (you have actually implemented ACR-aligned controls).
- Do not use ACR branding in a way that suggests formal certification or that the ACR project endorses your product.
- When in doubt, use "ACR-aligned" in text and link to this repository.

---

## Citation

Identify what you are citing: the repository/framework, the normative PDF, or an evaluated software implementation. These have separate version identities. The examples below cite the framework repository; `1.0` is its legacy framework label, not the normative PDF or a software conformance claim. For reproducible software references, include the exact evaluated commit and assessment date.

For the normative document, cite: **ACR Runtime Control Plane Standard, Version 1.2.0, 2026-11-07, runtimecontrol.io**, with the specific PDF artifact used for assessment. Do not infer a normative PDF revision from a similarly named software tag.

For papers and reports citing the framework repository:

**BibTeX:**

```bibtex
@misc{acr-standard-2026,
  author       = {DiStefano, Adam},
  title        = {ACR Standard: Agentic Control at Runtime},
  year         = {2026},
  publisher    = {GitHub},
  journal      = {GitHub repository},
  howpublished = {\url{https://github.com/AdamDiStefanoAI/acr-standard}},
  version      = {1.0}
}
```

**Plain text:**  
ACR Standard: Agentic Control at Runtime. DiStefano, A. (2026). https://github.com/AdamDiStefanoAI/acr-standard. Version 1.0.

**STRIKE threat model:** When referencing the threat model specifically, cite "STRIKE Threat Model (ACR Standard)" and link to [docs/security/acr-strike-threat-model.md](docs/security/acr-strike-threat-model.md).

---

## Case Studies and Community

- **Case studies:** We welcome adoption stories (anonymized or with permission). Open an issue or discussion with the tag `case-study` or submit a PR that adds a short narrative under `docs/guides/` or a dedicated case-studies section.
- **Speaking and events:** If you present on ACR at conferences or meetups, we encourage you to share links or slides via Discussions or a PR to a "Presentations" or "Community" section if we add one.
- **Working groups:** Roadmap includes working groups on drift detection, policy languages, and observability standards. See [ROADMAP.md](ROADMAP.md) and [GOVERNANCE.md](GOVERNANCE.md).

---

## References

- [ACR Standard README](README.md)
- [Implementation Guide](docs/guides/acr-implementation-guide.md)
- [STRIKE Threat Model](docs/security/acr-strike-threat-model.md)
- [NIST AI RMF Mapping](docs/compliance/acr-nist-ai-rmf-mapping.md)
- [Governance](GOVERNANCE.md)
