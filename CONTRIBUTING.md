# Contributing to ACR Standard

Thank you for your interest in contributing to the ACR (Agentic Control at Runtime) Standard. ACR is an open reference architecture for runtime governance of autonomous AI systems. Contributions to the Python control plane, tests, OPA policies, SDK examples, specifications, and documentation are welcome.

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

## How to Contribute

### Contribution Areas

- **Control-plane code and tests** — Fix reproducible bugs, add regression tests, and improve SDK examples in `implementations/acr-control-plane/`
- **Control layer refinements and extensions** — Improve pillar specifications, add implementation patterns, or propose new control objectives
- **Implementation pattern documentation** — Document deployment patterns, technology integrations, or migration approaches
- **Threat model expansion** — New attack vectors, mitigations, detection strategies, or STRIKE category refinements
- **Standards mappings** — EU AI Act, sector-specific regulations, or deeper NIST/ISO/SOC 2 mappings
- **Case studies and deployment experiences** — Real-world adoption stories (anonymized or with permission)
- **Research and open questions** — Drift detection methods, policy languages, observability schemas

### Contribution Process

1. **Review existing issues**
   Check [GitHub Issues](https://github.com/AdamDiStefanoAI/acr-standard/issues) to see if your idea is already being discussed. Use Issues for questions and design proposals too.

2. **Open an issue**
   Describe your proposed contribution, the problem it addresses, and how it aligns with ACR principles. For large changes, discuss the approach before submitting a pull request.

3. **Discuss approach and alignment**
   Maintainers and the community will review and may suggest adjustments to align with the framework’s scope and structure.

4. **Submit a pull request**
   - Branch from `main`
   - Put code and implementation docs under `implementations/acr-control-plane/`, and framework documentation under [docs/](docs/)
   - Follow the existing markdown style and structure
   - Keep changes focused; prefer multiple small PRs over one large one

5. **Community review and merge**
   Maintainers will review your PR. Address feedback and ensure any link or path updates are consistent with the [docs/](docs/) layout.

### Code Contributions

The runnable reference implementation lives in [implementations/acr-control-plane/](implementations/acr-control-plane/). Start with a small, reproducible change. For a first contribution, a regression test, a clearer error message, a policy test, or a corrected SDK example is useful. Check open issues before starting and discuss larger changes in an issue.

#### Repository map

All paths below are relative to `implementations/acr-control-plane/`:

- `src/acr/`: Python gateway, SDK, and six control pillars
- `tests/`: unit tests; `tests/integration/`: opt-in tests against disposable Postgres, Redis, and OPA
- `policies/`: OPA/Rego policies and tests
- `examples/`: sample agent, protected executor, and orchestrator examples
- `docs/`: implementation and API documentation
- `sdks/typescript/`: TypeScript SDK

GitHub Actions workflows live at the repository root in `.github/workflows/`.

#### Set up Python development

Use Python 3.11 or 3.12, which are the CI test versions, and a Git checkout (package versioning reads Git metadata). From the repository root, run:

```bash
cd implementations/acr-control-plane
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1`. Run the following commands from the implementation directory with this environment active. Unit tests use SQLite and mocks; they do not need a running Docker stack or production credentials.

```bash
ACR_ENV=test python -m pytest tests/ --ignore=tests/integration -v
python -m ruff format --check src/ tests/
python -m ruff check src/ tests/
python scripts/check_no_dev_secrets.py
```

In PowerShell, set `$env:ACR_ENV = "test"` before running pytest instead of using the inline environment assignment. To reproduce the CI coverage gate:

```bash
ACR_ENV=test python -m pytest tests/ --ignore=tests/integration \
  --cov=src/acr --cov-report=term-missing --cov-report=xml --cov-fail-under=80
```

Run the relevant focused tests while developing, then the full unit suite. Include the commands and results in your PR. If an existing check fails on unchanged `main`, report that separately rather than weakening the check or bundling unrelated fixes.

#### Policy and integration checks

Policy export/administration and tests require OPA **0.70.0** (the version used
by the local stack and CI). Install it from the official OPA release, place `opa`
on `PATH` or set `OPA_BINARY` to its executable path, then run:

```bash
opa check policies/
opa test policies/ -v
```

Integration tests require Docker Compose v2 and a **disposable** local stack. The fixtures create/drop database tables and flush the selected Redis database. Never point them at a shared or production system. From the implementation directory, use a separate Compose project and unused local ports:

```bash
export COMPOSE_FILE=docker-compose.yml:docker-compose.integration.yml
export OPERATOR_API_KEYS_JSON='{"ci-operator-only":{"subject":"ci-operator","roles":["auditor"]}}'
export SERVICE_OPERATOR_API_KEY=ci-operator-only
docker compose -p acr-contributor-test up --build -d postgres redis opa
# Wait for Postgres, Redis, and http://localhost:8181/health?bundles to be ready.
ACR_ENV=test \
DATABASE_URL=postgresql+asyncpg://acr:acr_dev_password@localhost:5432/acr_control_plane \
REDIS_URL=redis://localhost:6379/1 \
OPA_URL=http://localhost:8181 \
POLICY_EXTENSION_DIR=operator-policies \
RUN_INTEGRATION_TESTS=true \
TEST_DATABASE_URL=postgresql+asyncpg://acr:acr_dev_password@localhost:5432/acr_control_plane \
TEST_REDIS_URL=redis://localhost:6379/1 \
TEST_OPA_URL=http://localhost:8181 \
python -m pytest tests/integration/ -v --tb=short
# Removes only this disposable Compose project's containers and volumes.
docker compose -p acr-contributor-test down -v
```

These commands assume the repository's default local credentials and no conflicting environment overrides. Stop other local services on ports 5432, 6379, and 8181 first; do not reuse an existing development database. Always run the cleanup command when finished, including after a failed test.

For a full interactive demo, follow the [sample agent setup](implementations/acr-control-plane/examples/sample_agent/README.md). Keep local demo credentials out of real deployments. See [SECURITY.md](SECURITY.md) before sharing a vulnerability; do not post unfixed security details in public issues.

### Documentation Structure

- **Pillar specifications:** [docs/pillars/](docs/pillars/)
- **Architecture:** [docs/architecture/](docs/architecture/)
- **Specifications:** [docs/specifications/](docs/specifications/)
- **Compliance:** [docs/compliance/](docs/compliance/)
- **Security:** [docs/security/](docs/security/)
- **Guides:** [docs/guides/](docs/guides/)

When adding or moving documents, update internal links so they work from the new paths (e.g. from `docs/pillars/` use `../architecture/` for architecture docs and `../../README.md` for the repo root).

### Pull Request Guidelines

- Use clear, descriptive titles and descriptions
- For code changes, add or update regression tests and record checks run, failures, and anything not tested
- Reference any related issues
- Ensure all internal links are valid (see [ROADMAP](ROADMAP.md) for tooling plans)
- For specification changes, consider impact on existing implementations and the [Implementation Guide](docs/guides/acr-implementation-guide.md)

### Questions

- **Architecture, design, bugs, and clarifications:** [GitHub Issues](https://github.com/AdamDiStefanoAI/acr-standard/issues)

Thank you for helping advance runtime governance for autonomous AI systems.
