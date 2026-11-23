# Fetch the official OPA static binary for the TARGET architecture.
# This stage previously copied /opa out of the openpolicyagent/opa
# image, which bakes in that image's architecture: on an arm64 build
# (e.g. Apple Silicon) the image shipped an x86-64 binary that cannot
# execute in the arm64 runtime image, so the policy export died before
# the stack could start. The per-arch static binary keeps amd64 builds
# identical and makes arm64 builds work. The runtime version check in
# acr.policy_studio.compiler (requires "Version: 0.70.0") remains the
# guard against a wrong binary.
FROM python:3.12-slim AS policy-compiler
ARG TARGETARCH
ARG OPA_VERSION=0.70.0
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL -o /opa "https://openpolicyagent.org/downloads/v${OPA_VERSION}/opa_linux_${TARGETARCH:-amd64}_static" \
    && chmod +x /opa \
    && /opa version

# Stage 1: build
FROM python:3.12-slim AS builder
# Version for hatch-vcs (no .git in build context). Set via --build-arg
# from CI; defaults to 0.0.0+unknown for local builds.
ARG SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0+unknown
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN pip install --no-cache-dir build wheel \
    && pip wheel --no-cache-dir --wheel-dir /wheels .

# Stage 2: runtime
FROM python:3.12-slim AS runtime
WORKDIR /app
LABEL org.opencontainers.image.licenses="Apache-2.0"
COPY LICENSE /app/LICENSE
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=policy-compiler /opa /usr/local/bin/opa
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels acr-control-plane \
    && rm -rf /wheels
COPY src/ ./src/
COPY alembic.ini ./
# Migration entrypoint shared by the K8s init container, the docker-compose
# `acr-migrate` one-shot service, and CI. Installed on PATH so it can be
# invoked simply as `run-migrations` from any container using this image.
COPY scripts/run-migrations.sh /usr/local/bin/run-migrations
RUN chmod +x /usr/local/bin/run-migrations

ENV OPA_BINARY=/usr/local/bin/opa
ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
ENV WEB_CONCURRENCY=2

EXPOSE 8000

RUN useradd -r -u 1000 acr
USER acr

CMD ["uvicorn", "acr.main:app", "--host", "0.0.0.0", "--port", "8000"]
