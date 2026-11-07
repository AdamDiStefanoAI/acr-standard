# Stage 1: build
FROM python:3.12-slim AS builder
# Version for hatch-vcs (no .git in build context). Set via --build-arg
# from CI; defaults to 0.0.0+unknown for local builds.
ARG SETUPTOOLS_SCM_PRETEND_VERSION=0.0.0+unknown
WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends gcc libpq-dev \
    && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml README.md ./
COPY src/ ./src/
RUN pip install --no-cache-dir build wheel \
    && pip wheel --no-cache-dir --wheel-dir /wheels .

# Stage 2: runtime
FROM python:3.12-slim AS runtime
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 curl \
    && rm -rf /var/lib/apt/lists/*
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

ENV PYTHONPATH=/app/src
ENV PYTHONUNBUFFERED=1
ENV WEB_CONCURRENCY=2

EXPOSE 8000

RUN useradd -r -u 1000 acr
USER acr

CMD ["uvicorn", "acr.main:app", "--host", "0.0.0.0", "--port", "8000"]
