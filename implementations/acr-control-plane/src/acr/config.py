from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = "postgresql+asyncpg://acr:acr_dev_password@localhost:5432/acr_control_plane"

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── OPA ───────────────────────────────────────────────────────────────────
    opa_url: str = "http://localhost:8181"
    policy_extension_dir: str = ""

    # ── Kill switch ───────────────────────────────────────────────────────────
    killswitch_url: str = "http://localhost:8443"
    killswitch_secret: str = "killswitch_dev_secret_change_me"

    # ── JWT ───────────────────────────────────────────────────────────────────
    jwt_secret_key: str = "dev_jwt_secret_change_in_production"
    jwt_algorithm: str = "HS256"
    jwt_token_expire_minutes: int = 30

    # ── Runtime ───────────────────────────────────────────────────────────────
    acr_env: str = "development"
    log_level: str = "INFO"
    acr_version: str = "1.1.0"
    schema_bootstrap_mode: str = "auto"
    strict_dependency_startup: bool = False

    # ── Agent registry health sweep ──────────────────────────────────────────
    # Agents that have heartbeated at least once but haven't sent another in
    # this many seconds are downgraded to health_status='unhealthy'. Set to 0
    # to disable the sweep entirely.
    agent_heartbeat_stale_seconds: int = 300
    agent_heartbeat_sweep_interval_seconds: int = 60

    # ── Approval webhook ──────────────────────────────────────────────────────
    webhook_url: str = ""
    # HMAC-SHA256 key for signing outbound webhook payloads.
    # Receivers verify the X-ACR-Signature header to confirm authenticity.
    webhook_hmac_secret: str = ""
    audit_signing_secret: str = "dev_audit_signing_secret_change_me"

    # ── OpenTelemetry ─────────────────────────────────────────────────────────
    otel_exporter_otlp_endpoint: str = ""
    otel_service_name: str = "acr-control-plane"

    # ── Operator auth / RBAC ─────────────────────────────────────────────────
    # JSON object: {"api-key":{"subject":"alice","roles":["agent_admin","approver"]}}
    operator_api_keys_json: str = ""
    service_operator_api_key: str = ""
    operator_session_secret: str = "dev_operator_session_secret_change_me"
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_authorize_url: str = ""
    oidc_token_url: str = ""
    oidc_jwks_url: str = ""
    oidc_redirect_uri: str = ""
    oidc_scopes: str = "openid profile email"
    oidc_roles_claim: str = "roles"
    oidc_subject_claim: str = "email"
    oidc_role_mapping_json: str = ""
    oidc_session_ttl_seconds: int = 28800

    # ── Downstream execution ─────────────────────────────────────────────────
    execute_allowed_actions: bool = False
    # JSON object: {"tool_name":"https://executor.internal/run"}
    tool_executor_map_json: str = ""
    executor_integrations_json: str = ""
    executor_hmac_secret: str = ""
    executor_auth_ttl_seconds: int = 60
    executor_credential_secret: str = ""
    executor_credential_ttl_seconds: int = 300
    executor_timeout_seconds: float = 8.0

    # ── Policy bundle publishing ─────────────────────────────────────────────
    # When True, bundle download and OPA discovery endpoints require operator
    # authentication.  OPA's native bundle mechanism does not send auth headers
    # by default, so deployments that let OPA poll these endpoints directly may
    # need to set this to False and rely on network-level controls instead.
    require_bundle_auth: bool = True
    policy_bundle_backend: str = "local"
    policy_bundle_local_dir: str = "./var/policy_bundles"
    policy_bundle_public_base_url: str = ""
    policy_bundle_s3_bucket: str = ""
    policy_bundle_s3_prefix: str = "acr/policy-bundles"
    policy_bundle_s3_region: str = ""
    policy_bundle_s3_endpoint_url: str = ""


settings = Settings()


# ── Startup safety assertions ─────────────────────────────────────────────────

_WEAK_KEYS = {
    "dev_jwt_secret_change_in_production",
    "killswitch_dev_secret_change_me",
    "secret",
    "changeme",
    "password",
    "jwt_secret",
    "dev_audit_signing_secret_change_me",
}

_MIN_KEY_BYTES = 32  # 256 bits — minimum for HS256

# Algorithms outside this set have known weaknesses or enable confusion attacks.
# "none" is the classic JWT attack vector; RS256/ES256 require key-pair setup.
ALLOWED_JWT_ALGORITHMS = {"HS256", "RS256", "ES256"}

ALLOWED_SCHEMA_BOOTSTRAP_MODES = {"auto", "create", "validate", "off"}


def assert_production_secrets() -> None:
    """
    Reject clearly unsafe settings when running outside development/test.
    Call exactly once inside the FastAPI lifespan startup block.
    """
    if settings.acr_env in ("development", "test"):
        return

    # Algorithm allowlist — fail loudly on anything we don't explicitly support
    if settings.jwt_algorithm not in ALLOWED_JWT_ALGORITHMS:
        raise RuntimeError(
            f"JWT_ALGORITHM '{settings.jwt_algorithm}' is not in the allowed set "
            f"{ALLOWED_JWT_ALGORITHMS}. Update JWT_ALGORITHM in your environment."
        )

    jwt_key = settings.jwt_secret_key
    if jwt_key in _WEAK_KEYS or len(jwt_key.encode()) < _MIN_KEY_BYTES:
        raise RuntimeError(
            f"JWT_SECRET_KEY is too weak for environment '{settings.acr_env}'. "
            f"Supply a randomly-generated value of at least {_MIN_KEY_BYTES} bytes."
        )

    if settings.killswitch_secret in _WEAK_KEYS:
        raise RuntimeError(
            f"KILLSWITCH_SECRET is using a default/weak value in environment "
            f"'{settings.acr_env}'. Set a strong random secret before deploying."
        )

    if (
        settings.audit_signing_secret in _WEAK_KEYS
        or len(settings.audit_signing_secret.encode()) < _MIN_KEY_BYTES
    ):
        raise RuntimeError(
            "AUDIT_SIGNING_SECRET must be set to a strong value before deploying "
            "outside development/test."
        )

    if (
        settings.execute_allowed_actions
        and len(settings.executor_hmac_secret.encode()) < _MIN_KEY_BYTES
    ):
        raise RuntimeError(
            "EXECUTOR_HMAC_SECRET must be set to a strong value before enabling "
            "EXECUTE_ALLOWED_ACTIONS outside development/test."
        )

    if (
        settings.executor_credential_secret
        and len(settings.executor_credential_secret.encode()) < _MIN_KEY_BYTES
    ):
        raise RuntimeError(
            "EXECUTOR_CREDENTIAL_SECRET must be set to a strong value when brokered "
            "downstream credentials are enabled."
        )

    if not settings.operator_api_keys_json:
        raise RuntimeError("OPERATOR_API_KEYS_JSON must be set in non-development environments.")

    if not settings.service_operator_api_key:
        raise RuntimeError(
            "SERVICE_OPERATOR_API_KEY must be set in non-development environments "
            "so the gateway can authenticate to the independent kill-switch service."
        )

    if settings.oidc_enabled:
        if (
            settings.operator_session_secret in _WEAK_KEYS
            or len(settings.operator_session_secret.encode()) < _MIN_KEY_BYTES
        ):
            raise RuntimeError(
                "OPERATOR_SESSION_SECRET is too weak for OIDC-enabled environments. "
                f"Supply a randomly-generated value of at least {_MIN_KEY_BYTES} bytes."
            )
        required = {
            "OIDC_ISSUER": settings.oidc_issuer,
            "OIDC_CLIENT_ID": settings.oidc_client_id,
            "OIDC_AUTHORIZE_URL": settings.oidc_authorize_url,
            "OIDC_TOKEN_URL": settings.oidc_token_url,
            "OIDC_JWKS_URL": settings.oidc_jwks_url,
            "OIDC_REDIRECT_URI": settings.oidc_redirect_uri,
        }
        missing = sorted(name for name, value in required.items() if not value)
        if missing:
            raise RuntimeError(
                "OIDC is enabled but required settings are missing: " + ", ".join(missing)
            )


def effective_schema_bootstrap_mode() -> str:
    mode = settings.schema_bootstrap_mode
    if mode not in ALLOWED_SCHEMA_BOOTSTRAP_MODES:
        raise RuntimeError(
            f"SCHEMA_BOOTSTRAP_MODE '{mode}' is invalid. "
            f"Allowed values: {sorted(ALLOWED_SCHEMA_BOOTSTRAP_MODES)}"
        )
    if mode != "auto":
        return mode
    return "create" if settings.acr_env in ("development", "test") else "validate"


def runtime_dependencies_fail_closed() -> bool:
    """Enterprise posture: fail closed outside development/test."""
    return settings.strict_dependency_startup or settings.acr_env not in ("development", "test")


@lru_cache(maxsize=1)
def operator_api_keys() -> dict[str, dict]:
    if not settings.operator_api_keys_json:
        return {}
    try:
        raw = json.loads(settings.operator_api_keys_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError("OPERATOR_API_KEYS_JSON is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise RuntimeError("OPERATOR_API_KEYS_JSON must decode to an object")
    return raw


@lru_cache(maxsize=1)
def oidc_role_mapping() -> dict[str, list[str]]:
    if not settings.oidc_role_mapping_json:
        return {}
    try:
        raw = json.loads(settings.oidc_role_mapping_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError("OIDC_ROLE_MAPPING_JSON is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise RuntimeError("OIDC_ROLE_MAPPING_JSON must decode to an object")
    normalized: dict[str, list[str]] = {}
    for external_role, internal_roles in raw.items():
        if isinstance(internal_roles, str):
            normalized[str(external_role)] = [internal_roles]
            continue
        if not isinstance(internal_roles, list):
            raise RuntimeError("OIDC_ROLE_MAPPING_JSON values must be strings or arrays")
        normalized[str(external_role)] = [str(role) for role in internal_roles]
    return normalized


@lru_cache(maxsize=1)
def tool_executor_map() -> dict[str, str]:
    if not settings.tool_executor_map_json:
        return {}
    try:
        raw = json.loads(settings.tool_executor_map_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError("TOOL_EXECUTOR_MAP_JSON is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise RuntimeError("TOOL_EXECUTOR_MAP_JSON must decode to an object")
    return {str(tool): str(url) for tool, url in raw.items()}


@lru_cache(maxsize=1)
def executor_integrations() -> dict[str, dict]:
    raw_json = getattr(settings, "executor_integrations_json", "")
    if not raw_json:
        return {}
    try:
        raw = json.loads(raw_json)
    except json.JSONDecodeError as exc:
        raise RuntimeError("EXECUTOR_INTEGRATIONS_JSON is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise RuntimeError("EXECUTOR_INTEGRATIONS_JSON must decode to an object")
    return {str(tool): value for tool, value in raw.items() if isinstance(value, dict)}


def policy_bundle_local_path() -> Path:
    return Path(settings.policy_bundle_local_dir).expanduser()
