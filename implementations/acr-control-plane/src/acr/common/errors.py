from __future__ import annotations


class ACRError(Exception):
    """Base exception for all ACR control plane errors."""

    status_code: int = 500
    error_code: str = "ACR_ERROR"

    def __init__(self, message: str, *, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


# ── Identity / Auth ───────────────────────────────────────────────────────────


class AgentNotFoundError(ACRError):
    status_code = 404
    error_code = "AGENT_NOT_FOUND"


class AgentNotRegisteredError(ACRError):
    status_code = 403
    error_code = "AGENT_NOT_REGISTERED"


class AgentAlreadyExistsError(ACRError):
    status_code = 409
    error_code = "AGENT_ALREADY_EXISTS"


class InvalidTokenError(ACRError):
    status_code = 401
    error_code = "INVALID_TOKEN"


class UnauthorizedOperatorError(ACRError):
    status_code = 401
    error_code = "UNAUTHORIZED_OPERATOR"


class ForbiddenOperatorError(ACRError):
    status_code = 403
    error_code = "FORBIDDEN_OPERATOR"


class OperatorCredentialNotFoundError(ACRError):
    status_code = 404
    error_code = "OPERATOR_CREDENTIAL_NOT_FOUND"


class TokenExpiredError(ACRError):
    status_code = 401
    error_code = "TOKEN_EXPIRED"


class AgentKilledError(ACRError):
    status_code = 403
    error_code = "AGENT_KILLED"


class AgentLifecycleError(ACRError):
    """Raised when an agent's lifecycle state forbids the requested operation.

    Examples:
      * trying to evaluate against a draft or retired agent
      * trying to transition into an illegal state (e.g. retired → active)
    """

    status_code = 403
    error_code = "AGENT_LIFECYCLE_INVALID"


# ── Policy ────────────────────────────────────────────────────────────────────


class PolicyDeniedError(ACRError):
    status_code = 403
    error_code = "POLICY_DENIED"


class PolicyEngineError(ACRError):
    status_code = 503
    error_code = "POLICY_ENGINE_ERROR"


class RuntimeControlDependencyError(ACRError):
    status_code = 503
    error_code = "RUNTIME_CONTROL_DEPENDENCY_ERROR"


class AuthoritativeSpendControlError(ACRError):
    status_code = 503
    error_code = "AUTHORITATIVE_SPEND_CONTROL_ERROR"


# ── Approval ──────────────────────────────────────────────────────────────────


class ApprovalPendingError(ACRError):
    status_code = 202
    error_code = "APPROVAL_PENDING"


class ApprovalNotFoundError(ACRError):
    status_code = 404
    error_code = "APPROVAL_NOT_FOUND"


class ApprovalConflictError(ACRError):
    status_code = 409
    error_code = "APPROVAL_CONFLICT"


class ApprovalTimeoutError(ACRError):
    status_code = 403
    error_code = "APPROVAL_TIMEOUT"


# ── Containment ───────────────────────────────────────────────────────────────


class KillSwitchError(ACRError):
    status_code = 503
    error_code = "KILLSWITCH_ERROR"


class DownstreamExecutionError(ACRError):
    status_code = 503
    error_code = "DOWNSTREAM_EXECUTION_ERROR"


class InvalidExecutionAuthorizationError(ACRError):
    status_code = 401
    error_code = "INVALID_EXECUTION_AUTHORIZATION"


class PolicyDraftNotFoundError(ACRError):
    status_code = 404
    error_code = "POLICY_DRAFT_NOT_FOUND"


class PolicyReleaseNotFoundError(ACRError):
    status_code = 404
    error_code = "POLICY_RELEASE_NOT_FOUND"


class PolicyValidationError(ACRError):
    status_code = 422
    error_code = "POLICY_VALIDATION_ERROR"


class PolicySimulationNotFoundError(ACRError):
    status_code = 404
    error_code = "POLICY_SIMULATION_NOT_FOUND"


class EvidenceBundleNotFoundError(ACRError):
    status_code = 404
    error_code = "EVIDENCE_BUNDLE_NOT_FOUND"


class ContainmentError(ACRError):
    status_code = 503
    error_code = "CONTAINMENT_ERROR"


# ── Drift ─────────────────────────────────────────────────────────────────────


class BaselineNotFoundError(ACRError):
    status_code = 404
    error_code = "BASELINE_NOT_FOUND"
