"""SQLAlchemy ORM models for ACR control plane."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func

from acr.db.database import Base

# ── Agents ────────────────────────────────────────────────────────────────────


class AgentRecord(Base):
    __tablename__ = "agents"
    __table_args__ = (
        CheckConstraint(
            "lifecycle_state IN ('draft', 'active', 'deprecated', 'retired')",
            name="ck_agents_lifecycle_state",
        ),
        CheckConstraint(
            "health_status IN ('unknown', 'healthy', 'degraded', 'unhealthy')",
            name="ck_agents_health_status",
        ),
        CheckConstraint(
            "enforcement_mode IN ('enforce', 'observe')",
            name="ck_agents_enforcement_mode",
        ),
        Index("ix_agents_parent_agent_id", "parent_agent_id"),
        Index("ix_agents_lifecycle_state", "lifecycle_state"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    owner: Mapped[str] = mapped_column(String(256), nullable=False)
    purpose: Mapped[str] = mapped_column(String(512), nullable=False)
    risk_tier: Mapped[str] = mapped_column(String(16), nullable=False, default="medium")
    allowed_tools: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    forbidden_tools: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    data_access: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    boundaries: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    credential_hash: Mapped[str | None] = mapped_column(String(256), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # ── Registry expansion (migration 0012) ───────────────────────────────────
    # Agent's own semantic version. Used for lineage and audit trails.
    version: Mapped[str] = mapped_column(String(32), nullable=False, default="1.0.0")
    # Optional parent agent — for orchestrator → subagent relationships.
    # Plain string (not FK) so deletion of a parent does not cascade to its
    # subtree; lineage history is preserved even after a parent is retired.
    parent_agent_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # Declared capability tags (e.g. ["customer.read", "billing.refund"]).
    # Distinct from `allowed_tools`: capabilities describe *what the agent can do*
    # (skills/intents), tools describe *what the agent is permitted to call*.
    capabilities: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    # Lifecycle state: draft → active → deprecated → retired.
    # `is_active` is preserved for backwards compatibility and kept in sync:
    # is_active==False iff lifecycle_state=='retired'.
    lifecycle_state: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    # Health observability. Updated by heartbeat endpoint and the periodic
    # health sweep loop in main.py.
    health_status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    # Enforcement mode (v1.5.0 WS1, migration 0016): `enforce` applies policy
    # decisions to the call; `observe` records the would-be decision with the
    # same synchronous evidence semantics and lets the call proceed. Mode is
    # operator-controlled state: it lives only on this stored record, is read
    # by the gateway from here, and changes only via the dedicated
    # enforcement-mode transition endpoint — never from a request.
    enforcement_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="enforce")
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    policy_decisions: Mapped[list[PolicyDecisionRecord]] = relationship(
        back_populates="agent_ref", cascade="all, delete-orphan", passive_deletes=True
    )
    approval_requests: Mapped[list[ApprovalRequestRecord]] = relationship(
        back_populates="agent_ref", cascade="all, delete-orphan", passive_deletes=True
    )


# ── Policy decisions ─────────────────────────────────────────────────────────


class PolicyDecisionRecord(Base):
    __tablename__ = "policy_decisions"
    __table_args__ = (
        CheckConstraint(
            "decision IN ('allow', 'deny', 'modify', 'escalate')",
            name="ck_policy_decisions_decision",
        ),
        CheckConstraint(
            "enforcement_mode IN ('enforce', 'observe')",
            name="ck_policy_decisions_enforcement_mode",
        ),
        Index(
            "ix_policy_decisions_observe_report",
            "agent_id",
            "enforcement_mode",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=False, index=True
    )
    policy_id: Mapped[str] = mapped_column(String(128), nullable=False)
    decision: Mapped[str] = mapped_column(
        String(16), nullable=False
    )  # allow | deny | modify | escalate
    # The enforcement mode the decision was issued under (migration 0016).
    # For `observe` rows, `decision` is the would-be decision: what the
    # policy stack decided, recorded with full §18 semantics, while the
    # call itself proceeded. Reports must never mix the two modes.
    enforcement_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="enforce")
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    tool_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # §18 decision sequence: assigned when the decision is issued, before the
    # response is returned and before any approved action executes. All policy
    # decision rows from one evaluation share the evaluation's sequence, so a
    # verifier can order decisions by issuance rather than by persistence,
    # arrival, or completion time. Null only on rows written before this
    # column existed.
    sequence: Mapped[int | None] = mapped_column(BigInteger, nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    agent_ref: Mapped[AgentRecord] = relationship(back_populates="policy_decisions")


class DecisionSequenceRecord(Base):
    """Per-agent monotonic counter backing the §18 decision sequence.

    The counter is incremented inside the same transaction that durably
    records the policy decisions, so the sequence position of a decision is
    fixed at issuance and survives restarts. One row per agent.
    """

    __tablename__ = "decision_sequences"

    agent_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("agents.agent_id", ondelete="CASCADE"),
        primary_key=True,
    )
    last_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


# ── Telemetry events ──────────────────────────────────────────────────────────


class TelemetryEventRecord(Base):
    __tablename__ = "telemetry_events"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    event_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


# ── Approval requests ─────────────────────────────────────────────────────────


class ApprovalRequestRecord(Base):
    __tablename__ = "approval_requests"
    __table_args__ = (
        # The SLA expiry loop runs: WHERE status='pending' AND expires_at <= now()
        # This composite index makes that scan ~O(log n) instead of O(n).
        Index("ix_approval_status_expires", "status", "expires_at"),
        CheckConstraint(
            "status IN ('pending', 'approved', 'denied', 'overridden', 'timed_out')",
            name="ck_approval_requests_status",
        ),
        CheckConstraint(
            "decision IS NULL OR decision IN ('approved', 'denied', 'overridden')",
            name="ck_approval_requests_decision",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    request_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    parameters: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_tier: Mapped[str] = mapped_column(String(16), nullable=False, default="high")
    approval_queue: Mapped[str] = mapped_column(String(128), nullable=False, default="default")
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    decision: Mapped[str | None] = mapped_column(
        String(16), nullable=True
    )  # approved | denied | overridden
    decided_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # Chat-channel decisions (v1.5.0 WS4): when a decision arrives through
    # an integration (Slack/Teams), decided_by still carries the mapped
    # operator subject — the identity the approvals path authorized — and
    # these two columns preserve the transport identity alongside it:
    # decided_channel is "slack"/"teams", chat_actor_id is the chat user
    # id that was mapped to decided_by. Both stay NULL for API decisions.
    decided_channel: Mapped[str | None] = mapped_column(String(32), nullable=True)
    chat_actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    decision_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    sla_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=240)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    authorization_snapshot: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    request_payload_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    request_context: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    agent_ref: Mapped[AgentRecord] = relationship(back_populates="approval_requests")


class ExecutionReceiptRecord(Base):
    """Durable dispatch fence and outcome evidence, retained independently of agents.

    One approval can cause at most one gateway dispatch attempt. An unfinished
    receipt is NOT evidence that the downstream action did not execute.
    """

    __tablename__ = "execution_receipts"
    __table_args__ = (
        CheckConstraint(
            "state IN ('executing', 'succeeded', 'unknown', 'blocked')",
            name="ck_execution_receipts_state",
        ),
    )

    attempt_id: Mapped[str] = mapped_column(
        String(64), primary_key=True, default=lambda: f"exe-{uuid.uuid4()}"
    )
    # No cascading foreign key: deleting an identity must not erase evidence.
    approval_request_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    authorization_snapshot: Mapped[dict] = mapped_column(JSON, nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="executing")
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ── Drift baselines ───────────────────────────────────────────────────────────


class DriftBaselineRecord(Base):
    __tablename__ = "drift_baselines"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    baseline_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    collection_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# ── Drift baseline versions (governed snapshots) ─────────────────────────────


class DriftBaselineVersionRecord(Base):
    __tablename__ = "drift_baseline_versions"
    __table_args__ = (
        CheckConstraint(
            "status IN ('candidate', 'approved', 'active', 'rejected', 'superseded')",
            name="ck_drift_baseline_versions_status",
        ),
        Index("ix_drift_baseline_versions_agent_status", "agent_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    baseline_version_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    baseline_data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="candidate", index=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    activated_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


# ── Drift metrics (raw samples) ───────────────────────────────────────────────


class DriftMetricRecord(Base):
    __tablename__ = "drift_metrics"
    __table_args__ = (
        # Composite index: the drift detector's main query filters by agent_id
        # and orders/filters by created_at (recency window). Without this, every
        # drift computation does a full-table scan.
        Index("ix_drift_metrics_agent_created", "agent_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    action_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    policy_denied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


# ── Containment actions ───────────────────────────────────────────────────────


class ContainmentActionRecord(Base):
    __tablename__ = "containment_actions"
    __table_args__ = (
        CheckConstraint(
            "action_type IN ('kill', 'restore', 'throttle', 'restrict', 'isolate')",
            name="ck_containment_actions_action_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    action_type: Mapped[str] = mapped_column(
        String(32), nullable=False
    )  # kill | restore | throttle | restrict | isolate
    tier: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    drift_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    operator_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


# ── Operator credentials ─────────────────────────────────────────────────────


class OperatorCredentialRecord(Base):
    __tablename__ = "operator_credentials"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    key_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    subject: Mapped[str] = mapped_column(String(256), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    roles: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True, index=True)
    created_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Mandatory expiry for time-boxed auditor grants (v1.5.0 WS3, migration
    # 0019). NULL for standing operator credentials; an auditor grant is
    # only ever issued with this set, and authentication rejects it at or
    # after the expiry instant.
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# ── Retained evaluation inputs (v1.5.0 WS2, migration 0017) ─────────────────


class EvaluationInputRecord(Base):
    """One evaluation's retained input, kept for policy simulation replay.

    Written only when the deployment opts in
    (settings.evaluation_input_retention_enabled, default off), inside the
    same transaction that records the evaluation's policy decisions, so a
    retained input can never exist for an unrecorded decision and a storage
    failure fails the recording exactly like a decision-write failure.
    The payload is the effective evaluation input (agent manifest, action,
    enriched context) AFTER configured redaction has been applied — the
    unredacted payload never touches storage. Purge deletes the payload
    (sets it NULL) and flips state to 'purged'; the row remains as the
    durable note that this decision's input was retained and later purged,
    which is what lets simulation reports account coverage honestly.
    """

    __tablename__ = "evaluation_inputs"
    __table_args__ = (
        CheckConstraint(
            "state IN ('retained', 'purged')",
            name="ck_evaluation_inputs_state",
        ),
        Index("ix_evaluation_inputs_agent_retained", "agent_id", "retained_at"),
        Index("ix_evaluation_inputs_expires", "state", "expires_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    correlation_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(
        String(128), ForeignKey("agents.agent_id", ondelete="CASCADE"), nullable=False, index=True
    )
    # The redacted effective evaluation input. NULL once purged.
    payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    # SHA-256 of the stored (redacted) payload's canonical JSON. Kept after
    # purge so a simulation result can still reference what it replayed.
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # The final decision the gateway issued for this evaluation, denormalized
    # so coverage accounting does not need to reconstruct it from the
    # per-rule decision rows.
    recorded_decision: Mapped[str] = mapped_column(String(16), nullable=False)
    enforcement_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="enforce")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="retained")
    retained_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    purged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# ── Policy simulation runs (v1.5.0 WS2, migration 0018) ──────────────────────


class PolicySimulationRecord(Base):
    """A durable record of one policy simulation run.

    A simulation is itself evidence: who ran it, against which exact bundle
    (sha256 of the archive that was evaluated), over which window, and what
    it found. The full report is stored as JSON; result_hash binds the
    report's substantive content so a stored report can be checked for
    tampering the same way other ACR artifacts are.
    """

    __tablename__ = "policy_simulations"
    __table_args__ = (Index("ix_policy_simulations_bundle", "bundle_sha256"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    run_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(256), nullable=False)
    # Human-meaningful bundle identifier: a policy release id, or a file
    # name for an ad-hoc archive. The hash below is the identity that
    # matters; this is for readers.
    bundle_label: Mapped[str | None] = mapped_column(String(256), nullable=True)
    bundle_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    decisions_in_window: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    inputs_available: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    inputs_missing: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    report: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    result_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


# ── Policy drafts ────────────────────────────────────────────────────────────


class PolicyDraftRecord(Base):
    __tablename__ = "policy_drafts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    draft_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    template: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    rego_policy: Mapped[str] = mapped_column(Text, nullable=False)
    wizard_inputs: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


# ── Policy releases ──────────────────────────────────────────────────────────


class PolicyReleaseRecord(Base):
    __tablename__ = "policy_releases"
    __table_args__ = (
        CheckConstraint(
            "status IN ('published', 'superseded', 'rolled_back')",
            name="ck_policy_releases_status",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    release_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    draft_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    agent_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    template: Mapped[str] = mapped_column(String(64), nullable=False)
    manifest: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    rego_policy: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="published", index=True)
    artifact_uri: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    artifact_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    publish_backend: Mapped[str | None] = mapped_column(String(32), nullable=True)
    activation_status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="inactive", index=True
    )
    active_bundle_uri: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    activated_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    published_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # Simulation report (policy_simulations.run_id) attached when this
    # release was activated under the WS2 promotion gate; NULL for releases
    # activated with the gate inert or before the gate existed.
    simulation_report_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rollback_from_release_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )


# ── Integration outbox (v1.5.0 WS4) ───────────────────────────────────────────


class IntegrationOutboxRecord(Base):
    """Durable outbound-integration queue: one row per event per integration.

    Rows are written by the approval/containment/decision paths (in a
    savepoint, so an enqueue failure can never break the path that produced
    the event) and drained asynchronously by the outbox worker loop. The
    evaluate hot path never delivers from here; it only ever enqueues.
    Payloads never contain secrets — credentials live in deployment config.
    """

    __tablename__ = "integration_outbox"
    __table_args__ = (
        CheckConstraint(
            "integration IN ('slack', 'teams', 'servicenow', 'sentinel')",
            name="ck_integration_outbox_integration",
        ),
        CheckConstraint(
            "status IN ('pending', 'delivering', 'delivered', 'dead_letter')",
            name="ck_integration_outbox_status",
        ),
        UniqueConstraint(
            "integration", "event_type", "reference", name="uq_integration_outbox_event"
        ),
        Index("ix_integration_outbox_due", "status", "next_attempt_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    event_id: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, default=lambda: f"evt-{uuid.uuid4()}"
    )
    integration: Mapped[str] = mapped_column(String(16), nullable=False)
    # approval_requested | approval_decided | containment_action |
    # killswitch_activated | decision_export
    event_type: Mapped[str] = mapped_column(String(32), nullable=False)
    # Dedupe/lookup key: approval request_id, containment record id,
    # kill event id, or policy decision record id, depending on event_type.
    reference: Mapped[str] = mapped_column(String(128), nullable=False)
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # Non-secret destination descriptor (channel id, webhook host, table).
    target: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Provider-side reference captured on successful delivery, e.g.
    # {"channel": "C1", "ts": "1700.1"} for Slack, {"sys_id": ..., "number":
    # ...} for ServiceNow. Later events (approval message updates) read the
    # original event's delivery_ref to find the message they must update.
    delivery_ref: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class IntegrationDeliveryAttemptRecord(Base):
    """One row per delivery attempt — delivery itself is evidence."""

    __tablename__ = "integration_delivery_attempts"
    __table_args__ = (Index("ix_integration_attempts_outbox", "outbox_id", "attempt_number"),)

    id: Mapped[uuid.UUID] = mapped_column(Uuid(), primary_key=True, default=uuid.uuid4)
    outbox_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(), ForeignKey("integration_outbox.id", ondelete="CASCADE"), nullable=False
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    result: Mapped[str] = mapped_column(String(16), nullable=False)  # success | failure
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
