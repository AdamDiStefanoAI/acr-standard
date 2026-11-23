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
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
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
    rollback_from_release_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
