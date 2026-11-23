"""Integrations: durable outbox, delivery attempts, chat-decision stamp (v1.5.0 WS4).

Revision ID: 0020
Revises: 0019
Create Date: 2026-11-23

WS4 moves every outbound integration (Slack/Teams approvals and alerts,
ServiceNow incidents, Sentinel decision export) onto a durable outbox so
delivery is asynchronous, retried, dead-lettered, and itself recorded as
evidence. The evaluate hot path only ever enqueues; it never delivers.

approval_requests gains decided_channel / chat_actor_id: when a decision
arrives through a chat integration, decided_by keeps carrying the mapped
operator subject (the identity the approvals path authorized) and these
columns preserve the transport identity next to it.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "approval_requests",
        sa.Column("decided_channel", sa.String(32), nullable=True),
    )
    op.add_column(
        "approval_requests",
        sa.Column("chat_actor_id", sa.String(128), nullable=True),
    )
    op.create_table(
        "integration_outbox",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("integration", sa.String(16), nullable=False),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("reference", sa.String(128), nullable=False),
        sa.Column("correlation_id", sa.String(64), nullable=True),
        sa.Column("target", sa.String(256), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("next_attempt_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("delivery_ref", sa.JSON(), nullable=True),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "integration IN ('slack', 'teams', 'servicenow', 'sentinel')",
            name="ck_integration_outbox_integration",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'delivering', 'delivered', 'dead_letter')",
            name="ck_integration_outbox_status",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("event_id"),
        sa.UniqueConstraint(
            "integration", "event_type", "reference", name="uq_integration_outbox_event"
        ),
    )
    op.create_index(
        "ix_integration_outbox_correlation_id", "integration_outbox", ["correlation_id"]
    )
    op.create_index("ix_integration_outbox_status", "integration_outbox", ["status"])
    op.create_index("ix_integration_outbox_created_at", "integration_outbox", ["created_at"])
    op.create_index(
        "ix_integration_outbox_due", "integration_outbox", ["status", "next_attempt_at"]
    )
    op.create_table(
        "integration_delivery_attempts",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("outbox_id", sa.Uuid(), nullable=False),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["outbox_id"], ["integration_outbox.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_integration_attempts_outbox",
        "integration_delivery_attempts",
        ["outbox_id", "attempt_number"],
    )


def downgrade() -> None:
    op.drop_index("ix_integration_attempts_outbox", table_name="integration_delivery_attempts")
    op.drop_table("integration_delivery_attempts")
    op.drop_index("ix_integration_outbox_due", table_name="integration_outbox")
    op.drop_index("ix_integration_outbox_created_at", table_name="integration_outbox")
    op.drop_index("ix_integration_outbox_status", table_name="integration_outbox")
    op.drop_index("ix_integration_outbox_correlation_id", table_name="integration_outbox")
    op.drop_table("integration_outbox")
    op.drop_column("approval_requests", "chat_actor_id")
    op.drop_column("approval_requests", "decided_channel")
