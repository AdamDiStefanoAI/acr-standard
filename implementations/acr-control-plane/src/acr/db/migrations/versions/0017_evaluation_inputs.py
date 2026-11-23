"""Retained evaluation inputs for policy simulation (v1.5.0 WS2).

Revision ID: 0017
Revises: 0016
Create Date: 2026-11-22

Deployments may opt in to retaining the effective evaluation input
(manifest, action, enriched context) alongside each decision so policy
changes can be replayed against real traffic before promotion. Retention
is off by default; payloads are redacted before storage; a background
purge deletes expired payloads while this row remains as the note that
the input was retained and purged.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "evaluation_inputs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("correlation_id", sa.String(64), nullable=False),
        sa.Column("agent_id", sa.String(128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("recorded_decision", sa.String(16), nullable=False),
        sa.Column("enforcement_mode", sa.String(16), nullable=False, server_default="enforce"),
        sa.Column("state", sa.String(16), nullable=False, server_default="retained"),
        sa.Column(
            "retained_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("purged_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("state IN ('retained', 'purged')", name="ck_evaluation_inputs_state"),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.agent_id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("correlation_id"),
    )
    op.create_index("ix_evaluation_inputs_correlation_id", "evaluation_inputs", ["correlation_id"])
    op.create_index("ix_evaluation_inputs_agent_id", "evaluation_inputs", ["agent_id"])
    op.create_index(
        "ix_evaluation_inputs_agent_retained", "evaluation_inputs", ["agent_id", "retained_at"]
    )
    op.create_index("ix_evaluation_inputs_expires", "evaluation_inputs", ["state", "expires_at"])


def downgrade() -> None:
    op.drop_index("ix_evaluation_inputs_expires", table_name="evaluation_inputs")
    op.drop_index("ix_evaluation_inputs_agent_retained", table_name="evaluation_inputs")
    op.drop_index("ix_evaluation_inputs_agent_id", "evaluation_inputs")
    op.drop_index("ix_evaluation_inputs_correlation_id", "evaluation_inputs")
    op.drop_table("evaluation_inputs")
