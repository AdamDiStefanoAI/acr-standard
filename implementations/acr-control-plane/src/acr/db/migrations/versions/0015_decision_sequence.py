"""Assign every policy decision a sequence position at issuance (§18).

Revision ID: 0015
Revises: 0014
Create Date: 2026-11-22
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Per-agent counter incremented in the same transaction that records the
    # decisions, so a decision's sequence position is fixed when it is issued.
    op.create_table(
        "decision_sequences",
        sa.Column(
            "agent_id",
            sa.String(128),
            sa.ForeignKey("agents.agent_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("last_sequence", sa.BigInteger(), nullable=False, server_default="0"),
    )
    # Null on rows written before this migration: their issuance order was
    # never recorded and must not be reconstructed from persistence order.
    op.add_column("policy_decisions", sa.Column("sequence", sa.BigInteger(), nullable=True))
    op.create_index("ix_policy_decisions_sequence", "policy_decisions", ["sequence"])


def downgrade() -> None:
    op.drop_index("ix_policy_decisions_sequence", table_name="policy_decisions")
    op.drop_column("policy_decisions", "sequence")
    op.drop_table("decision_sequences")
