"""Per-agent enforcement mode: enforce | observe (v1.5.0 WS1).

Revision ID: 0016
Revises: 0015
Create Date: 2026-11-22

Observe mode lets an agent be evaluated with full §18 evidence semantics
while the call itself proceeds. The mode is operator-controlled state: it
lives on the agent record, is stamped onto every policy decision issued
under it, and defaults to `enforce` everywhere so existing agents and
existing decision semantics are unchanged by this migration.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "agents",
        sa.Column("enforcement_mode", sa.String(16), nullable=False, server_default="enforce"),
    )
    op.create_check_constraint(
        "ck_agents_enforcement_mode",
        "agents",
        "enforcement_mode IN ('enforce', 'observe')",
    )
    op.add_column(
        "policy_decisions",
        sa.Column("enforcement_mode", sa.String(16), nullable=False, server_default="enforce"),
    )
    op.create_check_constraint(
        "ck_policy_decisions_enforcement_mode",
        "policy_decisions",
        "enforcement_mode IN ('enforce', 'observe')",
    )
    # The observe report aggregates one agent's observe decisions over a
    # time window; this composite index serves exactly that scan.
    op.create_index(
        "ix_policy_decisions_observe_report",
        "policy_decisions",
        ["agent_id", "enforcement_mode", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_policy_decisions_observe_report", table_name="policy_decisions")
    op.drop_constraint("ck_policy_decisions_enforcement_mode", "policy_decisions", type_="check")
    op.drop_column("policy_decisions", "enforcement_mode")
    op.drop_constraint("ck_agents_enforcement_mode", "agents", type_="check")
    op.drop_column("agents", "enforcement_mode")
