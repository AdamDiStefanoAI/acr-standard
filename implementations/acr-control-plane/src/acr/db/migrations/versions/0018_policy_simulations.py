"""Policy simulation runs + release gate record (v1.5.0 WS2).

Revision ID: 0018
Revises: 0017
Create Date: 2026-11-22

A simulation run is evidence (who, which bundle by hash, which window,
what flipped), so runs are stored durably. Activations performed under
the simulation promotion gate record the report they relied on, on the
release row itself.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policy_simulations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("run_id", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("bundle_label", sa.String(256), nullable=True),
        sa.Column("bundle_sha256", sa.String(64), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("decisions_in_window", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("inputs_available", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("inputs_missing", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("report", sa.JSON(), nullable=False),
        sa.Column("result_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("run_id"),
    )
    op.create_index("ix_policy_simulations_run_id", "policy_simulations", ["run_id"])
    op.create_index("ix_policy_simulations_bundle", "policy_simulations", ["bundle_sha256"])
    op.create_index("ix_policy_simulations_created_at", "policy_simulations", ["created_at"])
    op.add_column(
        "policy_releases",
        sa.Column("simulation_report_id", sa.String(64), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("policy_releases", "simulation_report_id")
    op.drop_index("ix_policy_simulations_created_at", table_name="policy_simulations")
    op.drop_index("ix_policy_simulations_bundle", table_name="policy_simulations")
    op.drop_index("ix_policy_simulations_run_id", table_name="policy_simulations")
    op.drop_table("policy_simulations")
