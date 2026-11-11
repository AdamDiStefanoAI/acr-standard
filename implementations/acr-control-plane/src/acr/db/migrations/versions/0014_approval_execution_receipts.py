"""Bind approvals and durably fence execution attempts.

Revision ID: 0014
Revises: 0013
Create Date: 2026-11-11
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Legacy approvals intentionally remain unbound and cannot safely resume.
    op.add_column(
        "approval_requests", sa.Column("authorization_snapshot", sa.JSON(), nullable=True)
    )
    op.add_column(
        "approval_requests", sa.Column("request_payload_hash", sa.String(64), nullable=True)
    )
    op.add_column("approval_requests", sa.Column("request_context", sa.JSON(), nullable=True))
    op.create_table(
        "execution_receipts",
        sa.Column("attempt_id", sa.String(64), primary_key=True),
        sa.Column("approval_request_id", sa.String(64), nullable=False, unique=True),
        sa.Column("payload_hash", sa.String(64), nullable=False),
        sa.Column("authorization_snapshot", sa.JSON(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('executing', 'succeeded', 'unknown', 'blocked')",
            name="ck_execution_receipts_state",
        ),
    )


def downgrade() -> None:
    op.drop_table("execution_receipts")
    op.drop_column("approval_requests", "request_context")
    op.drop_column("approval_requests", "request_payload_hash")
    op.drop_column("approval_requests", "authorization_snapshot")
