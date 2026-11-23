"""Time-boxed auditor grants: operator credential expiry (v1.5.0 WS3).

Revision ID: 0019
Revises: 0018
Create Date: 2026-11-23

Auditor access is issued as a grant with a mandatory expiry, not as a
standing credential. The expiry lives on the operator credential row so
the existing key lifecycle (issue, rotate, revoke) governs grants too.
NULL means a standing operator credential; auditor grants are only ever
created with an expiry by the dedicated issuance endpoint.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "operator_credentials",
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_operator_credentials_expires_at",
        "operator_credentials",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_operator_credentials_expires_at", table_name="operator_credentials")
    op.drop_column("operator_credentials", "expires_at")
