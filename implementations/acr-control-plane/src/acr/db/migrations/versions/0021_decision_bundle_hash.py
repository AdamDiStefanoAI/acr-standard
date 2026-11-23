"""Decision records: stamp the active policy bundle hash (v1.5.0 follow-up).

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-23

WS3's auditor surface exposed a gap: decision rows recorded policy_id
only, so a reviewer could not tie a recorded decision to the exact
policy bundle that produced it without an approval authorization
snapshot. policy_decisions gains bundle_hash: the SHA-256 of the
active runtime bundle archive, derived exactly as WS2 policy
simulation derives it (sha256 over the bytes built by
build_active_runtime_bundle) and stamped at §18 recording time for
enforce and observe decisions alike.

Nullable: rows recorded before this migration keep NULL, and the
recording path stamps best-effort (a bundle that cannot be rebuilt at
recording time leaves NULL rather than failing the recording).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "policy_decisions",
        sa.Column("bundle_hash", sa.String(64), nullable=True),
    )
    op.create_index("ix_policy_decisions_bundle_hash", "policy_decisions", ["bundle_hash"])


def downgrade() -> None:
    op.drop_index("ix_policy_decisions_bundle_hash", table_name="policy_decisions")
    op.drop_column("policy_decisions", "bundle_hash")
