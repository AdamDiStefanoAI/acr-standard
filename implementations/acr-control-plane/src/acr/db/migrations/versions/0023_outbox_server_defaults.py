"""Outbox timestamps: restore the server defaults migration 0020 omitted.

Revision ID: 0023
Revises: 0022
Create Date: 2026-11-23

The ORM models declare ``server_default=func.now()`` for
``integration_outbox.next_attempt_at`` / ``created_at`` / ``updated_at``
and ``integration_delivery_attempts.attempted_at``, but migration 0020
created those columns NOT NULL with no database default. On a schema
built by the migrations (i.e. every real deployment) an outbox insert
that relies on the server default fails with a NOT NULL violation;
``enqueue_event`` deliberately swallows insert failures, so no
integration event was ever queued from a migrated deployment. Test
schemas built from model metadata (``create_all``) carry the defaults,
which is why the suite never saw it. A live verification session on
2026-11-23 caught it.

This migration aligns the migrated schema with the models: the four
columns gain ``DEFAULT now()``. No data changes; existing rows already
hold timestamps.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None

_COLUMNS = (
    ("integration_outbox", "next_attempt_at"),
    ("integration_outbox", "created_at"),
    ("integration_outbox", "updated_at"),
    ("integration_delivery_attempts", "attempted_at"),
)


def upgrade() -> None:
    for table, column in _COLUMNS:
        op.alter_column(table, column, server_default=sa.func.now())


def downgrade() -> None:
    for table, column in _COLUMNS:
        op.alter_column(table, column, server_default=None)
