"""Outbox: admit the Splunk and syslog integrations (v1.5.0).

Revision ID: 0021
Revises: 0020
Create Date: 2026-11-23

The WS4 outbox constrained `integration` to the four original senders.
The Splunk HEC and syslog emitters write rows under 'splunk' and
'syslog', so the check constraint grows to admit them. No other schema
change: both emitters reuse the existing outbox and attempt tables.
"""

from __future__ import annotations

from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("ck_integration_outbox_integration", "integration_outbox", type_="check")
    op.create_check_constraint(
        "ck_integration_outbox_integration",
        "integration_outbox",
        "integration IN ('slack', 'teams', 'servicenow', 'sentinel', 'splunk', 'syslog')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_integration_outbox_integration", "integration_outbox", type_="check")
    op.create_check_constraint(
        "ck_integration_outbox_integration",
        "integration_outbox",
        "integration IN ('slack', 'teams', 'servicenow', 'sentinel')",
    )
