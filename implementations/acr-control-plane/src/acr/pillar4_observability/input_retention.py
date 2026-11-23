"""Pillar 4: Evaluation-input retention for policy simulation (v1.5.0 WS2).

Retention is OFF by default and opt-in per deployment
(settings.evaluation_input_retention_enabled). When on, the gateway stores
the effective evaluation input — the exact manifest, action, and enriched
context handed to the policy engine — in the same transaction that records
the evaluation's decisions, so simulation (pillar2_policy.simulation) can
later replay real traffic against a candidate policy bundle.

Privacy posture, in order of importance:

1. Redaction happens BEFORE storage. Configured dot-paths
   (settings.evaluation_input_redaction_fields_json, e.g.
   "action.parameters.customer_id") are replaced with a fixed marker in a
   copy of the payload; the unredacted payload never reaches the database.
   Everything downstream (simulation reports, exports) reads only the
   stored, already-redacted copy.
2. Retention is bounded: every row carries an expiry, and
   purge_expired_inputs deletes expired payloads. The row itself remains
   as a tombstone (state='purged', payload NULL) so the decision record's
   retention note and simulation coverage accounting stay truthful.
3. Off means off: with retention disabled the gateway writes nothing here
   and the evaluate path is unchanged beyond a settings check.
"""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from acr.common.time import utcnow
from acr.config import evaluation_input_redaction_fields, settings
from acr.db.models import EvaluationInputRecord

REDACTED_MARKER = "[REDACTED]"


def redact_payload(payload: dict, field_paths: list[str]) -> dict:
    """Return a copy of payload with each dot-path's value replaced.

    Paths walk dict keys from the payload root ("agent", "action",
    "context"). A path that does not resolve (missing key, non-dict
    intermediate) is a no-op: redaction config may name fields that only
    some evaluations carry. The input is never mutated.
    """
    redacted = copy.deepcopy(payload)
    for path in field_paths:
        parts = [part for part in str(path).split(".") if part]
        if not parts:
            continue
        node = redacted
        for part in parts[:-1]:
            if not isinstance(node, dict) or part not in node:
                node = None
                break
            node = node[part]
        if isinstance(node, dict) and parts[-1] in node:
            node[parts[-1]] = REDACTED_MARKER
    return redacted


def canonical_payload_hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def build_retained_input_data(
    *,
    correlation_id: str,
    agent_id: str,
    evaluation_input: dict,
    recorded_decision: str,
    enforcement_mode: str,
    now: datetime | None = None,
    redaction_fields: list[str] | None = None,
) -> dict:
    """Constructor kwargs for EvaluationInputRecord, redaction applied.

    Returned as plain data (not an ORM object) so the gateway's recording
    transaction can construct the row inside its retry loop, next to the
    decision rows it commits with.
    """
    retained_at = now or utcnow()
    fields = (
        redaction_fields if redaction_fields is not None else evaluation_input_redaction_fields()
    )
    payload = redact_payload(evaluation_input, fields)
    return {
        "correlation_id": correlation_id,
        "agent_id": agent_id,
        "payload": payload,
        "payload_sha256": canonical_payload_hash(payload),
        "recorded_decision": recorded_decision,
        "enforcement_mode": enforcement_mode,
        "state": "retained",
        "retained_at": retained_at,
        "expires_at": retained_at
        + timedelta(days=max(1, settings.evaluation_input_retention_days)),
    }


async def get_retained_input(db: AsyncSession, correlation_id: str) -> EvaluationInputRecord | None:
    result = await db.execute(
        select(EvaluationInputRecord).where(EvaluationInputRecord.correlation_id == correlation_id)
    )
    return result.scalar_one_or_none()


async def purge_expired_inputs(db: AsyncSession, *, now: datetime | None = None) -> int:
    """Delete the payloads of retained inputs past their expiry.

    The payload is the sensitive part, so the payload is what is deleted;
    the tombstone row (state, hashes, timestamps) remains so decision
    records keep their retention note and simulation coverage counts stay
    honest. Idempotent: purged rows no longer match the state filter.
    The caller owns the transaction (the lifespan purge loop commits),
    matching the codebase's other sweep functions.
    """
    moment = now or utcnow()
    result = await db.execute(
        update(EvaluationInputRecord)
        .where(
            EvaluationInputRecord.state == "retained",
            EvaluationInputRecord.expires_at <= moment,
        )
        .values(payload=None, state="purged", purged_at=moment)
    )
    return int(result.rowcount or 0)
