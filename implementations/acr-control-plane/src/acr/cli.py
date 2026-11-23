"""Installed-package CLI: diagnostics plus WS2 operator commands.

`acr simulate` replays retained evaluation inputs against a candidate
policy release and prints the simulation report; `acr
purge-evaluation-inputs` deletes expired retained-input payloads. Both
talk to the configured database, like the service itself.
"""

import argparse
import asyncio
import json
from datetime import datetime
from importlib.metadata import version


def _parse_window(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise argparse.ArgumentTypeError(f"window bound '{value}' must include a timezone")
    return parsed


async def _run_simulation(args: argparse.Namespace) -> int:
    from acr.db.database import async_session_factory
    from acr.pillar2_policy.simulation import build_release_candidate_bundle, run_simulation

    async with async_session_factory() as db:
        artifact, _release = await build_release_candidate_bundle(db, args.release_id)
        record = await run_simulation(
            db,
            actor=args.actor,
            window_start=args.window_start,
            window_end=args.window_end,
            bundle_bytes=artifact.bytes_data,
            bundle_label=args.release_id,
        )
        await db.commit()
    print(json.dumps(record.report, indent=2, sort_keys=True))
    return 0


async def _run_purge() -> int:
    from acr.db.database import async_session_factory
    from acr.pillar4_observability.input_retention import purge_expired_inputs

    async with async_session_factory() as db:
        purged = await purge_expired_inputs(db)
        await db.commit()
    print(f"Purged {purged} expired evaluation input(s).")
    return 0


def main() -> None:
    """Report the installed distribution version using standard CLI conventions."""
    parser = argparse.ArgumentParser(prog="acr", description="ACR control-plane utilities")
    parser.add_argument(
        "--version", action="version", version=f"acr {version('acr-control-plane')}"
    )
    subparsers = parser.add_subparsers(dest="command")

    simulate = subparsers.add_parser(
        "simulate",
        help="Replay retained evaluation inputs against a candidate policy release",
    )
    simulate.add_argument("--release-id", required=True, help="Candidate policy release id")
    simulate.add_argument(
        "--window-start", required=True, type=_parse_window, help="ISO 8601 window start"
    )
    simulate.add_argument(
        "--window-end", required=True, type=_parse_window, help="ISO 8601 window end"
    )
    simulate.add_argument("--actor", default="cli", help="Actor recorded on the simulation run")

    subparsers.add_parser(
        "purge-evaluation-inputs",
        help="Delete payloads of retained evaluation inputs past their expiry",
    )

    args = parser.parse_args()
    if args.command == "simulate":
        raise SystemExit(asyncio.run(_run_simulation(args)))
    if args.command == "purge-evaluation-inputs":
        raise SystemExit(asyncio.run(_run_purge()))


if __name__ == "__main__":
    main()
