#!/usr/bin/env python3
"""Local operator controls for ActivityLogger."""

from __future__ import annotations

import argparse
import sys
from datetime import date, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from analysis_log import RedactionRefused, redact_completed_day  # noqa: E402
from analysis_view import USER_PRIVATE_OUTPUT_DIR as DEFAULT_OUTPUT_DIR  # noqa: E402
from config import load_config  # noqa: E402
from operator_errors import safe_error_message  # noqa: E402
from operator_controls import (  # noqa: E402
    health_report,
    record_review_outcome,
    set_manual_pause,
    storage_report,
)


def _print_report(report: dict[str, object]) -> None:
    for key, value in report.items():
        print(f"{key}={str(value).lower() if isinstance(value, bool) else value}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Private local ActivityLogger controls.")
    parser.add_argument("--log-dir", type=Path, default=None)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    commands = parser.add_subparsers(dest="command", required=True)
    health = commands.add_parser("health", help="Show payload-free runtime and day health.")
    health.add_argument("--day", type=date.fromisoformat, default=None)
    commands.add_parser("storage", help="Show payload-free private storage totals.")
    commands.add_parser("pause", help="Pause every capture channel.")
    commands.add_parser("resume", help="Clear only the manual privacy pause.")
    review = commands.add_parser("review", help="Record a local weekly review outcome.")
    review.add_argument("--week", type=date.fromisoformat, required=True)
    review.add_argument("--days", type=int, choices=(5, 7), default=None,
                        help="Exact review window. Omit only for an older outcome with no known window.")
    review.add_argument("--outcome", choices=("accepted", "ignored", "tried"), required=True)
    review.add_argument("--value-result", default="")
    review.add_argument("--notes", default="")
    redact = commands.add_parser(
        "redact",
        help="Replace literal text in one completed v2 day's record payloads, then republish its ready proof.",
        description="Dry run by default; --apply writes after backing up the day. Literals are never printed. "
                    "Use --literal-file so secrets stay out of shell history.",
    )
    redact.add_argument("--day", type=date.fromisoformat, required=True)
    redact.add_argument("--literal", action="append", default=[],
                        help="Exact text to replace with [REDACTED] inside record payloads. Repeat for each literal.")
    redact.add_argument("--literal-file", type=Path, default=None,
                        help="File with one literal per line. Prefer this over --literal for secrets.")
    redact.add_argument("--reseal", action="store_true",
                        help="Reseal from the current canonical log: repair an intent_mismatch day, or republish a "
                             "missing or invalid ready proof. Takes no literals.")
    redact.add_argument("--apply", action="store_true", help="Write the change. Without it, print counts only.")
    args = parser.parse_args()
    try:
        if args.command == "health":
            log_dir = args.log_dir or load_config().log_dir
            _print_report(health_report(log_dir, args.day or datetime.now().astimezone().date()))
        elif args.command == "storage":
            log_dir = args.log_dir or load_config().log_dir
            _print_report(storage_report(log_dir, output_dir=args.output_dir))
        elif args.command in {"pause", "resume"}:
            state = set_manual_pause(args.command == "pause")
            _print_report(
                {
                    "manual_paused": state["manual_paused"],
                    "capture_paused": state["capture_paused"],
                    "control_revision": state["control_revision"],
                }
            )
        elif args.command == "review":
            output = record_review_outcome(
                args.week,
                args.outcome,
                args.value_result,
                args.notes,
                days=args.days,
                output_dir=args.output_dir,
            )
            print(f"output={output.resolve()}")
        elif args.command == "redact":
            log_dir = args.log_dir or load_config().log_dir
            literals = list(args.literal)
            if args.literal_file is not None:
                if args.literal_file.stat().st_mode & 0o077:
                    print("warning=literal file is readable by group or other users. Run chmod 600 on it.",
                          file=sys.stderr)
                literals += [line for line in args.literal_file.read_text(encoding="utf-8").splitlines() if line]
            _print_report(
                redact_completed_day(
                    log_dir,
                    args.day,
                    literals,
                    backup_root=args.output_dir,
                    reseal=args.reseal,
                    apply=args.apply,
                )
            )
    except RedactionRefused as exc:
        print(f"error={exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"error={safe_error_message(exc)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
