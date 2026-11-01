"""Payload-only redaction of completed v2 days, through the activityloggerctl command."""

from __future__ import annotations

import os
import stat
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

import analysis_log as al
from scripts import activityloggerctl as cli
from tests.test_analysis_v2 import _document, _record, _v2_body, _write_intent

DAY = date(2026, 8, 27)
T0 = datetime(2026, 8, 27, 10, tzinfo=timezone(timedelta(hours=2)))
FIXED_NOW = datetime(2026, 11, 1, 12, tzinfo=timezone.utc)
SECRET = "hunter2-SECRET"


class _FixedClock(datetime):
    @classmethod
    def now(cls, tz=None):
        return FIXED_NOW


def _write_ready_day(
    log_dir: Path,
    heading: str = "App - Window",
    payloads: tuple[str, str] = (f"tab {SECRET}", f'typed "{SECRET}"\n'),
) -> tuple[al.AnalysisRecord, ...]:
    log_dir.mkdir(mode=0o700)
    os.chmod(log_dir, 0o700)
    records = (
        _record("focus", T0, payload=payloads[0], heading=heading),
        _record(
            "type",
            T0 + timedelta(seconds=5),
            payload=payloads[1],
            heading=heading,
            trigger="file_flush",
        ),
        _record("heartbeat", T0 + timedelta(seconds=10), heading=heading),
    )
    body, *_rest = _v2_body(records)
    canonical = log_dir / f"daily_log_{DAY.isoformat()}.md"
    canonical.write_text(_document(DAY, al.ANALYSIS_FORMAT_V2, body), encoding="utf-8")
    os.chmod(canonical, 0o600)
    _write_intent(log_dir, DAY, records)
    al.publish_day_ready(log_dir, DAY)
    return records


def _snapshot(log_dir: Path) -> dict[str, bytes]:
    return {
        path.relative_to(log_dir).as_posix(): path.read_bytes()
        for path in sorted(log_dir.rglob("*"))
        if path.is_file()
    }


def _redact(monkeypatch, log_dir: Path, out_dir: Path, *args: str) -> int:
    monkeypatch.setattr(
        "sys.argv",
        ["activityloggerctl", "--log-dir", str(log_dir), "--output-dir", str(out_dir), "redact", *args],
    )
    return cli.main()


def _reason(log_dir: Path) -> str:
    return al.inspect_analysis_day(log_dir, DAY, today=date(2026, 11, 1)).reason


def _payloads(log_dir: Path) -> list[str]:
    text = (log_dir / f"daily_log_{DAY.isoformat()}.md").read_text(encoding="utf-8")
    return [r.payload for r in al.parse_records(text, day=DAY, expected_format=al.ANALYSIS_FORMAT_V2)]


def test_payload_overlap_and_marker_rules():
    # Overlapping literals merge into one marker, counted for each literal that matched.
    assert al._redact_payload("abc", ["ab", "abc"]) == ("[REDACTED]", (1, 1))
    assert al._redact_payload("xabcx", ["ab", "abc"]) == ("x[REDACTED]x", (1, 1))
    # Text inside an existing marker is never matched, even by a partial overlap.
    assert al._redact_payload("a[REDACTED]b", ["]b"]) == ("a[REDACTED]b", (0,))
    assert al._redact_payload("[REDACTED]z", ["z"]) == ("[REDACTED][REDACTED]", (1,))
    # A second pass finds nothing, so reruns are idempotent.
    once, _counts = al._redact_payload("abc and abc", ["abc"])
    assert al._redact_payload(once, ["abc"]) == (once, (0,))


def test_dry_run_prints_counts_and_changes_nothing(tmp_path, monkeypatch, capsys):
    log_dir, out_dir = tmp_path / "logs", tmp_path / "private_review"
    _write_ready_day(log_dir)
    before = _snapshot(log_dir)

    assert _redact(monkeypatch, log_dir, out_dir, "--day", DAY.isoformat(), "--literal", SECRET) == 0

    captured = capsys.readouterr()
    assert "literal_1_occurrences=2" in captured.out
    assert "records_changed=2" in captured.out
    assert "batches_redigested=1" in captured.out
    assert "applied=false" in captured.out
    assert SECRET not in captured.out + captured.err
    assert _snapshot(log_dir) == before
    assert not out_dir.exists()


def test_apply_from_literal_file_redacts_keeps_records_and_publishes_ready(tmp_path, monkeypatch, capsys):
    log_dir = tmp_path / "logs"
    out_dir = tmp_path / "missing" / "private_review"
    records = _write_ready_day(log_dir)
    literal_file = tmp_path / "literals.txt"
    literal_file.write_text(f"\n{SECRET}\n\n", encoding="utf-8")
    os.chmod(literal_file, 0o600)

    args = ["--day", DAY.isoformat(), "--literal-file", str(literal_file), "--apply"]
    assert _redact(monkeypatch, log_dir, out_dir, *args) == 0

    captured = capsys.readouterr()
    assert "applied=true" in captured.out
    assert "reason_after=ready" in captured.out
    assert SECRET not in captured.out + captured.err
    assert "readable by group or other users" not in captured.err

    canonical = (log_dir / f"daily_log_{DAY.isoformat()}.md").read_text(encoding="utf-8")
    assert SECRET not in canonical
    redacted = al.parse_records(canonical, day=DAY, expected_format=al.ANALYSIS_FORMAT_V2)
    assert [(r.kind, r.captured_at) for r in redacted] == [(r.kind, r.captured_at) for r in records]
    assert _reason(log_dir) == "ready"

    # Missing parents are created owner-only, and the run folder is exclusive.
    for directory in (out_dir.parent, out_dir, out_dir / "redaction_backups"):
        assert stat.S_IMODE(os.stat(directory).st_mode) == 0o700
    backups = list((out_dir / "redaction_backups").iterdir())
    assert len(backups) == 1 and backups[0].name.startswith(f"{DAY.isoformat()}_")
    assert stat.S_IMODE(os.stat(backups[0]).st_mode) == 0o700
    names = sorted(path.name for path in backups[0].iterdir())
    assert names == [
        f".daily_log_{DAY.isoformat()}.ready.json",
        f"analysis_intents_{DAY.isoformat()}.journal",
        f"daily_log_{DAY.isoformat()}.md",
    ]
    for path in backups[0].iterdir():
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert SECRET in (backups[0] / f"daily_log_{DAY.isoformat()}.md").read_text(encoding="utf-8")


def test_overlapping_literals_replace_once_and_rerun_is_idempotent(tmp_path, monkeypatch, capsys):
    log_dir, out_dir = tmp_path / "logs", tmp_path / "private_review"
    _write_ready_day(log_dir, payloads=("abc", "xabcx"))
    args = ["--day", DAY.isoformat(), "--literal", "ab", "--literal", "abc"]

    assert _redact(monkeypatch, log_dir, out_dir, *args, "--apply") == 0
    assert _payloads(log_dir) == ["[REDACTED]", "x[REDACTED]x", ""]
    assert _reason(log_dir) == "ready"
    capsys.readouterr()

    assert _redact(monkeypatch, log_dir, out_dir, *args) == 0
    assert "literal_1_occurrences=0" in capsys.readouterr().out
    assert _redact(monkeypatch, log_dir, out_dir, *args, "--apply") == 1
    assert "No literal occurrences" in capsys.readouterr().err
    assert _payloads(log_dir) == ["[REDACTED]", "x[REDACTED]x", ""]


def test_refuses_literal_that_is_part_of_the_marker(tmp_path, monkeypatch, capsys):
    log_dir, out_dir = tmp_path / "logs", tmp_path / "private_review"
    _write_ready_day(log_dir)
    before = _snapshot(log_dir)

    for literal in ("RED", "[REDACTED]"):
        assert _redact(monkeypatch, log_dir, out_dir, "--day", DAY.isoformat(), "--literal", literal) == 1
        assert "part of the redaction marker" in capsys.readouterr().err
    assert _snapshot(log_dir) == before


def test_refuses_existing_backup_folder_without_writing(tmp_path, monkeypatch, capsys):
    log_dir, out_dir = tmp_path / "logs", tmp_path / "private_review"
    _write_ready_day(log_dir)
    monkeypatch.setattr(al, "datetime", _FixedClock)
    stamp = FIXED_NOW.astimezone().strftime("%Y%m%dT%H%M%S%f")
    (out_dir / "redaction_backups" / f"{DAY.isoformat()}_{stamp}").mkdir(parents=True, mode=0o700)
    before = _snapshot(log_dir)

    assert _redact(monkeypatch, log_dir, out_dir, "--day", DAY.isoformat(), "--literal", SECRET, "--apply") == 1

    assert "backup folder for this run already exists" in capsys.readouterr().err
    assert _snapshot(log_dir) == before


def test_late_write_failure_names_only_the_backup_folder(tmp_path, monkeypatch, capsys):
    log_dir, out_dir = tmp_path / "logs", tmp_path / "private_review"
    _write_ready_day(log_dir)

    def failing_publish(*_args, **_kwargs):
        raise OSError("simulated publish failure")

    monkeypatch.setattr(al, "publish_day_ready", failing_publish)

    assert _redact(monkeypatch, log_dir, out_dir, "--day", DAY.isoformat(), "--literal", SECRET, "--apply") == 1

    err = capsys.readouterr().err
    assert "Backups are in" in err and "redaction_backups" in err
    assert "simulated publish failure" not in err
    assert SECRET not in err


def test_refuses_today_without_touching_files(tmp_path, monkeypatch, capsys):
    log_dir, out_dir = tmp_path / "logs", tmp_path / "private_review"
    today = datetime.now().astimezone().date()

    assert _redact(monkeypatch, log_dir, out_dir, "--day", today.isoformat(), "--literal", SECRET, "--apply") == 1

    assert "Only completed days can be redacted" in capsys.readouterr().err
    assert not out_dir.exists()


def test_refuses_invalid_marker(tmp_path, monkeypatch, capsys):
    log_dir, out_dir = tmp_path / "logs", tmp_path / "private_review"
    _write_ready_day(log_dir)
    marker = log_dir / "analysis_shadow" / f"analysis_invalid_{DAY.isoformat()}.txt"
    marker.write_text("2026-08-28T10:00:00+02:00 shadow failed\n", encoding="utf-8")
    os.chmod(marker, 0o600)
    before = _snapshot(log_dir)

    assert _redact(monkeypatch, log_dir, out_dir, "--day", DAY.isoformat(), "--literal", SECRET, "--apply") == 1

    assert "invalid marker" in capsys.readouterr().err
    assert _snapshot(log_dir) == before
    assert not out_dir.exists()


def test_refuses_when_day_is_not_ready(tmp_path, monkeypatch, capsys):
    log_dir, out_dir = tmp_path / "logs", tmp_path / "private_review"
    _write_ready_day(log_dir)
    al.ready_path(log_dir, DAY).unlink()

    assert _redact(monkeypatch, log_dir, out_dir, "--day", DAY.isoformat(), "--literal", SECRET) == 1

    assert "must be ready" in capsys.readouterr().err


def test_refuses_literal_outside_payloads(tmp_path, monkeypatch, capsys):
    log_dir, out_dir = tmp_path / "logs", tmp_path / "private_review"
    _write_ready_day(log_dir, heading=f"App {SECRET}")
    before = _snapshot(log_dir)

    assert _redact(monkeypatch, log_dir, out_dir, "--day", DAY.isoformat(), "--literal", SECRET, "--apply") == 1

    assert "outside record payloads" in capsys.readouterr().err
    assert _snapshot(log_dir) == before


def test_reseal_repairs_hand_edited_intent_mismatch(tmp_path, monkeypatch, capsys):
    log_dir, out_dir = tmp_path / "logs", tmp_path / "private_review"
    _write_ready_day(log_dir)
    canonical = log_dir / f"daily_log_{DAY.isoformat()}.md"
    canonical.write_text(canonical.read_text(encoding="utf-8").replace(SECRET, "REDACTED"), encoding="utf-8")
    assert _reason(log_dir) == "intent_mismatch"

    assert _redact(monkeypatch, log_dir, out_dir, "--day", DAY.isoformat(), "--literal", SECRET) == 1
    assert "must be ready" in capsys.readouterr().err

    assert _redact(monkeypatch, log_dir, out_dir, "--day", DAY.isoformat(), "--reseal") == 0
    dry = capsys.readouterr().out
    assert "reason_before=intent_mismatch" in dry
    assert "batches_redigested=1" in dry
    assert _reason(log_dir) == "intent_mismatch"

    assert _redact(monkeypatch, log_dir, out_dir, "--day", DAY.isoformat(), "--reseal", "--apply") == 0
    assert "reason_after=ready" in capsys.readouterr().out
    assert _reason(log_dir) == "ready"
    assert "REDACTED" in canonical.read_text(encoding="utf-8")


@pytest.mark.parametrize("damage", ["missing", "invalid"])
def test_reseal_republishes_missing_or_invalid_proof(tmp_path, monkeypatch, capsys, damage):
    log_dir, out_dir = tmp_path / "logs", tmp_path / "private_review"
    _write_ready_day(log_dir)
    proof = al.ready_path(log_dir, DAY)
    if damage == "missing":
        proof.unlink()
    else:
        proof.write_text("{}\n", encoding="utf-8")
        os.chmod(proof, 0o600)
    expected = "proof_missing" if damage == "missing" else "proof_invalid"
    assert _reason(log_dir) == expected
    canonical_before = (log_dir / f"daily_log_{DAY.isoformat()}.md").read_bytes()
    journal_before = al.intent_path(log_dir, DAY).read_bytes()

    assert _redact(monkeypatch, log_dir, out_dir, "--day", DAY.isoformat(), "--reseal") == 0
    assert f"reason_before={expected}" in capsys.readouterr().out

    assert _redact(monkeypatch, log_dir, out_dir, "--day", DAY.isoformat(), "--reseal", "--apply") == 0
    assert "reason_after=ready" in capsys.readouterr().out
    assert _reason(log_dir) == "ready"
    assert (log_dir / f"daily_log_{DAY.isoformat()}.md").read_bytes() == canonical_before
    assert al.intent_path(log_dir, DAY).read_bytes() == journal_before


def test_literal_file_open_to_others_is_warned_but_not_printed(tmp_path, monkeypatch, capsys):
    log_dir, out_dir = tmp_path / "logs", tmp_path / "private_review"
    _write_ready_day(log_dir)
    literal_file = tmp_path / "literals.txt"
    literal_file.write_text(f"{SECRET}\n", encoding="utf-8")
    os.chmod(literal_file, 0o644)

    assert _redact(monkeypatch, log_dir, out_dir, "--day", DAY.isoformat(), "--literal-file", str(literal_file)) == 0

    captured = capsys.readouterr()
    assert "readable by group or other users" in captured.err
    assert SECRET not in captured.out + captured.err
