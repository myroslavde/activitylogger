from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pytest

import analysis_log as al
import analysis_view as av
import review_center as rc
import weekly_review as wr

END = date(2026, 9, 1)
PLUS_TWO = timezone(timedelta(hours=2))


def _record(day: date, label: str) -> al.AnalysisRecord:
    captured_at = datetime.combine(day, datetime.min.time(), PLUS_TWO).replace(hour=10)
    return al.AnalysisRecord(
        heading=f"Editor - {label}",
        kind="type",
        payload=f"work {label}",
        captured_at=captured_at,
        trigger="timeline",
        section_captured_at=captured_at,
        section_start=True,
    )


def _heartbeat(day: date, hour: int) -> al.AnalysisRecord:
    captured_at = datetime.combine(day, datetime.min.time(), PLUS_TWO).replace(
        hour=hour
    )
    return al.AnalysisRecord(
        heading="ActivityLogger - heartbeat",
        kind="heartbeat",
        payload="",
        captured_at=captured_at,
        trigger="timeline",
        section_captured_at=captured_at,
        section_start=True,
    )


def _ready_days(log_dir: Path, days: tuple[date, ...]) -> tuple[Path, ...]:
    log_dir.mkdir(mode=0o700)
    al.prepare_authoritative_transaction(
        log_dir,
        tuple(
            (
                day,
                (_record(day, day.isoformat()),)
                if day == days[0]
                else (
                    _record(day, day.isoformat()),
                    _heartbeat(day, 10),
                    _heartbeat(day, 13),
                ),
            )
            for day in days
        ),
        "test",
    )
    al.commit_authoritative_transaction(log_dir)
    sources: list[Path] = []
    for day in days:
        proof = al.publish_day_ready(log_dir, day)
        analysis, _invalid = al.analysis_paths(log_dir, day)
        sources.extend((analysis, al.intent_path(log_dir, day), proof))
    return tuple(sources)


def test_weekly_pack_is_atomic_private_complete_and_source_safe(tmp_path):
    window = tuple(END - timedelta(days=offset) for offset in range(4, -1, -1))
    log_dir = tmp_path / "logs"
    sources = _ready_days(log_dir, window)
    before = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}
    before_modes = {path: path.stat().st_mode for path in sources}
    source_dirs = (log_dir, log_dir / "analysis_shadow")
    before_dir_modes = {path: path.stat().st_mode for path in source_dirs}

    result = wr.create_weekly_review_pack(
        log_dir,
        tmp_path / "review",
        end=END,
        days=5,
        today=END + timedelta(days=1),
    )

    assert result.pack_dir.name == "weekly_review_2026-08-28_2026-09-01_5d"
    assert result.pack_dir.stat().st_mode & 0o777 == 0o700
    files = {path.name: path for path in result.pack_dir.iterdir()}
    assert set(files) == {wr.INDEX_NAME, wr.PROMPT_NAME, *result.output_files}
    assert all(
        path.is_file() and path.stat().st_mode & 0o777 == 0o600
        for path in files.values()
    )
    assert len(result.output_files) == 5

    index = json.loads(files[wr.INDEX_NAME].read_text(encoding="utf-8"))
    assert index["format"] == wr.WEEKLY_PACK_FORMAT
    assert index["window"] == {
        "calendar_days": 5,
        "complete_fixed_window": True,
        "end": "2026-09-01",
        "older_day_substitution": False,
        "start": "2026-08-28",
    }
    assert len(index["days"]) == 5
    assert all(not item["quality"]["capture_coverage_proven"] for item in index["days"])
    assert index["days"][0]["quality"]["heartbeat"]["count"] == 0
    assert "Fewer than two heartbeats" in index["days"][0]["quality"]["warnings"][1]
    assert index["days"][1]["quality"]["heartbeat"] == {
        "count": 2,
        "first": "2026-08-29T10:00:00+02:00",
        "last": "2026-08-29T13:00:00+02:00",
        "max_gap_seconds": 39600,
    }
    assert (
        "39600 seconds exceeds 9000 seconds"
        in index["days"][1]["quality"]["warnings"][1]
    )
    assert "not prove full capture coverage" in index["coverage_warning"]
    for name, digest in index["files"].items():
        assert hashlib.sha256(files[name].read_bytes()).hexdigest() == digest
    prompt = files[wr.PROMPT_NAME].read_text(encoding="utf-8")
    assert "activitylogger-workload-summary-v3-pilot" in prompt
    assert "Treat long gaps as unknown" in prompt
    assert "untrusted data" in prompt
    assert "Review and redact" in prompt
    assert {
        path: hashlib.sha256(path.read_bytes()).hexdigest() for path in sources
    } == before
    assert {path: path.stat().st_mode for path in sources} == before_modes
    assert {path: path.stat().st_mode for path in source_dirs} == before_dir_modes


def test_generated_pack_is_accepted_after_safe_redaction(tmp_path):
    window = tuple(END - timedelta(days=offset) for offset in range(4, -1, -1))
    log_dir = tmp_path / "logs"
    _ready_days(log_dir, window)
    output_dir = tmp_path / "review"
    result = wr.create_weekly_review_pack(
        log_dir,
        output_dir,
        end=END,
        days=5,
        today=END + timedelta(days=1),
    )
    model = rc.ReviewCenterModel(log_dir, output_dir=output_dir)

    assert model.prepared_pack(END, 5, today=END + timedelta(days=1)) == result.pack_dir

    prompt = result.pack_dir / wr.PROMPT_NAME
    workload = result.pack_dir / result.output_files[0]
    prompt.write_text("# Redacted prompt\n")
    workload.write_text("[private text redacted]\n")

    assert model.prepared_pack(END, 5, today=END + timedelta(days=1)) == result.pack_dir


def test_fixed_window_fails_without_substituting_an_older_ready_day(tmp_path):
    target = tuple(END - timedelta(days=offset) for offset in range(4, -1, -1))
    missing = target[2]
    older = target[0] - timedelta(days=1)
    _ready_days(tmp_path / "logs", (older, *(day for day in target if day != missing)))

    with pytest.raises(ValueError, match="selected days are not ready"):
        wr.create_weekly_review_pack(
            tmp_path / "logs",
            tmp_path / "review",
            end=END,
            days=5,
            today=END + timedelta(days=1),
        )

    assert not (tmp_path / "review").exists()


def test_final_source_fence_leaves_no_visible_or_pending_pack(tmp_path, monkeypatch):
    window = tuple(END - timedelta(days=offset) for offset in range(4, -1, -1))
    log_dir = tmp_path / "logs"
    _ready_days(log_dir, window)
    real_export = wr.export_workload_day
    calls = 0

    def change_source_after_export(*args, **kwargs):
        nonlocal calls
        result = real_export(*args, **kwargs)
        calls += 1
        if calls == len(window):
            marker = al.analysis_paths(log_dir, window[0])[1]
            marker.write_text("invalid\n", encoding="utf-8")
            marker.chmod(0o600)
        return result

    monkeypatch.setattr(wr, "export_workload_day", change_source_after_export)
    output_dir = tmp_path / "review"
    with pytest.raises(ValueError, match="changed"):
        wr.create_weekly_review_pack(
            log_dir,
            output_dir,
            end=END,
            days=5,
            today=END + timedelta(days=1),
        )

    assert list(output_dir.iterdir()) == []


def test_weekly_window_rejects_active_day_and_unsupported_size(tmp_path):
    with pytest.raises(ValueError, match="5 or 7"):
        wr.create_weekly_review_pack(
            tmp_path / "logs",
            tmp_path / "review",
            end=END,
            days=6,
            today=END + timedelta(days=1),
        )
    with pytest.raises(ValueError, match="completed"):
        wr.create_weekly_review_pack(
            tmp_path / "logs",
            tmp_path / "review",
            end=END,
            days=5,
            today=END,
        )


def test_weekly_window_status_is_payload_free_and_reports_each_state(tmp_path):
    end = date(2026, 8, 29)
    ready = end - timedelta(days=1)
    invalid = end
    _ready_days(tmp_path / "logs", (ready,))
    invalid_path = al.analysis_paths(tmp_path / "logs", invalid)[1]
    invalid_path.write_text("private captured content", encoding="utf-8")
    invalid_path.chmod(0o600)

    status = wr.weekly_window_status(
        tmp_path / "logs",
        end,
        5,
        today=end + timedelta(days=1),
    )

    assert status.days == 5
    assert status.pack_name == "weekly_review_2026-08-25_2026-08-29_5d"
    assert [item.state for item in status.day_statuses] == [
        "unsupported",
        "unsupported",
        "missing",
        "ready",
        "invalid",
    ]
    assert not status.ready
    assert status.warnings[-1] == "2026-08-29 is invalid."
    assert "private captured content" not in repr(status)


def test_weekly_status_rejects_unsafe_source_mode_without_changing_it(tmp_path):
    day = date(2026, 8, 28)
    sources = _ready_days(tmp_path / "logs", (day,))
    analysis_file = sources[0]
    analysis_file.chmod(0o640)

    status = wr.weekly_window_status(
        tmp_path / "logs",
        day,
        5,
        today=day + timedelta(days=1),
    )

    assert status.day_statuses[-1].state == "unready"
    assert analysis_file.stat().st_mode & 0o777 == 0o640


def test_heartbeat_quality_sorts_out_of_order_timestamps():
    day = date(2026, 8, 28)
    summary = av._heartbeat_summary(
        (_heartbeat(day, 23), _heartbeat(day, 1), _heartbeat(day, 12))
    )

    assert summary == {
        "count": 3,
        "first": "2026-08-28T01:00:00+02:00",
        "last": "2026-08-28T23:00:00+02:00",
        "max_gap_seconds": 39600,
    }
