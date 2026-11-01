from __future__ import annotations

import os
import time
from dataclasses import replace
from datetime import date, datetime, timedelta, timezone

import pytest

import analysis_log as al
import interleaved_logger as il


def _record(payload: str, *, second: int = 0, heading: str = "App - Window") -> al.AnalysisRecord:
    return al.AnalysisRecord(
        heading=heading,
        kind="type",
        payload=payload,
        captured_at=datetime(2026, 8, 23, 10, 0, second, tzinfo=timezone.utc),
        trigger="file_flush",
        section_captured_at=datetime(2026, 8, 23, 10, 1, tzinfo=timezone.utc),
        section_start=second == 1,
    )


def test_analysis_round_trip_is_lossless_and_only_exact_adjacent_runs_merge():
    records = (
        _record("  raw\n```\n## heading\n", second=1),
        _record("  raw\n```\n## heading\n", second=2),
        _record("different", second=3),
        _record("  raw\n```\n## heading\n", second=4),
    )
    rendered, heading = al.render_records(records)
    assert heading == "App - Window"
    assert rendered.count("type x2") == 1
    assert al.parse_records(
        rendered, day=date(2026, 8, 23), strict=False
    ) == records


def test_unicode_line_separators_cannot_escape_one_record():
    record = _record("a\u0085b\u2028c\u2029d", second=1)
    rendered, _heading = al.render_records((record,))
    assert len([line for line in rendered.splitlines() if line.startswith("- ")]) == 1
    assert al.parse_records(
        rendered, day=date(2026, 8, 23), strict=False
    ) == (record,)


def test_strict_parser_rejects_unrecognized_visible_text(tmp_path):
    record = _record("work", second=1)
    body, _heading = al.render_records((record,))
    text = (
        "# Work Log - 2026-08-23\n\n"
        "> format: activitylogger-analysis-v1\n"
        "> generated locally by ActivityLogger test\n"
        + body
        + "GARBAGE\n"
    )
    with pytest.raises(ValueError, match="unexpected"):
        al.parse_records(text)


def test_compact_times_preserve_midnight_and_offset_changes():
    plus_two = timezone(timedelta(hours=2))
    plus_one = timezone(timedelta(hours=1))
    midnight = al.AnalysisRecord(
        "App",
        "type",
        "before midnight",
        datetime(2026, 8, 23, 23, 59, 59, tzinfo=plus_two),
        "file_flush",
        datetime(2026, 8, 24, 0, 0, 1, tzinfo=plus_two),
        True,
    )
    offset_change = al.AnalysisRecord(
        "App",
        "event",
        "offset changed",
        datetime(2026, 10, 25, 2, 59, 59, tzinfo=plus_two),
        "file_flush",
        datetime(2026, 10, 25, 2, 0, 1, tzinfo=plus_one),
        True,
    )
    for day_value, record in (
        (date(2026, 8, 24), midnight),
        (date(2026, 10, 25), offset_change),
    ):
        rendered, _heading = al.render_records((record,))
        assert al.parse_records(rendered, day=day_value, strict=False) == (record,)


def test_snapshot_is_immutable_and_keeps_payload_whitespace():
    event = al.CapturedEvent("legacy", kind="type", payload="  exact\n")
    section = {
        "heading": "App - Window",
        "events": [event],
        "timestamp": "10:00:00",
        "captured_at": datetime(2026, 8, 23, 10, tzinfo=timezone.utc),
        "_trigger": "file_flush",
        "privacy_generation": 99,
    }
    snapshot = al.snapshot_sections([section])[0]
    section["events"].clear()
    assert snapshot.events[0].payload == "  exact\n"
    assert not hasattr(snapshot, "privacy_generation")
    with pytest.raises(AttributeError):
        event.kind = "click"


def test_private_framed_journal_and_analysis_have_the_same_records(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    section = al.SectionSnapshot(
        heading="App - Window",
        timestamp="10:00:00",
        captured_at=datetime(2026, 8, 23, 10, tzinfo=timezone.utc),
        trigger="file_flush",
        events=(
            al.EventSnapshot(
                kind="clipboard",
                payload="line 1\u0085line 2\u2028line 3\u2029\n",
                legacy="legacy",
                captured_at=datetime(2026, 8, 23, 10, tzinfo=timezone.utc),
            ),
        ),
    )
    trial = al.prepare_trial_intent(
        log_dir, section.captured_at.date(), (section,), "test"
    )
    assert trial is not None
    _batch_id, records = trial
    al.commit_trial_batch(
        log_dir, section.captured_at.date(), records, "test", None
    )
    analysis_path, invalid_path = al.shadow_paths(
        log_dir, section.captured_at.date()
    )
    parsed = al.parse_records(analysis_path.read_text(encoding="utf-8"))
    intents = al.read_intents(al.intent_path(log_dir, section.captured_at.date()))
    assert parsed == records
    assert intents == ((trial[0], len(records), al._records_digest(records)),)
    assert not invalid_path.exists()
    assert analysis_path.stat().st_mode & 0o777 == 0o600
    assert analysis_path.parent.stat().st_mode & 0o777 == 0o700


def test_day_validator_allows_no_session_markers_when_coverage_is_disabled(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    captured = datetime(2026, 8, 22, 12, tzinfo=timezone.utc)
    section = al.SectionSnapshot(
        heading="App",
        timestamp="12:00:00",
        captured_at=captured,
        trigger="file_flush",
        events=(al.EventSnapshot("type", "work", "work", captured),),
    )
    trial = al.prepare_trial_intent(log_dir, captured.date(), (section,), "test")
    assert trial is not None
    al.commit_trial_batch(
        log_dir, captured.date(), trial[1], "test", None
    )
    (log_dir / "daily_log_2026-08-22.md").write_text("legacy\n" * 100)
    result = al.validate_trial(
        log_dir,
        captured.date(),
        today=date(2026, 8, 23),
        min_byte_reduction=-1.0,
        min_coverage_hours=0.0,
    )
    assert result.ok, result.errors


def test_day_validator_counts_midnight_boundaries_as_heartbeat_gaps(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    day = date(2026, 8, 22)
    events = tuple(
        al.EventSnapshot(
            "heartbeat",
            "",
            "",
            datetime(2026, 8, 22, hour, 30, tzinfo=timezone.utc),
            hour + 1,
        )
        for hour in range(23)
    )
    section = al.SectionSnapshot(
        heading="App",
        timestamp="00:00:00",
        captured_at=events[0].captured_at,
        trigger="timeline",
        events=events,
    )
    trial = al.prepare_trial_intent(log_dir, day, (section,), "test")
    assert trial is not None
    al.commit_trial_batch(log_dir, day, trial[1], "test", None)
    next_event = al.EventSnapshot(
        "heartbeat",
        "",
        "",
        datetime(2026, 8, 23, 1, 30, tzinfo=timezone.utc),
        1,
    )
    next_section = al.SectionSnapshot(
        heading="App",
        timestamp="01:30:00",
        captured_at=next_event.captured_at,
        trigger="timeline",
        events=(next_event,),
    )
    next_trial = al.prepare_trial_intent(
        log_dir, day + timedelta(days=1), (next_section,), "test"
    )
    assert next_trial is not None
    al.commit_trial_batch(
        log_dir, day + timedelta(days=1), next_trial[1], "test", None
    )
    (log_dir / "daily_log_2026-08-22.md").write_text("legacy\n" * 1000)
    result = al.validate_trial(
        log_dir,
        day,
        today=date(2026, 8, 23),
        min_byte_reduction=-1.0,
    )
    assert not result.ok
    assert "heartbeat gap 3.0h exceeds 2.0h" in result.errors


def test_day_validator_requires_post_midnight_continuity(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    day = date(2026, 8, 22)

    def commit_heartbeats(record_day, hours):
        events = tuple(
            al.EventSnapshot(
                "heartbeat",
                "",
                "",
                datetime.combine(
                    record_day,
                    datetime.min.time(),
                    tzinfo=timezone.utc,
                )
                + timedelta(hours=hour, minutes=30),
                hour + 1,
            )
            for hour in hours
        )
        section = al.SectionSnapshot(
            heading="App",
            timestamp=events[0].captured_at.strftime("%H:%M:%S"),
            captured_at=events[0].captured_at,
            trigger="timeline",
            events=events,
        )
        trial = al.prepare_trial_intent(log_dir, record_day, (section,), "test")
        assert trial is not None
        al.commit_trial_batch(log_dir, record_day, trial[1], "test", None)

    commit_heartbeats(day, range(24))
    (log_dir / "daily_log_2026-08-22.md").write_text("legacy\n" * 1000)
    failed = al.validate_trial(
        log_dir,
        day,
        today=date(2026, 8, 23),
        min_byte_reduction=-1.0,
    )
    assert "missing next-day heartbeat proof" in failed.errors
    commit_heartbeats(day + timedelta(days=1), range(1))
    passed = al.validate_trial(
        log_dir,
        day,
        today=date(2026, 8, 23),
        min_byte_reduction=-1.0,
    )
    assert passed.ok, passed.errors


def test_day_validator_rejects_restart_before_next_heartbeat(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    day = date(2026, 8, 22)
    base = datetime(2026, 8, 22, 0, 30, tzinfo=timezone.utc)
    heartbeats = tuple(
        al.EventSnapshot("heartbeat", "", "", base + timedelta(hours=hour), hour + 1)
        for hour in range(24)
    )
    target = al.SectionSnapshot(
        "App", "00:30:00", base, "timeline", heartbeats
    )
    trial = al.prepare_trial_intent(log_dir, day, (target,), "test")
    assert trial is not None
    al.commit_trial_batch(log_dir, day, trial[1], "test", None)
    next_at = datetime(2026, 8, 23, 0, 30, tzinfo=timezone.utc)
    next_events = (
        al.EventSnapshot("session_start", "", "", next_at, 1),
        al.EventSnapshot("heartbeat", "", "", next_at, 2),
    )
    next_section = al.SectionSnapshot(
        "App", "00:30:00", next_at, "timeline", next_events
    )
    next_trial = al.prepare_trial_intent(
        log_dir, day + timedelta(days=1), (next_section,), "test"
    )
    assert next_trial is not None
    al.commit_trial_batch(
        log_dir, day + timedelta(days=1), next_trial[1], "test", None
    )
    (log_dir / "daily_log_2026-08-22.md").write_text("legacy\n" * 1000)
    result = al.validate_trial(
        log_dir,
        day,
        today=date(2026, 8, 23),
        min_byte_reduction=-1.0,
    )
    assert "next-day session changed before heartbeat proof" in result.errors


def test_day_validator_rejects_partial_next_day_analysis(tmp_path):
    log_dir = tmp_path / "logs"
    log_dir.mkdir()
    day = date(2026, 8, 22)
    base = datetime(2026, 8, 22, 0, 30, tzinfo=timezone.utc)
    target_events = tuple(
        al.EventSnapshot("heartbeat", "", "", base + timedelta(hours=hour), hour + 1)
        for hour in range(24)
    )
    target = al.SectionSnapshot(
        "App", "00:30:00", base, "timeline", target_events
    )
    trial = al.prepare_trial_intent(log_dir, day, (target,), "test")
    assert trial is not None
    al.commit_trial_batch(log_dir, day, trial[1], "test", None)
    next_at = datetime(2026, 8, 23, 0, 30, tzinfo=timezone.utc)
    next_events = (
        al.EventSnapshot("session_start", "", "", next_at, 1),
        al.EventSnapshot("heartbeat", "", "", next_at, 2),
    )
    next_section = al.SectionSnapshot(
        "App", "00:30:00", next_at, "timeline", next_events
    )
    next_trial = al.prepare_trial_intent(
        log_dir, day + timedelta(days=1), (next_section,), "test"
    )
    assert next_trial is not None
    heartbeat_only = replace(next_trial[1][1], section_start=True)
    al.commit_trial_batch(
        log_dir, day + timedelta(days=1), (heartbeat_only,), "test", None
    )
    (log_dir / "daily_log_2026-08-22.md").write_text("legacy\n" * 1000)
    result = al.validate_trial(
        log_dir,
        day,
        today=date(2026, 8, 23),
        min_byte_reduction=-1.0,
    )
    assert "next-day analysis differs from intents" in result.errors


def test_duplicate_trial_intent_is_idempotent(tmp_path):
    root = tmp_path / "shadow"
    root.mkdir()
    path = root / "intents.journal"
    kwargs = {"header": "# h\n", "body": "body\n", "batch_id": "a1", "count": 1}
    al.append_batch(path, **kwargs)
    al.append_batch(path, **kwargs)
    assert len(al.read_batches(path)) == 1


def test_incomplete_tail_is_removed_without_zero_filling(tmp_path):
    root = tmp_path / "shadow"
    root.mkdir()
    path = root / "log.md"
    al.append_batch(path, header="# h\n", body="body\n", batch_id="a1", count=1)
    valid = path.read_bytes()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fd, b"<!-- batch-start id=broken")
    finally:
        os.close(fd)
    with pytest.raises(OSError, match="incomplete"):
        al.append_batch(path, header="# h\n", body="next\n", batch_id="a2", count=1)
    assert path.read_bytes() == valid


def test_shadow_failure_does_not_fail_authoritative_legacy_write(
    tmp_path, monkeypatch, reset_logger_state
):
    reset_logger_state()
    monkeypatch.setattr(il, "_analysis_only_day", lambda _day: False)
    monkeypatch.setattr(il, "ANALYSIS_SHADOW_ENABLED", True)
    monkeypatch.setattr(
        il, "commit_trial_batch", lambda *args: (_ for _ in ()).throw(OSError())
    )
    with il._lock:
        il._current_events.append(al.CapturedEvent("hello", kind="type", payload="hello"))
    assert il.flush_to_file() is True
    assert "hello" in next((tmp_path / "logs").glob("daily_log_*.md")).read_text()
    assert next((tmp_path / "logs" / "analysis_shadow").glob("analysis_invalid_*.txt"))


def test_trial_intent_precedes_legacy_and_analysis(
    monkeypatch, reset_logger_state
):
    reset_logger_state()
    monkeypatch.setattr(il, "_analysis_only_day", lambda _day: False)
    order: list[str] = []
    monkeypatch.setattr(
        il,
        "prepare_trial_intent",
        lambda *args: order.append("intent") or ("id", ()),
    )
    monkeypatch.setattr(
        il, "_write_section_group", lambda *args: order.append("legacy") or True
    )
    monkeypatch.setattr(
        il, "_write_analysis_group", lambda *args: order.append("analysis")
    )
    with il._lock:
        il._current_events.append(al.CapturedEvent("work", kind="type", payload="work"))
    assert il.flush_to_file() is True
    assert order == ["intent", "legacy", "analysis"]


def test_focus_and_idle_transitions_are_shadow_only(
    tmp_path, monkeypatch, reset_logger_state
):
    reset_logger_state()
    monkeypatch.setattr(il, "_analysis_only_day", lambda _day: False)
    monkeypatch.setattr(il, "_analysis_runtime_enabled", True)
    monkeypatch.setattr(il, "SYSTEM_IDLE_AVAILABLE", True)
    il.apply_heading_change("Editor - Report")
    marker_day = il._analysis_markers[-1]["captured_at"]
    marker_at = marker_day.replace(hour=10, minute=10, second=0, microsecond=0)
    il.observe_system_idle(301, now=marker_at)
    il.observe_system_idle(350, now=marker_at + timedelta(minutes=1))
    il.observe_system_idle(0, now=marker_at + timedelta(minutes=2))
    assert il.flush_to_file() is True
    analysis = next(
        (tmp_path / "logs" / "analysis_shadow").glob("analysis_log_*.md")
    )
    kinds = [record.kind for record in al.parse_records(analysis.read_text())]
    assert kinds == ["focus", "idle_start", "idle_end"]
    assert not list((tmp_path / "logs").glob("daily_log_*.md"))


def test_paused_timeline_marker_uses_private_context(
    monkeypatch, reset_logger_state
):
    reset_logger_state()
    monkeypatch.setattr(il, "_analysis_runtime_enabled", True)
    with il._lock:
        il._current_heading = "Password Manager - Secret"
        il._is_paused = True
        il._append_analysis_marker_locked("heartbeat")
        marker = il._analysis_markers[-1]
    assert marker["heading"] == "[PRIVATE CONTEXT]"


def test_privacy_pause_transitions_are_explicit_and_neutral(
    monkeypatch, reset_logger_state
):
    reset_logger_state()
    monkeypatch.setattr(il, "_analysis_runtime_enabled", True)
    with il._lock:
        il._current_heading = "Password Manager - Secret"
        il._pause_secure_field = True
        il._recompute_paused_locked()
        il._pause_secure_field = False
        il._recompute_paused_locked()
        markers = list(il._analysis_markers)
    assert [marker["events"][0].kind for marker in markers] == [
        "privacy_pause_start",
        "privacy_pause_end",
    ]
    assert {marker["heading"] for marker in markers} == {"[PRIVATE CONTEXT]"}


def test_timeline_marker_order_does_not_split_legacy_section(
    tmp_path, monkeypatch, reset_logger_state
):
    reset_logger_state()
    monkeypatch.setattr(il, "_analysis_only_day", lambda _day: False)
    monkeypatch.setattr(il, "_analysis_runtime_enabled", True)
    with il._lock:
        il._add_event_locked(al.CapturedEvent("first", kind="type", payload="first"))
        il._append_analysis_marker_locked("heartbeat")
        il._add_event_locked(al.CapturedEvent("second", kind="type", payload="second"))
    assert il.flush_to_file() is True
    legacy = next((tmp_path / "logs").glob("daily_log_*.md")).read_text()
    assert legacy.count("## App - Window") == 1
    analysis = next(
        (tmp_path / "logs" / "analysis_shadow").glob("analysis_log_*.md")
    )
    records = al.parse_records(analysis.read_text())
    assert [(record.kind, record.payload) for record in records] == [
        ("type", "first"),
        ("heartbeat", ""),
        ("type", "second"),
    ]


@pytest.fixture
def local_zone(monkeypatch):
    def use(name: str) -> None:
        monkeypatch.setenv("TZ", name)
        time.tzset()

    yield use
    monkeypatch.undo()
    time.tzset()


def _heartbeat(stamp: datetime) -> al.AnalysisRecord:
    return al.AnalysisRecord("App - Window", "heartbeat", "", stamp, "timeline", stamp, True)


def test_heartbeat_gap_ignores_unfinished_day_tail_and_counts_completed_tail(local_zone):
    local_zone("Europe/Berlin")
    beats = tuple(_heartbeat(datetime(2026, 8, 28, hour, 30).astimezone()) for hour in range(11))
    active = al.heartbeat_summary(beats, now=datetime(2026, 8, 28, 12).astimezone())
    completed = al.heartbeat_summary(beats, now=datetime(2026, 8, 29, 1).astimezone())

    assert active["max_gap_seconds"] == 3600
    assert completed["max_gap_seconds"] == 13.5 * 3600
    assert al.LARGE_HEARTBEAT_GAP_SECONDS == 9000


def test_heartbeat_day_boundaries_follow_local_dst_midnight(local_zone):
    local_zone("Europe/Berlin")
    # 2026-10-25: CEST midnight at the start, CET after the 03:00 switch, so the day is 25 h.
    cet = timezone(timedelta(hours=1))
    beats = tuple(_heartbeat(datetime(2026, 10, 25, hour, 30, tzinfo=cet)) for hour in range(3, 19))
    summary = al.heartbeat_summary(beats, now=datetime(2026, 10, 27, 12).astimezone())

    # Tail 18:30 CET to next CET midnight is 5.5 h; a fixed 24 h day would give 4.5 h.
    assert summary["max_gap_seconds"] == 5.5 * 3600


def test_heartbeat_edges_keep_record_offset_when_process_zone_differs(local_zone):
    local_zone("America/New_York")
    plus_two = timezone(timedelta(hours=2))
    beats = tuple(_heartbeat(datetime(2026, 8, 28, hour, 30, tzinfo=plus_two)) for hour in range(9, 18))
    summary = al.heartbeat_summary(beats, now=datetime(2026, 8, 30, 12).astimezone())

    # Midnight in +02:00 (not New York): head 9.5 h beats the 6.5 h tail. New York midnight gave 12.5 h.
    assert summary["max_gap_seconds"] == 9.5 * 3600
