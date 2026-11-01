"""Capture-context and storage-fault regression checks with synthetic native data."""
from __future__ import annotations

import queue
import signal
from datetime import date, datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import analysis_log as al
import interleaved_logger as il


@pytest.fixture(autouse=True)
def _reset(reset_logger_state):
    reset_logger_state(browser_url_capture=True, scroll_coalesce_enabled=True)


@pytest.fixture
def native(monkeypatch):
    current = [1]
    apps = {1: ("Safari", "First"), 2: ("Editor", "Second"), 3: ("Passwords", "Private")}
    reads = []

    def front():
        pid = current[0]
        return SimpleNamespace(processIdentifier=lambda: pid, localizedName=lambda: apps[pid][0])

    def attribute(element, name, _):
        if element == "system" and name == "AXFocusedUIElement":
            return 0, ("input", current[0])
        if isinstance(element, int) and name in {"AXFocusedWindow", "AXMainWindow"}:
            return 0, ("window", element)
        if isinstance(element, tuple):
            kind, pid = element
            if name == "AXRole":
                return 0, {"window": "AXWindow", "input": "AXTextArea", "note": "AXStaticText"}[kind]
            if name == "AXTitle":
                return 0, apps[pid][1]
            if name == "AXChildren":
                return 0, [("note", pid)] if kind == "window" else []
            if name == "AXValue":
                reads.append(pid)
                return 0, "synthetic note"
        return 0, ""

    monkeypatch.setattr(il, "AX_AVAILABLE", True)
    monkeypatch.setattr(il, "NSWorkspace", SimpleNamespace(sharedWorkspace=lambda: SimpleNamespace(frontmostApplication=front)))
    monkeypatch.setattr(il, "AXUIElementCreateApplication", lambda pid: pid)
    monkeypatch.setattr(il, "AXUIElementCreateSystemWide", lambda: "system")
    monkeypatch.setattr(il, "AXUIElementCopyAttributeValue", attribute)
    monkeypatch.setattr(il, "_frontmost_app_identity", lambda: (current[0], *apps[current[0]]))
    return current, reads


@pytest.mark.parametrize("new_pid", [2, 3])
def test_queued_scan_rejects_changed_native_context_before_read(native, monkeypatch, new_pid):
    current, reads = native
    assert il.apply_resolved_window("Safari", "First")
    assert il._ax_jobs.qsize() == 1
    current[0] = new_pid
    get = il._ax_jobs.get

    def next_job(timeout=None):
        try:
            return get(block=False)
        except queue.Empty:
            il._stop_event.set()
            raise

    monkeypatch.setattr(il._ax_jobs, "get", next_job)
    il._ax_worker_loop()
    assert reads == []
    assert il._current_events == []


def test_input_updates_heading_and_retains_prior_keys(native, monkeypatch):
    current, _ = native
    assert il.apply_resolved_window("Safari", "First")
    il.on_press(SimpleNamespace(char="a", vk=None))
    current[0] = 2
    il.on_press(SimpleNamespace(char="b", vk=None))
    assert il._sections[0]["heading"] == il.build_heading_body("Safari", "First")
    assert il._sections[0]["events"][0].payload == "a"
    il.on_click(1, 2, object(), True)
    reserved = next(iter(il._pending_clicks.values()))
    assert reserved["heading"] == il.build_heading_body("Editor", "Second")
    assert il._sections[-2]["events"][0].payload == "b"

    monkeypatch.setattr(il, "refresh_secure_field_focus", lambda **_kwargs: True)
    assert il.apply_resolved_window("Editor", "Second")
    assert "SECURE FIELD PAUSED" in il._current_heading
    monkeypatch.setattr(il, "refresh_secure_field_focus", lambda **_kwargs: False)
    il._secure_field_cache_known = False
    il.on_press(SimpleNamespace(char="c", vk=None))
    assert il._current_keystrokes == ["c"]
    assert il._current_heading == il.build_heading_body("Editor", "Second")


def test_empty_native_title_preserves_only_same_context_enrichment(monkeypatch):
    context = [(1, "Safari", "")]
    monkeypatch.setattr(il, "_frontmost_app_identity", lambda: context[0])
    monkeypatch.setattr(il, "refresh_secure_field_focus", lambda **_kwargs: False)
    assert il.apply_resolved_window("Safari", "Enriched title")
    il.on_press(SimpleNamespace(char="a", vk=None))
    assert il.apply_resolved_window("Safari", "Enriched title")
    il.on_press(SimpleNamespace(char="b", vk=None))
    enriched = il.build_heading_body("Safari", "Enriched title")
    assert il._current_heading == enriched
    assert il._current_keystrokes == ["a", "b"] and not il._sections
    context[0] = (2, "Safari", "")
    il.on_press(SimpleNamespace(char="c", vk=None))
    assert il._sections[0]["heading"] == enriched
    assert il._sections[0]["events"][0].payload == "ab"
    assert il._current_heading == il.build_heading_body("Safari", "")
    assert il._current_keystrokes == ["c"]


def test_callback_admission_expires_when_same_heading_moves_to_another_pid(monkeypatch):
    context = [(1, "Safari", "Shared title")]
    monkeypatch.setattr(il, "_frontmost_app_identity", lambda: context[0])
    monkeypatch.setattr(il, "refresh_secure_field_focus", lambda **_kwargs: False)
    first = il._capture_context()
    assert first == context[0]
    with il._lock:
        assert il._capture_context_matches_locked(first)
    context[0] = (2, "Safari", "Shared title")
    second = il._capture_context()
    with il._lock:
        assert il._current_heading == il.build_heading_body("Safari", "Shared title")
        assert not il._capture_context_matches_locked(first)
        assert il._capture_context_matches_locked(second)


@pytest.mark.parametrize("channel", ["key", "click", "scroll", "screen", "url", "clipboard"])
def test_each_capture_channel_checks_excluded_app(native, monkeypatch, channel):
    current, reads = native
    current[0] = 3
    if channel == "key":
        il.on_press(SimpleNamespace(char="x", vk=None))
    elif channel == "click":
        il.on_click(1, 2, object(), True)
    elif channel == "scroll":
        il.on_scroll(1, 2, 0, -1)
    elif channel == "screen":
        il.scan_screen()
    elif channel == "url":
        provider = Mock(return_value="https://example.test/")
        il.maybe_capture_browser_url("Safari", url_provider=provider)
        provider.assert_not_called()
    else:
        counts = iter([1, 2, 2])
        pasteboard = SimpleNamespace(changeCount=lambda: next(counts), types=lambda: [], stringForType_=lambda _: "synthetic copy")
        waits = iter([False, True])
        monkeypatch.setattr(il, "NSPasteboard", SimpleNamespace(generalPasteboard=lambda: pasteboard))
        monkeypatch.setattr(il._stop_event, "wait", lambda _: next(waits))
        il.clipboard_checker_loop()
        assert il._last_clipboard_digest == il._clipboard_digest("synthetic copy")
    assert reads == []
    assert il._current_keystrokes == []
    assert il._current_events == []
    assert il._sections == []
    assert il._scroll_burst is None


def test_async_url_and_clipboard_changes_recheck_native_context(native, monkeypatch):
    current, _ = native

    def provider(_app):
        current[0] = 2
        return "https://example.test/changed"

    il.maybe_capture_browser_url("Safari", url_provider=provider)
    assert il._current_events == []
    assert il._last_emitted_url == "https://example.test/changed"
    current[0] = 1
    counts = iter([1, 2, 2])
    def copied(_kind):
        current[0] = 3
        return "synthetic copy"
    pasteboard = SimpleNamespace(changeCount=lambda: next(counts), types=lambda: [], stringForType_=copied)
    waits = iter([False, True])
    monkeypatch.setattr(il, "NSPasteboard", SimpleNamespace(generalPasteboard=lambda: pasteboard))
    monkeypatch.setattr(il._stop_event, "wait", lambda _: next(waits))
    il.clipboard_checker_loop()
    assert il._current_events == []


def test_click_wakeups_do_not_move_scheduled_flush(native, monkeypatch):
    clock = [0.0]
    flushed = []
    original = il.flush_to_file

    def flush():
        flushed.append(clock[0])
        return original()

    def wait(timeout):
        if clock[0] >= 90:
            il._stop_event.set()
            return True
        clock[0] += min(1.0, timeout)
        context = il._capture_context()
        pending = il._reserve_pending_click(context)
        assert il._resolve_pending_click(pending, "Button", context)
        return True

    monkeypatch.setattr(il.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(il._writer_wakeup, "wait", wait)
    monkeypatch.setattr(il, "flush_to_file", flush)
    il.file_writer_loop()
    assert flushed == [30.0, 60.0, 90.0]


def test_storage_failure_bounds_new_admission_and_recovers_exact_data(native, monkeypatch):
    clock = [0.0]
    il._analysis_runtime_enabled = True
    il.on_press(SimpleNamespace(char="a", vk=None))
    il.add_event(al.CapturedEvent("saved", kind="clipboard", payload="saved"))
    il.on_scroll(1, 2, 0, -2)
    prepare = il.prepare_authoritative_transaction
    failing = Mock(side_effect=OSError("synthetic storage failure"))
    monkeypatch.setattr(il.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(il, "prepare_authoritative_transaction", failing)
    assert not il.flush_to_file()
    accepted = tuple(il._sections)
    accepted_markers = tuple(il._analysis_markers)
    assert il._storage_blocked and not il._is_paused
    for number in range(50):
        il.on_press(SimpleNamespace(char="x", vk=None))
        il.add_event("new")
        il.on_scroll_tick(dx=0, dy=-1, now=float(number))
        il.maybe_record_analysis_heartbeat(float(number) * 4000)
        assert not il.flush_to_file()
    assert failing.call_count == 1
    assert tuple(il._sections) == accepted
    assert not il._current_keystrokes and not il._current_events
    assert tuple(il._analysis_markers) == accepted_markers and il._scroll_burst is None
    clock[0] = il._file_flush_deadline
    assert not il.flush_to_file()
    assert failing.call_count == 2
    monkeypatch.setattr(il, "prepare_authoritative_transaction", prepare)
    clock[0] = il._file_flush_deadline
    assert il.flush_to_file()
    assert not il._storage_blocked
    assert il.flush_to_file()
    day = datetime.now().astimezone().date()
    records = al.parse_records(al.analysis_paths(il.LOG_DIR, day)[0].read_text(), day=day)
    assert [r.payload for r in records if r.kind in {"type", "clipboard"}] == ["a", "saved"]
    assert len([r for r in records if r.kind == "scroll"]) == 1
    assert len([r for r in records if r.payload.startswith("storage_gap start=")]) == 1
    assert il._pending_storage_gap is None


def test_storage_block_preserves_an_accepted_click_reservation(native, monkeypatch):
    context = il._capture_context()
    pending_id = il._reserve_pending_click(context)
    il._storage_blocked = True
    monkeypatch.setattr(il, "AXUIElementCopyElementAtPosition", lambda *_args: (0, ("input", 1)))
    il._process_click(1, 2, pending_id)
    assert pending_id not in il._pending_clicks
    assert len(il._sections) == 1
    assert il._sections[0]["events"][0].kind == "click"
    assert il._storage_blocked and not il._is_paused


def test_later_healthy_day_reconciles_existing_days_and_skips_invalid(monkeypatch):
    friday = date(2026, 9, 4)
    saturday = date(2026, 9, 5)
    monday = date(2026, 9, 7)
    for day in (friday, saturday):
        stamp = datetime.combine(day, datetime.min.time(), timezone.utc).replace(hour=12)
        record = al.AnalysisRecord("Editor", "type", "saved", stamp, "file_flush", stamp, True)
        al.prepare_authoritative_transaction(il.LOG_DIR, [(day, [record])], il.__version__)
        al.commit_authoritative_transaction(il.LOG_DIR)
    al.mark_invalid(il.LOG_DIR, saturday, "synthetic invalid day")
    il._analysis_runtime_enabled = True
    il._append_analysis_marker_locked("heartbeat", captured_at=datetime(2026, 9, 7, 12, tzinfo=timezone.utc))
    assert il.flush_to_file()
    assert al.validate_day_ready(il.LOG_DIR, friday)
    assert not al.ready_path(il.LOG_DIR, saturday).exists()
    assert not al.analysis_paths(il.LOG_DIR, date(2026, 9, 6))[0].exists()
    assert not al.ready_path(il.LOG_DIR, monday).exists()
    scan = Mock(side_effect=AssertionError("history was rescanned on the same healthy day"))
    monkeypatch.setattr(al, "completed_analysis_days", scan)
    il._reconcile_completed_days(monday, set())
    scan.assert_not_called()


def test_runtime_state_retry_keeps_pause_and_honors_deadline(monkeypatch):
    clock = [0.0]
    publish = Mock(side_effect=[False, False, True, True])
    monkeypatch.setattr(il.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(il, "_publish_runtime_state", publish)
    il._request_manual_control(signal.SIGUSR1)
    il._apply_pending_manual_control()
    for _ in range(20):
        il._apply_pending_manual_control()
    assert publish.call_count == 1 and il._pause_manual
    clock[0] = 1.0
    il._apply_pending_manual_control()
    assert il._manual_state_retry_at == 3.0
    clock[0] = 3.0
    il._apply_pending_manual_control()
    assert il._pause_manual and il._manual_control_pending is None
    il._request_manual_control(signal.SIGUSR2)
    il._apply_pending_manual_control()
    assert not il._pause_manual and publish.call_count == 4


def test_runtime_reason_codes_separate_storage_from_privacy(monkeypatch):
    states = []
    monkeypatch.setattr(il, "write_runtime_state", lambda **kwargs: states.append(kwargs))
    il._storage_blocked = True
    assert il._publish_runtime_state(running=True)
    assert not il._is_paused and il.is_paused()
    assert states[0]["capture_paused"] is True
    assert states[0]["storage_blocked"] is True
    assert states[0]["pause_reasons"] == ("storage",)
