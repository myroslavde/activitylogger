"""Secure-field pause recheck and wall-clock sleep markers (AX and time patched)."""

from __future__ import annotations

from datetime import datetime

import pytest

import interleaved_logger as il


@pytest.fixture(autouse=True)
def _reset(reset_logger_state):
    reset_logger_state()
    yield


def _kinds() -> list[str]:
    return [marker["events"][0].kind for marker in il._analysis_markers]


def _verified_focus(monkeypatch, *, secure: bool) -> None:
    monkeypatch.setattr(il, "AX_AVAILABLE", True)
    monkeypatch.setattr(il, "AXUIElementCreateSystemWide", lambda: object())
    monkeypatch.setattr(il, "AXUIElementCopyAttributeValue", lambda *args: (0, object()))
    monkeypatch.setattr(il, "_element_secure_status", lambda _element: secure)


def test_recheck_clears_field_pause_on_verified_non_secure_focus(monkeypatch):
    _verified_focus(monkeypatch, secure=False)
    il._set_pause(field=True)
    il.recheck_secure_field_pause(now_mono=100.0)
    assert il._pause_secure_field is False
    assert il._is_paused is False


def test_recheck_keeps_field_pause_on_secure_focus(monkeypatch):
    _verified_focus(monkeypatch, secure=True)
    il._set_pause(field=True)
    il.recheck_secure_field_pause(now_mono=100.0)
    assert il._pause_secure_field is True


def test_unverified_focus_keeps_pause_and_logs_attribute_error_only(monkeypatch):
    messages: list[str] = []
    monkeypatch.setattr(il, "_diag_rate_limited", messages.append)
    monkeypatch.setattr(il, "AX_AVAILABLE", True)
    monkeypatch.setattr(il, "AXUIElementCreateSystemWide", lambda: object())

    def copy_attribute(_element, attribute, _unused):
        if attribute == "AXFocusedUIElement":
            return 0, object()
        if attribute == "AXRole":
            return -25212, None
        return 0, "SECRET WINDOW TITLE"

    monkeypatch.setattr(il, "AXUIElementCopyAttributeValue", copy_attribute)
    il._set_pause(field=True)
    il.recheck_secure_field_pause(now_mono=100.0)
    assert il._pause_secure_field is True
    assert messages == ["secure field focus unverified [AXRole err=-25212]"]


def test_recheck_runs_only_while_field_paused_and_at_most_every_three_seconds(monkeypatch):
    calls: list[dict] = []
    monkeypatch.setattr(
        il, "sync_secure_field_from_focus", lambda **kwargs: calls.append(kwargs)
    )
    il.recheck_secure_field_pause(now_mono=100.0)
    assert calls == []
    il._set_pause(field=True)
    il.recheck_secure_field_pause(now_mono=100.0)
    il.recheck_secure_field_pause(now_mono=102.9)
    assert calls == [{"force": True}]
    il.recheck_secure_field_pause(now_mono=103.0)
    assert len(calls) == 2
    il._stop_event.set()
    il.recheck_secure_field_pause(now_mono=110.0)
    assert len(calls) == 2


def _enable_analysis(monkeypatch) -> None:
    monkeypatch.setattr(il, "_analysis_runtime_enabled", True)


def test_wall_clock_jump_marks_suspension_and_forces_heartbeat(monkeypatch):
    _enable_analysis(monkeypatch)
    il.observe_wall_clock_gap(now_wall=1_000.0)
    il.maybe_record_analysis_heartbeat(now_mono=500.0)
    assert _kinds() == ["heartbeat"]
    il.observe_wall_clock_gap(now_wall=1_010.0)  # 10 s gap: no marker
    assert _kinds() == ["heartbeat"]
    il.observe_wall_clock_gap(now_wall=4_610.0)  # one hour since the last check
    assert _kinds() == ["heartbeat", "idle_start", "idle_end"]
    start = il._analysis_markers[1]["events"][0].payload
    assert start == datetime.fromtimestamp(1_010.0).astimezone().isoformat()
    assert il._analysis_idle_active is False
    il.maybe_record_analysis_heartbeat(now_mono=501.0)  # 1 s later: only forced beats land
    assert _kinds()[-1] == "heartbeat"


def test_long_check_interval_is_not_mistaken_for_sleep(monkeypatch):
    _enable_analysis(monkeypatch)
    monkeypatch.setattr(il, "WINDOW_CHECK_SEC", 300)
    il.observe_wall_clock_gap(now_wall=1_000.0)
    il.observe_wall_clock_gap(now_wall=1_300.0)  # normal 300 s cycle: no marker
    assert _kinds() == []
    il.observe_wall_clock_gap(now_wall=2_200.0)  # 900 s cycle: 600 s beyond the interval
    assert _kinds() == ["idle_start", "idle_end"]


def test_wall_clock_gap_while_idle_keeps_idle_state_and_forces_heartbeat(monkeypatch):
    _enable_analysis(monkeypatch)
    monkeypatch.setattr(il, "_analysis_idle_active", True)
    il.observe_wall_clock_gap(now_wall=1_000.0)
    il.maybe_record_analysis_heartbeat(now_mono=500.0)
    il.observe_wall_clock_gap(now_wall=5_000.0)
    assert _kinds() == ["heartbeat"]
    assert il._analysis_idle_active is True
    il.maybe_record_analysis_heartbeat(now_mono=501.0)
    assert _kinds() == ["heartbeat", "heartbeat"]


def test_wall_clock_gap_is_noop_when_analysis_is_disabled():
    il.observe_wall_clock_gap(now_wall=1_000.0)
    il.observe_wall_clock_gap(now_wall=9_000.0)
    assert il._analysis_markers == []
    assert il._wall_clock_last is None


def test_window_checker_loop_writes_suspension_pair_then_forced_heartbeat(monkeypatch):
    _enable_analysis(monkeypatch)
    monkeypatch.setattr(il, "observe_system_idle", lambda *args, **kwargs: None)
    monkeypatch.setattr(il, "resolve_window", lambda: ("App", "Title"))
    monkeypatch.setattr(il, "process_window_check_cycle", lambda **kwargs: True)
    clock = [1_000.0]
    monkeypatch.setattr(il.time, "time", lambda: clock[0])
    waits = [0]

    def fake_wait(_timeout):
        waits[0] += 1
        if waits[0] == 2:
            clock[0] = 5_000.0  # the Mac slept between cycle one and cycle two
        return waits[0] >= 3

    monkeypatch.setattr(il._stop_event, "wait", fake_wait)
    il.window_checker_loop()
    assert _kinds() == ["heartbeat", "idle_start", "idle_end", "heartbeat"]
