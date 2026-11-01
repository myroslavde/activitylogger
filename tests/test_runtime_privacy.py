from __future__ import annotations

import signal
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import interleaved_logger as il


@pytest.fixture(autouse=True)
def _reset(reset_logger_state):
    reset_logger_state()
    yield


def test_unknown_frontmost_identity_drops_key():
    with (
        patch.object(il, "_frontmost_app_identity", return_value=None),
        patch.object(il, "sync_secure_field_from_focus", return_value=False),
    ):
        il._state.last_secure_app_pid = None
        il.on_press(SimpleNamespace(char="x", vk=None))
    assert il._current_keystrokes == []
    assert il._pause_secure_app is True


def test_unknown_secure_focus_drops_key_without_queueing():
    with (
        patch.object(il, "_frontmost_app_identity", return_value=(1, "Safari")),
        patch.object(il, "sync_secure_field_from_focus", return_value=None),
        patch.object(il, "_enqueue_ax") as enqueue,
    ):
        il.on_press(SimpleNamespace(char="x", vk=None))
    assert il._current_keystrokes == []
    assert il._pause_secure_field is True
    enqueue.assert_not_called()


def test_cached_clear_focus_is_revalidated_for_every_key():
    il._secure_field_cache = False
    il._secure_field_cache_known = True
    il._secure_field_cache_at = time.monotonic()
    with (
        patch.object(il, "_frontmost_app_identity", return_value=(1, "Safari", "Page")),
        patch.object(il, "sync_secure_field_from_focus", return_value=False) as sync,
    ):
        il.on_press(SimpleNamespace(char="x", vk=None))
        il.on_press(SimpleNamespace(char="y", vk=None))
    assert sync.call_count == 2
    assert il._current_keystrokes == ["x", "y"]


def test_secure_field_refresh_serializes_query_and_commit(monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    calls: list[int] = []

    def status(_element):
        calls.append(threading.get_ident())
        if len(calls) == 1:
            entered.set()
            assert release.wait(2)
        return False

    monkeypatch.setattr(il, "AX_AVAILABLE", True)
    monkeypatch.setattr(il, "AXUIElementCreateSystemWide", lambda: object())
    monkeypatch.setattr(
        il, "AXUIElementCopyAttributeValue", lambda *args: (0, object())
    )
    monkeypatch.setattr(il, "_element_secure_status", status)
    results: list[bool | None] = []
    first = threading.Thread(
        target=lambda: results.append(il.refresh_secure_field_focus(force=True))
    )
    second = threading.Thread(
        target=lambda: results.append(il.refresh_secure_field_focus(force=True))
    )
    first.start()
    assert entered.wait(1)
    second.start()
    time.sleep(0.02)
    assert len(calls) == 1
    release.set()
    first.join(2)
    second.join(2)
    assert results == [False, False]
    assert len(calls) == 2


def test_focus_query_and_pause_commit_are_one_serialized_operation(monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    secure_committed = threading.Event()

    def stale_clear(*, force=False):
        entered.set()
        assert release.wait(2)
        return False

    monkeypatch.setattr(il, "refresh_secure_field_focus", stale_clear)
    clear_thread = threading.Thread(
        target=lambda: il.sync_secure_field_from_focus(force=True)
    )

    def commit_secure():
        with il._secure_field_lock:
            il._mark_secure_field_cache(True)
            il._set_pause(field=True)
        secure_committed.set()

    secure_thread = threading.Thread(target=commit_secure)
    clear_thread.start()
    assert entered.wait(1)
    secure_thread.start()
    time.sleep(0.02)
    assert not secure_committed.is_set()
    release.set()
    clear_thread.join(2)
    secure_thread.join(2)
    assert secure_committed.is_set()
    assert il._pause_secure_field is True


def test_partial_secure_attribute_failure_is_unknown(monkeypatch):
    def copy_attribute(_element, attribute, _unused):
        if attribute == "AXRole":
            return 0, "AXTextField"
        return 1, None

    monkeypatch.setattr(il, "AXUIElementCopyAttributeValue", copy_attribute)
    assert il._element_secure_status(object()) is None


def test_focus_refresh_cannot_overwrite_newer_secure_mark(monkeypatch):
    monkeypatch.setattr(il, "AX_AVAILABLE", True)
    monkeypatch.setattr(il, "AXUIElementCreateSystemWide", lambda: object())
    monkeypatch.setattr(
        il, "AXUIElementCopyAttributeValue", lambda *args: (0, object())
    )

    def stale_result(_element):
        il._mark_secure_field_cache(True)
        return False

    monkeypatch.setattr(il, "_element_secure_status", stale_result)
    assert il.refresh_secure_field_focus(force=True) is True
    assert il._secure_field_cache is True


def test_changed_pid_bypasses_classification_throttle():
    identities = iter([(10, "Safari", "Page"), (10, "Safari", "Page"), (11, "1Password", "Vault")])
    with (
        patch.object(il, "_frontmost_app_identity", side_effect=lambda: next(identities)),
        patch.object(il, "sync_secure_field_from_focus", return_value=False),
    ):
        il.on_press(SimpleNamespace(char="a", vk=None))
        il.on_press(SimpleNamespace(char="b", vk=None))
    assert il._current_keystrokes == []
    assert il._pause_secure_app is True


def test_same_pid_title_change_is_reclassified_immediately():
    identities = iter([(10, "Safari", "Page"), (10, "Safari", "Page"), (10, "Safari", "Bitwarden Login")])
    with (
        patch.object(il, "_frontmost_app_identity", side_effect=lambda: next(identities)),
        patch.object(il, "sync_secure_field_from_focus", return_value=False),
    ):
        il.on_press(SimpleNamespace(char="a", vk=None))
        il.on_press(SimpleNamespace(char="b", vk=None))
    assert il._pause_secure_app is True
    assert il._current_keystrokes == []


def test_frontmost_app_check_is_fully_serialized(monkeypatch):
    entered = threading.Event()
    release = threading.Event()
    calls = 0

    def identity():
        nonlocal calls
        calls += 1
        if calls == 1:
            entered.set()
            assert release.wait(2)
        return 1, "Safari", "Page"

    monkeypatch.setattr(il, "_frontmost_app_identity", identity)
    results: list[tuple[int, str, str] | None] = []
    first = threading.Thread(target=lambda: results.append(il._maybe_pause_secure_app_on_key()))
    second = threading.Thread(target=lambda: results.append(il._maybe_pause_secure_app_on_key()))
    first.start()
    assert entered.wait(1)
    second.start()
    time.sleep(0.02)
    assert calls == 1
    release.set()
    first.join(2)
    second.join(2)
    assert results == [(1, "Safari", "Page"), (1, "Safari", "Page")]
    assert calls == 2


def test_verified_context_clears_fail_closed_app_pause():
    il._state.last_secure_app_pid = None
    il._state.last_secure_app_is_secure = None
    with patch.object(il, "_frontmost_app_identity", return_value=None):
        assert il._maybe_pause_secure_app_on_key() is None
    assert il._pause_secure_app is True
    with patch.object(
        il, "_frontmost_app_identity", return_value=(1, "Safari", "Page")
    ):
        assert il._maybe_pause_secure_app_on_key() == (1, "Safari", "Page")
    assert il._pause_secure_app is False


def test_failed_title_lookup_keeps_title_only_secure_pause(monkeypatch):
    il._state.last_secure_app_pid = 1
    il._state.last_secure_app_context = (1, "Safari", "Bitwarden Login")
    il._state.last_secure_app_is_secure = True
    il._set_pause(app=True)
    monkeypatch.setattr(
        il, "_frontmost_app_identity", lambda: (1, "Safari", None)
    )
    assert il._maybe_pause_secure_app_on_key() is None
    assert il._pause_secure_app is True
    assert il._state.last_secure_app_context == (1, "Safari", "Bitwarden Login")


def test_verified_empty_title_can_clear_prior_title_only_pause(monkeypatch):
    il._state.last_secure_app_pid = 1
    il._state.last_secure_app_context = (1, "Safari", "Bitwarden Login")
    il._state.last_secure_app_is_secure = True
    il._set_pause(app=True)
    monkeypatch.setattr(
        il, "_frontmost_app_identity", lambda: (1, "Safari", "")
    )
    assert il._maybe_pause_secure_app_on_key() == (1, "Safari", "")
    assert il._pause_secure_app is False


def test_empty_resolved_window_context_pauses_globally():
    assert il.apply_resolved_window("", "") is False
    assert il._pause_secure_app is True


def test_ax_title_distinguishes_verified_empty_from_failure(monkeypatch):
    monkeypatch.setattr(
        il,
        "AXUIElementCopyAttributeValue",
        lambda _element, _attribute, _unused: (0, None),
    )
    assert il._ax_window_title(object()) == ""

    monkeypatch.setattr(
        il,
        "AXUIElementCopyAttributeValue",
        lambda _element, _attribute, _unused: (1, None),
    )
    assert il._ax_window_title(object()) is None


def test_stale_window_apply_cannot_clear_newer_secure_pause(monkeypatch):
    first_refresh_entered = threading.Event()
    release_first = threading.Event()
    calls = 0

    def refresh(*, force=False):
        nonlocal calls
        calls += 1
        if calls == 1:
            first_refresh_entered.set()
            assert release_first.wait(2)
        return False

    def identity():
        if threading.current_thread().name == "stale-window":
            return 1, "Safari", "Page"
        return 2, "1Password", "Vault"

    monkeypatch.setattr(il, "refresh_secure_field_focus", refresh)
    monkeypatch.setattr(il, "_frontmost_app_identity", identity)
    results: dict[str, bool] = {}
    stale = threading.Thread(
        name="stale-window",
        target=lambda: results.setdefault(
            "stale", il.apply_resolved_window("Safari", "Page")
        ),
    )
    current = threading.Thread(
        name="secure-window",
        target=lambda: results.setdefault(
            "current", il.apply_resolved_window("1Password", "Vault")
        ),
    )
    stale.start()
    assert first_refresh_entered.wait(1)
    current.start()
    time.sleep(0.02)
    release_first.set()
    stale.join(2)
    current.join(2)
    assert results == {"stale": False, "current": True}
    assert il._pause_secure_app is True
    assert "SECURE APP PAUSED" in il._current_heading


def test_left_and_right_modifier_release_independently():
    if not il.PYNPUT_AVAILABLE:
        pytest.skip("pynput unavailable")
    left = il.keyboard.Key.shift_l
    right = il.keyboard.Key.shift_r
    with (
        patch.object(il, "_frontmost_app_identity", return_value=(1, "Safari")),
        patch.object(il, "sync_secure_field_from_focus", return_value=False),
    ):
        il.on_press(left)
        il.on_press(right)
        il.on_release(left)
        assert "SHIFT" in il._current_modifiers
        il.on_release(right)
    assert "SHIFT" not in il._current_modifiers


def test_clipboard_digest_state_never_retains_plaintext():
    count, digest, event = il._apply_clipboard_change_digest(2, "secret", False, 1, "")
    assert count == 2
    assert digest != "secret"
    assert len(digest) == 64
    assert "secret" in event


def test_click_reservation_preserves_callback_heading(monkeypatch):
    monkeypatch.setattr(il, "AX_AVAILABLE", True)
    context = (1, "Safari", "Page")
    monkeypatch.setattr(il, "_frontmost_app_identity", lambda: context)
    monkeypatch.setattr(il, "sync_secure_field_from_focus", lambda **kwargs: False)
    jobs: list[tuple] = []
    monkeypatch.setattr(il, "_enqueue_ax", lambda job: jobs.append(job) or True)
    il._current_heading = "Before"
    il.on_click(1, 2, object(), True)
    il._current_heading = "After"
    pending_id = jobs[0][3]
    assert il._resolve_pending_click(pending_id, "Button 'OK'", context) is True
    assert il._sections[-1]["heading"] == il.build_heading_body("Safari", "Page")
    assert "Клік" in il._sections[-1]["events"][0]


def test_click_queue_failure_discards_placeholder(monkeypatch):
    monkeypatch.setattr(il, "_frontmost_app_identity", lambda: (1, "Safari"))
    monkeypatch.setattr(il, "sync_secure_field_from_focus", lambda **kwargs: False)
    monkeypatch.setattr(il, "_enqueue_ax", lambda job: False)
    monkeypatch.setattr(il, "_diag_rate_limited", lambda msg: None)
    il.on_click(1, 2, object(), True)
    assert il._pending_clicks == {}
    assert not any(section.get("pending_click") for section in il._sections)


def test_click_context_mismatch_discards_placeholder(monkeypatch):
    identities = iter(
        [(1, "Safari", "Before"), (1, "Safari", "Before"), (2, "Finder", "After"), (2, "Finder", "After")]
    )
    jobs: list[tuple] = []
    monkeypatch.setattr(
        il, "_frontmost_app_identity", lambda: next(identities)
    )
    monkeypatch.setattr(il, "sync_secure_field_from_focus", lambda **kwargs: False)
    monkeypatch.setattr(il, "_enqueue_ax", lambda job: jobs.append(job) or True)
    il.on_click(1, 2, object(), True)
    il._process_click(1, 2, jobs[0][3])
    assert il._pending_clicks == {}
    assert not any(section.get("pending_click") for section in il._sections)


def test_click_revalidates_context_after_ax_enrichment(monkeypatch):
    identities = iter(
        [
            (1, "Safari", "Before"),
            (1, "Safari", "Before"),
            (2, "Finder", "After"),
        ]
    )
    jobs: list[tuple] = []
    element = object()
    monkeypatch.setattr(il, "AX_AVAILABLE", True)
    monkeypatch.setattr(il, "_frontmost_app_identity", lambda: next(identities))
    monkeypatch.setattr(il, "sync_secure_field_from_focus", lambda **kwargs: False)
    monkeypatch.setattr(il, "_enqueue_ax", lambda job: jobs.append(job) or True)
    monkeypatch.setattr(il, "AXUIElementCreateSystemWide", lambda: object())
    monkeypatch.setattr(
        il,
        "AXUIElementCopyElementAtPosition",
        lambda *_args: (0, element),
    )
    monkeypatch.setattr(il, "_element_secure_status", lambda _element: False)

    def attribute(_element, name, _unused):
        if name == "AXRole":
            return 0, "AXButton"
        if name == "AXTitle":
            return 0, "OK"
        return 1, None

    monkeypatch.setattr(il, "AXUIElementCopyAttributeValue", attribute)
    il.on_click(1, 2, object(), True)
    il._process_click(1, 2, jobs[0][3])
    assert il._pending_clicks == {}
    assert not any(section.get("pending_click") for section in il._sections)
    assert not any(
        "Клік" in event
        for section in il._sections
        for event in section.get("events", [])
    )


def test_screen_capture_spanning_pause_is_discarded(monkeypatch):
    monkeypatch.setattr(il, "AX_AVAILABLE", True)
    front_app = SimpleNamespace(processIdentifier=lambda: 1)
    workspace = SimpleNamespace(frontmostApplication=lambda: front_app)
    monkeypatch.setattr(
        il, "NSWorkspace", SimpleNamespace(sharedWorkspace=lambda: workspace)
    )
    monkeypatch.setattr(il, "AXUIElementCreateApplication", lambda pid: object())
    monkeypatch.setattr(
        il, "AXUIElementCopyAttributeValue", lambda *args: (0, object())
    )

    def text_during_pause(_window):
        il._set_pause(field=True)
        il._set_pause(field=False)
        return "sensitive screen"

    monkeypatch.setattr(il, "extract_text", text_during_pause)
    il.scan_screen()
    assert il._current_events == []


def test_url_capture_spanning_pause_is_absorbed(monkeypatch):
    monkeypatch.setattr(il, "BROWSER_URL_CAPTURE", True)
    monkeypatch.setattr(il, "sync_secure_field_from_focus", lambda **_kwargs: False)

    def provider(_app):
        il._set_pause(field=True)
        il._set_pause(field=False)
        return "https://example.test/private"

    il.maybe_capture_browser_url("Safari", url_provider=provider)
    assert il._current_events == []
    assert il._last_emitted_url == "https://example.test/private"


def test_clipboard_read_spanning_pause_is_absorbed(monkeypatch):
    pasteboard = MagicMock()
    pasteboard.changeCount.side_effect = [1, 2, 2]

    def read_text(_kind):
        il._set_pause(field=True)
        il._set_pause(field=False)
        return "sensitive clipboard"

    pasteboard.stringForType_.side_effect = read_text
    waits = iter([False, True])
    monkeypatch.setattr(il, "AX_AVAILABLE", True)
    monkeypatch.setattr(
        il,
        "NSPasteboard",
        SimpleNamespace(generalPasteboard=lambda: pasteboard),
    )
    monkeypatch.setattr(il._stop_event, "wait", lambda _delay: next(waits))
    il.clipboard_checker_loop()
    assert il._current_events == []
    assert il._last_clipboard_digest == il._clipboard_digest("sensitive clipboard")


def test_clipboard_change_during_pause_between_polls_is_absorbed(monkeypatch):
    pasteboard = MagicMock()
    pasteboard.changeCount.side_effect = [1, 2, 2]
    pasteboard.stringForType_.return_value = "copied while paused"
    waits = 0

    def wait(_delay):
        nonlocal waits
        waits += 1
        if waits == 1:
            il._set_pause(field=True)
            il._set_pause(field=False)
            return False
        return True

    monkeypatch.setattr(il, "AX_AVAILABLE", True)
    monkeypatch.setattr(
        il,
        "NSPasteboard",
        SimpleNamespace(generalPasteboard=lambda: pasteboard),
    )
    monkeypatch.setattr(il._stop_event, "wait", wait)
    il.clipboard_checker_loop()
    assert il._current_events == []
    assert il._last_clipboard_digest == il._clipboard_digest("copied while paused")


def test_activitywatch_requests_disable_env_and_redirects(monkeypatch):
    response = MagicMock()
    response.json.return_value = {}
    monkeypatch.setattr(il._aw_session, "get", MagicMock(return_value=response))
    il._find_window_bucket()
    assert il._aw_session.trust_env is False
    assert il._aw_session.get.call_args.kwargs["allow_redirects"] is False


def test_scan_first_enqueue_is_not_debounced():
    il._state.last_ax_scan_mono = None
    assert il._enqueue_ax(("scan",)) is True


def test_ax_extraction_has_process_wide_node_cap(monkeypatch):
    visited: set[int] = set()

    def copy_attribute(element, attribute, _unused):
        visited.add(element)
        if attribute == "AXRole":
            return 0, "AXGroup"
        if attribute == "AXSubrole":
            return 0, None
        if attribute == "AXChildren":
            return 0, [element + 1]
        return 1, None

    monkeypatch.setattr(il, "AX_MAX_DEPTH", 2000)
    monkeypatch.setattr(il.time, "monotonic", lambda: 0.0)
    monkeypatch.setattr(il, "AXUIElementCopyAttributeValue", copy_attribute)
    assert il.extract_text(0) == ""
    assert len(visited) == 1000


def test_clipboard_unchanged_count_does_not_fetch_text(monkeypatch):
    pasteboard = MagicMock()
    pasteboard.changeCount.return_value = 7
    waits = iter([False, True])
    monkeypatch.setattr(il, "AX_AVAILABLE", True)
    monkeypatch.setattr(
        il,
        "NSPasteboard",
        SimpleNamespace(generalPasteboard=MagicMock(return_value=pasteboard)),
    )
    monkeypatch.setattr(il._stop_event, "wait", lambda _delay: next(waits))
    il.clipboard_checker_loop()
    pasteboard.stringForType_.assert_not_called()


@pytest.mark.parametrize(
    ("loop", "event_name"),
    [
        (il.typing_pause_idle_loop, "_key_deadline_changed"),
        (il.scroll_coalesce_idle_loop, "_scroll_deadline_changed"),
        (il.file_writer_loop, "_writer_wakeup"),
    ],
)
def test_worker_rechecks_stop_immediately_after_clearing_wakeup(
    monkeypatch, loop, event_name
):
    class StopOnClear:
        def clear(self):
            il._stop_event.set()

        def wait(self, _timeout=None):
            raise AssertionError("worker waited after shutdown")

        def is_set(self):
            return False

    monkeypatch.setattr(il, event_name, StopOnClear())
    loop()
    assert il._stop_event.is_set()


def test_event_admission_rejects_shutdown():
    il._stop_event.set()
    il.add_event("must not be admitted")
    assert il._current_events == []
    assert il._reserve_pending_click((1, "Safari", "Page")) is None


def test_url_post_io_commit_rejects_shutdown(monkeypatch):
    monkeypatch.setattr(il, "BROWSER_URL_CAPTURE", True)

    def provider(_app):
        il._request_stop()
        return "https://example.test/private"

    il.maybe_capture_browser_url("Safari", url_provider=provider)
    assert il._last_emitted_url is None
    assert il._current_events == []


def test_window_post_io_commit_rejects_shutdown(monkeypatch):
    context = (1, "Safari", "Page")
    monkeypatch.setattr(il, "_frontmost_app_identity", lambda: context)

    def refresh(*, force=False):
        il._request_stop()
        return False

    monkeypatch.setattr(il, "refresh_secure_field_focus", refresh)
    original_heading = il._current_heading
    assert il.apply_resolved_window("Safari", "Page") is False
    assert il._current_heading == original_heading


def test_diagnostic_sanitizer_is_single_line_and_bounded(monkeypatch):
    written: list[str] = []
    monkeypatch.setattr(
        il,
        "_write_to_file",
        lambda _path, lines, append=True: written.extend(lines) is None,
    )
    il._diag("first\nsecond\x00" + "x" * 800)
    assert len(written) == 1
    assert written[0].count("\n") == 1
    assert "\x00" not in written[0]
    payload = written[0].split("] ", 1)[1].rstrip("\n")
    assert len(payload) <= il._DIAG_MAX_CHARS


def test_diagnostics_log_exception_category_not_raw_text(monkeypatch):
    messages: list[str] = []
    il._diag_last.clear()
    monkeypatch.setattr(il, "_diag", messages.append)
    monkeypatch.setattr(
        il._aw_session,
        "get",
        MagicMock(side_effect=RuntimeError("secret title https://private.invalid")),
    )
    assert il._find_window_bucket() is None
    assert messages
    assert "RuntimeError" in messages[0]
    assert "secret title" not in messages[0]
    assert "private.invalid" not in messages[0]


def test_scroll_section_cap_flushes_outside_state_lock(tmp_path, monkeypatch):
    monkeypatch.setattr(il, "SCROLL_COALESCE_ENABLED", True)
    monkeypatch.setattr(il, "SCROLL_COALESCE_MS", 10)
    monkeypatch.setattr(il, "MAX_SECTIONS", 1)
    il.on_scroll_tick(dx=0, dy=-1, now=0.0, app="Safari", heading="Safari")
    with patch.object(il, "flush_to_file", return_value=True) as flush:
        assert il.check_scroll_coalesce_idle(now=0.02) is True
    flush.assert_called_once()


def test_listener_shutdown_joins_both_and_reports_timeout(monkeypatch):
    stopped: list[str] = []
    joined: list[tuple[str, float]] = []

    class Listener:
        def __init__(self, name, alive=False):
            self.name = name
            self.alive = alive

        def stop(self):
            stopped.append(self.name)

        def join(self, timeout):
            joined.append((self.name, timeout))

        def is_alive(self):
            return self.alive

    monkeypatch.setattr(il, "_diag", lambda msg: None)
    first = Listener("mouse")
    second = Listener("keyboard")
    assert il._stop_and_join_listeners(first, second) is True
    assert stopped == ["mouse", "keyboard"]
    assert joined == [
        ("mouse", il.WORKER_JOIN_TIMEOUT_SEC),
        ("keyboard", il.WORKER_JOIN_TIMEOUT_SEC),
    ]
    assert il._stop_and_join_listeners(Listener("stuck", alive=True)) is False


def test_signal_stop_records_only_privacy_neutral_signal_name():
    il._shutdown_reason = None
    il._request_stop(signal.SIGTERM, None)
    assert il._shutdown_reason == "signal=SIGTERM"
    assert il._stop_event.is_set()


def test_main_handles_signal_during_config_before_startup_and_cleans_up(monkeypatch):
    events: list[str] = []
    installed: dict[int, object] = {}
    previous = {signal.SIGTERM: object(), signal.SIGINT: object()}

    monkeypatch.setattr(il.os, "umask", lambda _mode: 0o22)
    monkeypatch.setattr(signal, "getsignal", lambda signum: previous[signum])

    def set_handler(signum, handler):
        if handler is il._request_stop:
            installed[signum] = handler
            events.append(f"install {signal.Signals(signum).name}")
        else:
            assert handler is previous[signum]
            events.append(f"restore {signal.Signals(signum).name}")

    monkeypatch.setattr(signal, "signal", set_handler)

    def load_during_signal(*, warn):
        del warn
        events.append("load config")
        assert installed[signal.SIGTERM] is il._request_stop
        assert installed[signal.SIGINT] is il._request_stop
        installed[signal.SIGTERM](signal.SIGTERM, None)
        return object()

    monkeypatch.setattr(il, "load_config", load_during_signal)
    apply_config = MagicMock(side_effect=AssertionError("startup continued"))
    monkeypatch.setattr(il, "apply_config", apply_config)
    monkeypatch.setattr(
        il,
        "_stop_and_join_listeners",
        lambda *_listeners: events.append("stop listeners") or True,
    )
    monkeypatch.setattr(
        il, "_discard_all_pending_clicks", lambda: events.append("discard clicks")
    )
    monkeypatch.setattr(
        il,
        "flush_scroll_burst_on_shutdown",
        lambda: events.append("flush scroll"),
    )
    monkeypatch.setattr(
        il, "flush_to_file", lambda: events.append("flush file") or True
    )
    monkeypatch.setattr(
        il, "_close_instance_lock", lambda: events.append("close lock")
    )
    publish = MagicMock()
    monkeypatch.setattr(il, "_publish_runtime_state", publish)
    monkeypatch.setattr(il, "_diag", lambda message: events.append(f"diag {message}"))

    assert il.main() == 0
    apply_config.assert_not_called()
    publish.assert_not_called()
    assert "close lock" not in events
    assert "discard clicks" not in events
    assert "flush scroll" not in events
    assert "flush file" not in events
    shutdown = "diag shutdown requested signal=SIGTERM"
    assert events.count(shutdown) == 1
    assert events.index("install SIGINT") < events.index("load config")
    assert events.index("stop listeners") < events.index(shutdown)
    assert events.index(shutdown) < events.index("restore SIGTERM")
    assert events.index(shutdown) < events.index("restore SIGINT")


@pytest.mark.parametrize("startup", ["bad_config", "duplicate", "owns_lock"])
def test_main_publishes_status_only_after_owning_instance_lock(
    tmp_path, monkeypatch, isolated_operator_home, startup,
):
    from dataclasses import replace

    import operator_controls as controls
    from config import ConfigError, default_config

    state = controls.write_runtime_state(
        running=True, manual_paused=True, capture_paused=True, control_revision=17,
    )
    assert state.is_relative_to(isolated_operator_home)
    previous_bytes = state.read_bytes()
    monkeypatch.setattr(il.os, "umask", lambda _mode: 0o22)
    monkeypatch.setattr(signal, "getsignal", lambda _signum: object())
    monkeypatch.setattr(signal, "signal", lambda *_args: None)
    monkeypatch.setattr(il, "_diag", lambda _message: None)
    monkeypatch.setattr(il, "_diag_rate_limited", lambda _message: None)
    cfg = replace(default_config(home=tmp_path), log_dir=tmp_path / "logs")

    def load(*, warn):
        if startup == "bad_config":
            raise ConfigError("synthetic invalid config")
        return cfg

    monkeypatch.setattr(il, "load_config", load)
    monkeypatch.setattr(il, "acquire_instance_lock", lambda: startup == "owns_lock")
    close_lock = MagicMock()
    monkeypatch.setattr(il, "_close_instance_lock", close_lock)
    flush = MagicMock(return_value=True)
    marker = MagicMock()
    monkeypatch.setattr(il, "flush_to_file", flush)
    monkeypatch.setattr(il, "_append_analysis_marker_locked", marker)
    monkeypatch.setattr(il, "_initialize_analysis_persistence", MagicMock(side_effect=OSError("synthetic startup fault")))

    assert il.main() == 1
    if startup == "owns_lock":
        close_lock.assert_called_once_with()
        flush.assert_called_once_with()
        marker.assert_any_call("session_stop", "normal")
        final_state = controls.read_runtime_state()
        assert final_state["running"] is False
        assert final_state["manual_paused"] is True
        assert final_state["control_revision"] == 0
        assert state.read_bytes() != previous_bytes
    else:
        close_lock.assert_not_called()
        flush.assert_not_called()
        marker.assert_not_called()
        assert state.read_bytes() == previous_bytes
