#!/usr/bin/env python3
"""
Interleaved Work Log - macOS (v4)
Логує клавіатуру (з хоткеями), кліки, екран, буфер обміну + ЗАХИСТ ПАРОЛІВ.
"""

from __future__ import annotations

import fcntl
import hashlib
import itertools
import os
import pwd
import queue
import signal
import stat
import sys
import threading
import time
from datetime import date, datetime, timedelta
from pathlib import Path

import requests

from analysis_log import (
    ANALYSIS_ONLY_START_DAY,
    CapturedEvent,
    SectionSnapshot,
    authoritative_transaction_pending,
    commit_authoritative_transaction,
    commit_trial_batch,
    mark_invalid,
    prepare_authoritative_transaction,
    prepare_trial_intent,
    publish_day_ready,
    records_from_sections,
    recover_authoritative_transaction,
    snapshot_sections,
    validate_authoritative_day,
)

try:
    from pynput import keyboard, mouse

    PYNPUT_AVAILABLE = True
except ImportError:
    keyboard = None  # type: ignore
    mouse = None  # type: ignore
    PYNPUT_AVAILABLE = False

try:
    from AppKit import NSWorkspace, NSPasteboard, NSStringPboardType
    from ApplicationServices import (
        AXUIElementCreateSystemWide,
        AXUIElementCopyElementAtPosition,
        AXUIElementCopyAttributeValue,
        AXUIElementCreateApplication,
    )

    AX_AVAILABLE = True
except ImportError:
    AX_AVAILABLE = False

try:
    from Quartz import (
        CGEventSourceSecondsSinceLastEventType,
        kCGAnyInputEventType,
        kCGEventSourceStateCombinedSessionState,
    )

    SYSTEM_IDLE_AVAILABLE = True
except ImportError:
    SYSTEM_IDLE_AVAILABLE = False

from browser_url import (
    apply_url_observation,
    get_frontmost_browser_url,
    is_browser_app,
    set_unsafe_full_browser_urls,
)
from config import (
    AppConfig,
    ConfigError,
    default_config,
    ensure_log_dir,
    load_config,
    startup_diag_line,
)
from markdown_format import (
    CAPTURE_TRIGGERS,
    format_markdown_fenced_text,
    format_section_timestamp_line,
    sanitize_markdown_inline,
)
from operator_controls import initial_manual_pause, write_runtime_state
from scroll_coalesce import (
    ScrollBurst,
    accumulate as scroll_accumulate,
    discard_burst as scroll_discard,
    format_burst_line,
    mouse_listener_kwargs,
    should_flush as scroll_should_flush,
)
from window_titles import (
    FALLBACK_HEADING,
    build_heading_body,
    merge_native_and_aw,
)

__version__ = "4.6.1"
ANALYSIS_SHADOW_ENABLED = True

# Config mirrors - seeded from AppConfig defaults (single literal source: config.default_config).
_DEFAULTS = default_config()
AW_BASE_URL = _DEFAULTS.activitywatch_base_url
WINDOW_CHECK_SEC = _DEFAULTS.window_check_sec
FLUSH_INTERVAL_SEC = _DEFAULTS.flush_interval_sec
TYPING_PAUSE_SEC = _DEFAULTS.typing_pause_sec
SECURE_FIELD_CACHE_SEC = _DEFAULTS.secure_field_cache_sec
SECURE_APP_CHECK_SEC = _DEFAULTS.secure_app_check_sec
AX_QUEUE_MAXSIZE = _DEFAULTS.ax_queue_maxsize
AX_MAX_DEPTH = _DEFAULTS.ax_max_depth
AX_MAX_CHILDREN = _DEFAULTS.ax_max_children
AX_SCAN_DEBOUNCE_SEC = _DEFAULTS.ax_scan_debounce_sec
SCREEN_COMPARE_MAX_CHARS = _DEFAULTS.screen_compare_max_chars
SECURE_APPS: set[str] = set(_DEFAULTS.secure_apps)
ACTIVITYWATCH_ENRICHER = _DEFAULTS.activitywatch_enricher
AW_BACKOFF_SEC = _DEFAULTS.aw_backoff_sec
BROWSER_URL_CAPTURE = _DEFAULTS.browser_url_capture
CAPTURE_TRIGGERS_ENABLED = _DEFAULTS.capture_triggers_enabled
SCROLL_COALESCE_ENABLED = _DEFAULTS.scroll_coalesce_enabled
SCROLL_COALESCE_MS = _DEFAULTS.scroll_coalesce_ms
MAX_KEYSTROKES = _DEFAULTS.max_keystrokes
MAX_EVENTS = _DEFAULTS.max_events
MAX_SECTIONS = _DEFAULTS.max_sections

if PYNPUT_AVAILABLE:
    _MODIFIER_KEYS = {
        keyboard.Key.cmd: "CMD",
        keyboard.Key.cmd_l: "CMD",
        keyboard.Key.cmd_r: "CMD",
        keyboard.Key.ctrl: "CTRL",
        keyboard.Key.ctrl_l: "CTRL",
        keyboard.Key.ctrl_r: "CTRL",
        keyboard.Key.alt: "OPT",
        keyboard.Key.alt_l: "OPT",
        keyboard.Key.alt_r: "OPT",
        keyboard.Key.alt_gr: "OPT",
        keyboard.Key.shift: "SHIFT",
        keyboard.Key.shift_l: "SHIFT",
        keyboard.Key.shift_r: "SHIFT",
    }
else:
    _MODIFIER_KEYS = {}


# Import is side-effect free. Startup and apply_config create the directory.
LOG_DIR = _DEFAULTS.log_dir


class LoggerState:
    """Mutable capture state. Buffer lists are identity-aliased at module level for tests."""

    __slots__ = (
        "aw_backoff_until",
        "last_ax_scan_mono",
        "last_secure_app_check_mono",
        "last_secure_app_pid",
        "last_secure_app_context",
        "last_secure_app_is_secure",
        "config",
        "current_keystrokes",
        "current_events",
        "sections",
    )

    def __init__(self) -> None:
        self.aw_backoff_until: float = 0.0
        self.last_ax_scan_mono: float | None = None
        self.last_secure_app_check_mono: float = 0.0
        self.last_secure_app_pid: int | None = None
        self.last_secure_app_context: tuple[int, str, str | None] | None = None
        self.last_secure_app_is_secure: bool | None = None
        self.config: AppConfig | None = None
        self.current_keystrokes: list[str] = []
        self.current_events: list[str] = []
        self.sections: list[dict] = []

    def reset_runtime_controls(self) -> None:
        self.aw_backoff_until = 0.0
        self.last_ax_scan_mono = None
        self.last_secure_app_check_mono = 0.0
        self.last_secure_app_pid = None
        self.last_secure_app_context = None
        self.last_secure_app_is_secure = None

    def clear_capture_buffers(self) -> None:
        """Clear in place so module aliases keep the same list objects."""
        self.current_keystrokes.clear()
        self.current_events.clear()
        self.sections.clear()


_state = LoggerState()
_lock = threading.RLock()
_flush_lock = threading.Lock()
_io_lock = threading.Lock()
_current_heading = ""
_heading_native_context: tuple[int, str, str] | None = None
# Same list objects as LoggerState (tests mutate il._current_* / il._sections).
_current_keystrokes = _state.current_keystrokes
_current_events = _state.current_events
_sections = _state.sections

_last_screen_text = ""
_last_clipboard_count = 0
_last_clipboard_text = ""
_last_clipboard_digest = ""
_last_clipboard_privacy_generation = 0
_last_emitted_url: str | None = None

_pause_secure_app = False
_pause_secure_field = False
_pause_manual = False
_pause_review_center = False
_is_paused = False
_privacy_generation = 0
_manual_control_revision = 0
_manual_control_pending: bool | None = None
_manual_state_dirty = threading.Event()
_manual_state_retry_at = 0.0
_manual_state_retry_delay = 0.0
_current_modifiers: set[str] = set()
_physical_modifiers: set[object] = set()
_modifier_counts: dict[str, int] = {}

# F3 typing-pause: last buffer-mutating key activity (monotonic). None = idle inert.
_last_key_activity_mono: float | None = None
_last_key_flush_cause: str | None = None
_key_flush_hook = None  # optional Callable[[str], None] for tests

_secure_field_cache = False
_secure_field_cache_at = 0.0
_secure_field_cache_known = False
_secure_field_generation = 0
_secure_field_recheck_mono: float | None = None
_secure_field_lock = threading.RLock()
_secure_app_lock = threading.RLock()

_window_bucket: str | None = None
_ax_jobs: queue.Queue = queue.Queue(maxsize=AX_QUEUE_MAXSIZE)
_scan_pending = False
_ax_meta_lock = threading.Lock()
_instance_lock_file = None
_stop_event = threading.Event()
_shutdown_reason: str | None = None
_key_deadline_changed = threading.Event()
_scroll_deadline_changed = threading.Event()
_writer_wakeup = threading.Event()
_fatal_worker_event = threading.Event()
_flush_failed = False
_storage_blocked = False
_storage_gap_started_at: datetime | None = None
_pending_storage_gap: tuple[datetime, datetime] | None = None
_file_flush_deadline: float | None = None
_file_retry_delay = 0.0
_readiness_reconciled_day: date | None = None
_readiness_candidates: set[date] = set()
_click_sequence = itertools.count(1)
_analysis_sequence = itertools.count(1)
_pending_clicks: dict[int, dict] = {}
_analysis_heading_by_day: dict[date, str | None] = {}
_analysis_markers: list[dict] = []
_analysis_marker_overflow_days: set[date] = set()
_analysis_runtime_enabled = False
_analysis_idle_active = False
_analysis_last_heartbeat_mono: float | None = None
_wall_clock_last: float | None = None
_window_apply_generation = 0
CLICK_RESOLVE_TIMEOUT_SEC = 2.0
WORKER_JOIN_TIMEOUT_SEC = 6.0
WORKLOAD_IDLE_SEC = 300.0
MAX_ANALYSIS_MARKERS = 2000
ANALYSIS_HEARTBEAT_SEC = 3600.0
SECURE_FIELD_RECHECK_SEC = 3.0
SUSPEND_GAP_SEC = 120.0

_diag_last: dict[str, float] = {}
_DIAG_MIN_INTERVAL = _DEFAULTS.diag_min_interval_sec
_DIAG_MAX_CHARS = 500

# F6 scroll coalesce - open burst (None = no open burst)
_scroll_burst: ScrollBurst | None = None
_scroll_diag_emitted = False

# Alias for tests that stub Listener construction
mouse_Listener = mouse.Listener if PYNPUT_AVAILABLE else None

_aw_session = requests.Session()
_aw_session.trust_env = False


def _active_config() -> AppConfig:
    """Runtime config: last apply_config, else built-in defaults."""
    return _state.config if _state.config is not None else _DEFAULTS


# Module attribute used by tests (updated in apply_config). Same object as _state.config.
_APP_CONFIG: AppConfig | None = None


def rebind_capture_buffers() -> None:
    """Point module buffer aliases at LoggerState lists (after tests reassign globals)."""
    global _current_keystrokes, _current_events, _sections
    _current_keystrokes = _state.current_keystrokes
    _current_events = _state.current_events
    _sections = _state.sections


def apply_config(cfg: AppConfig) -> None:
    """Apply loaded AppConfig to module mirrors and LoggerState (startup / tests)."""
    global AW_BASE_URL, WINDOW_CHECK_SEC, FLUSH_INTERVAL_SEC, TYPING_PAUSE_SEC
    global SECURE_FIELD_CACHE_SEC, SECURE_APP_CHECK_SEC
    global AX_QUEUE_MAXSIZE, AX_MAX_DEPTH, AX_MAX_CHILDREN, AX_SCAN_DEBOUNCE_SEC
    global SCREEN_COMPARE_MAX_CHARS
    global SECURE_APPS, LOG_DIR, _DIAG_MIN_INTERVAL, _ax_jobs, _APP_CONFIG
    global ACTIVITYWATCH_ENRICHER, AW_BACKOFF_SEC, BROWSER_URL_CAPTURE
    global CAPTURE_TRIGGERS_ENABLED, SCROLL_COALESCE_ENABLED, SCROLL_COALESCE_MS
    global MAX_KEYSTROKES, MAX_EVENTS, MAX_SECTIONS

    AW_BASE_URL = cfg.activitywatch_base_url
    WINDOW_CHECK_SEC = cfg.window_check_sec
    FLUSH_INTERVAL_SEC = cfg.flush_interval_sec
    TYPING_PAUSE_SEC = cfg.typing_pause_sec
    SECURE_FIELD_CACHE_SEC = cfg.secure_field_cache_sec
    SECURE_APP_CHECK_SEC = cfg.secure_app_check_sec
    AX_QUEUE_MAXSIZE = cfg.ax_queue_maxsize
    AX_MAX_DEPTH = cfg.ax_max_depth
    AX_MAX_CHILDREN = cfg.ax_max_children
    AX_SCAN_DEBOUNCE_SEC = cfg.ax_scan_debounce_sec
    SCREEN_COMPARE_MAX_CHARS = cfg.screen_compare_max_chars
    SECURE_APPS = set(cfg.secure_apps)
    _DIAG_MIN_INTERVAL = cfg.diag_min_interval_sec
    ACTIVITYWATCH_ENRICHER = cfg.activitywatch_enricher
    AW_BACKOFF_SEC = cfg.aw_backoff_sec
    BROWSER_URL_CAPTURE = cfg.browser_url_capture
    set_unsafe_full_browser_urls(cfg.unsafe_full_browser_urls)
    CAPTURE_TRIGGERS_ENABLED = cfg.capture_triggers_enabled
    SCROLL_COALESCE_ENABLED = cfg.scroll_coalesce_enabled
    SCROLL_COALESCE_MS = cfg.scroll_coalesce_ms
    MAX_KEYSTROKES = cfg.max_keystrokes
    MAX_EVENTS = cfg.max_events
    MAX_SECTIONS = cfg.max_sections
    LOG_DIR = ensure_log_dir(cfg.log_dir)
    _APP_CONFIG = cfg
    _state.config = cfg
    rebind_capture_buffers()
    # Recreate AX queue if capacity changed and queue is idle (startup / tests).
    if _ax_jobs.maxsize != AX_QUEUE_MAXSIZE and _ax_jobs.empty():
        _ax_jobs = queue.Queue(maxsize=AX_QUEUE_MAXSIZE)


def _recompute_paused_locked() -> None:
    global _is_paused, _last_key_activity_mono, _privacy_generation, _scroll_burst
    was_paused = _is_paused
    newly = (
        _pause_secure_app
        or _pause_secure_field
        or _pause_manual
        or _pause_review_center
    )
    if newly and not was_paused:
        _privacy_generation += 1
        _current_modifiers.clear()
        _physical_modifiers.clear()
        _modifier_counts.clear()
        _current_keystrokes.clear()
        # Cancel pending typing-pause idle; do not flush secrets into events.
        _last_key_activity_mono = None
        _key_deadline_changed.set()
        # F6: discard open scroll burst on pause enter (no flush, no seal).
        _scroll_burst = scroll_discard(_scroll_burst)
        _scroll_deadline_changed.set()
    _is_paused = newly
    if newly != was_paused:
        _append_analysis_marker_locked(
            "privacy_pause_start" if newly else "privacy_pause_end",
            heading_override="[PRIVATE CONTEXT]",
        )


def is_paused() -> bool:
    with _lock:
        return _is_paused or _storage_blocked


def _set_pause(
    *,
    app: bool | None = None,
    field: bool | None = None,
    manual: bool | None = None,
    review: bool | None = None,
) -> None:
    global _pause_secure_app, _pause_secure_field, _pause_manual
    global _pause_review_center
    with _lock:
        before = (
            _pause_secure_app,
            _pause_secure_field,
            _pause_manual,
            _pause_review_center,
        )
        if app is not None:
            _pause_secure_app = app
        if field is not None:
            _pause_secure_field = field
        if manual is not None:
            _pause_manual = manual
        if review is not None:
            _pause_review_center = review
        _recompute_paused_locked()
        after = (
            _pause_secure_app,
            _pause_secure_field,
            _pause_manual,
            _pause_review_center,
        )
        if after != before:
            _manual_state_dirty.set()


def _mark_secure_field_cache(focused: bool) -> None:
    global _secure_field_cache, _secure_field_cache_at
    global _secure_field_cache_known, _secure_field_generation
    with _secure_field_lock:
        _secure_field_generation += 1
        _secure_field_cache = focused
        _secure_field_cache_known = True
        _secure_field_cache_at = time.monotonic()


def _is_secure_app_name(app: str, title: str = "") -> bool:
    app_l = (app or "").casefold()
    title_l = (title or "").casefold()
    return any(sec.casefold() in app_l for sec in SECURE_APPS) or any(
        sec.casefold() in title_l for sec in SECURE_APPS
    )


def _element_looks_secure(element) -> bool:
    return _element_secure_status(element) is True


def _element_secure_status(element) -> bool | None:
    try:
        err, role = AXUIElementCopyAttributeValue(element, "AXRole", None)
        role_str = str(role) if err == 0 and role is not None else ""
        role_known = err == 0 and role is not None
        subrole_err, subrole = AXUIElementCopyAttributeValue(element, "AXSubrole", None)
        subrole_str = str(subrole) if subrole_err == 0 and subrole is not None else ""
        if not role_known:
            _diag_rate_limited(f"secure field focus unverified [AXRole err={err}]")
            return None
        secure = (
            "SecureTextField" in role_str
            or "SecureTextField" in subrole_str
            or "Password" in role_str
        )
        if secure:
            return True
        if subrole_err != 0 and role_str in {"AXTextField", "AXTextArea"}:
            _diag_rate_limited(
                f"secure field focus unverified [AXSubrole err={subrole_err} role={role_str}]"
            )
            return None
        return False
    except Exception as e:
        _diag_rate_limited(f"secure field focus unverified [{_exception_category(e)}]")
        return None


def _frontmost_app_identity() -> tuple[int, str, str | None] | None:
    """Return the frontmost process identity, or None when it cannot be verified."""
    if not AX_AVAILABLE:
        return None
    try:
        front_app = NSWorkspace.sharedWorkspace().frontmostApplication()
        if not front_app:
            return None
        name = front_app.localizedName()
        pid = int(front_app.processIdentifier())
        if pid <= 0 or not name:
            return None
        app_elem = AXUIElementCreateApplication(pid)
        return pid, str(name), _ax_window_title(app_elem)
    except Exception:
        return None


def _frontmost_app_name() -> str:
    """Compatibility helper for diagnostics and tests."""
    identity = _frontmost_app_identity()
    return identity[1] if identity is not None else ""


def _ax_window_title(app_elem) -> str | None:
    """Return a verified title, empty when absent, or None on lookup failure."""
    window = None
    window_lookup_succeeded = False
    for attr in ("AXFocusedWindow", "AXMainWindow"):
        try:
            err, candidate = AXUIElementCopyAttributeValue(app_elem, attr, None)
            if err == 0:
                window_lookup_succeeded = True
            if err == 0 and candidate:
                window = candidate
                break
        except Exception:
            continue
    if window is None:
        try:
            err, windows = AXUIElementCopyAttributeValue(app_elem, "AXWindows", None)
            if err == 0:
                window_lookup_succeeded = True
            if err == 0 and windows:
                window = windows[0]
        except Exception:
            window = None
    if not window:
        return "" if window_lookup_succeeded else None
    try:
        err, title = AXUIElementCopyAttributeValue(window, "AXTitle", None)
        if err == 0:
            return str(title) if title else ""
    except Exception:
        pass
    return None


def get_native_window() -> tuple[str, str]:
    """Frontmost app (NSWorkspace) + window title (AX). Returns (app, title)."""
    if not AX_AVAILABLE:
        return "", ""
    try:
        front_app = NSWorkspace.sharedWorkspace().frontmostApplication()
        if not front_app:
            return "", ""
        name = front_app.localizedName()
        app = str(name) if name else ""
        app_elem = AXUIElementCreateApplication(front_app.processIdentifier())
        title = _ax_window_title(app_elem)
        return app, title if title is not None else ""
    except Exception:
        return "", ""


def refresh_secure_field_focus(force: bool = False) -> bool | None:
    """Return secure state, with None meaning focus could not be verified."""
    global _secure_field_cache, _secure_field_cache_at, _secure_field_cache_known
    if not AX_AVAILABLE:
        return None
    with _secure_field_lock:
        now = time.monotonic()
        if (
            not force
            and _secure_field_cache_known
            and (now - _secure_field_cache_at) < SECURE_FIELD_CACHE_SEC
        ):
            return _secure_field_cache
        generation = _secure_field_generation
        try:
            system_wide = AXUIElementCreateSystemWide()
            err, element = AXUIElementCopyAttributeValue(
                system_wide, "AXFocusedUIElement", None
            )
            if err != 0 or not element:
                _diag_rate_limited(
                    f"secure field focus unverified [AXFocusedUIElement err={err}]"
                )
                return None
            focused = _element_secure_status(element)
            if focused is None:
                return None
        except Exception as e:
            _diag_rate_limited(f"secure field focus unverified [{_exception_category(e)}]")
            return None
        if _stop_event.is_set():
            return None
        if generation != _secure_field_generation:
            return _secure_field_cache if _secure_field_cache_known else None
        _secure_field_cache = focused
        _secure_field_cache_known = True
        _secure_field_cache_at = time.monotonic()
    return focused


def sync_secure_field_from_focus(*, force: bool = False) -> bool | None:
    """Stale cached False must never clear an active field pause (P0)."""
    with _secure_field_lock:
        focused = refresh_secure_field_focus(force=force)
        if _stop_event.is_set():
            return None
        if focused is None:
            _set_pause(field=True)
            return None
        if focused:
            _set_pause(field=True)
            return True
        if force:
            _set_pause(field=False)
            return False
        return is_paused()


def recheck_secure_field_pause(now_mono: float | None = None) -> None:
    """While the field pause is on, re-verify focus at most every SECURE_FIELD_RECHECK_SEC.

    Takes no lock itself. sync_secure_field_from_focus takes _secure_field_lock, then _lock,
    the same order as apply_resolved_window and the key path.
    """
    global _secure_field_recheck_mono
    with _lock:
        paused = _pause_secure_field
    if not paused or _stop_event.is_set():
        return
    current = time.monotonic() if now_mono is None else now_mono
    if (
        _secure_field_recheck_mono is not None
        and current - _secure_field_recheck_mono < SECURE_FIELD_RECHECK_SEC
    ):
        return
    _secure_field_recheck_mono = current
    sync_secure_field_from_focus(force=True)


def _mark_aw_backoff() -> None:
    _state.aw_backoff_until = time.monotonic() + AW_BACKOFF_SEC


def _aw_in_backoff(now: float | None = None) -> bool:
    t = time.monotonic() if now is None else now
    return t < _state.aw_backoff_until


def _find_window_bucket() -> str | None:
    if _aw_in_backoff():
        return None
    try:
        resp = _aw_session.get(
            f"{AW_BASE_URL}/api/0/buckets/", timeout=2, allow_redirects=False
        )
        resp.raise_for_status()
        if _stop_event.is_set():
            return None
        for b_id in resp.json():
            if "window" in b_id.lower():
                return None if _stop_event.is_set() else b_id
    except Exception as e:
        if not _stop_event.is_set():
            _mark_aw_backoff()
            _diag_rate_limited(
                f"ActivityWatch buckets error [{_exception_category(e)}]"
            )
    return None


def get_activitywatch_window() -> tuple[str, str]:
    """ActivityWatch enricher source. Returns (app, title); empty on failure."""
    global _window_bucket
    if _aw_in_backoff():
        return "", ""
    try:
        if not _window_bucket:
            bucket = _find_window_bucket()
            if _stop_event.is_set():
                return "", ""
            _window_bucket = bucket
        if _stop_event.is_set():
            return "", ""
        if not _window_bucket:
            return "", ""
        resp = _aw_session.get(
            f"{AW_BASE_URL}/api/0/buckets/{_window_bucket}/events",
            params={"limit": 1},
            timeout=2,
            allow_redirects=False,
        )
        resp.raise_for_status()
        if _stop_event.is_set():
            return "", ""
        events = resp.json()
        if not events:
            return "", ""
        d = events[0].get("data", {}) or {}
        app = d.get("app") or ""
        title = d.get("title") or ""
        return str(app), str(title)
    except Exception as e:
        if not _stop_event.is_set():
            _window_bucket = None
            _mark_aw_backoff()
            _diag_rate_limited(
                f"ActivityWatch events error, bucket cleared [{_exception_category(e)}]"
            )
        return "", ""


def resolve_window() -> tuple[str, str]:
    """Native-first (app, title); optional AW fills empty fields only.

    Skips ActivityWatch HTTP when native app and title are both non-empty.
    Respects AW failure backoff to avoid rediscovery storms.
    """
    native = get_native_window()
    app_n, title_n = native[0] or "", native[1] or ""
    if not ACTIVITYWATCH_ENRICHER:
        return merge_native_and_aw(native, None, enricher_enabled=False)
    if app_n and title_n:
        return app_n, title_n
    if _aw_in_backoff():
        return merge_native_and_aw(native, None, enricher_enabled=False)
    try:
        aw = get_activitywatch_window()
    except Exception as e:
        if not _stop_event.is_set():
            _mark_aw_backoff()
            _diag_rate_limited(
                f"ActivityWatch enricher error [{_exception_category(e)}]"
            )
        return merge_native_and_aw(native, None, enricher_enabled=False)
    return merge_native_and_aw(native, aw, enricher_enabled=True)


def get_active_window() -> tuple[str, str]:
    """test/compat alias → resolve_window()."""
    return resolve_window()


def _window_context_matches(
    app: str, title: str, context: tuple[int, str, str | None]
) -> bool:
    _pid, current_app, current_title = context
    if not app or app.casefold() != current_app.casefold() or current_title is None:
        return False
    return not current_title or title == current_title


def _frontmost_context_for_window_test_compat(
    app: str, title: str
) -> tuple[int, str, str | None] | None:
    context = _frontmost_app_identity()
    if context is None and _state.last_secure_app_pid == 0:
        return 0, app or "test", title
    return context


def apply_resolved_window(app: str, title: str) -> bool:
    """Apply a window only while its verified privacy context is still current."""
    global _pause_secure_app, _pause_secure_field, _window_apply_generation
    global _heading_native_context

    if _stop_event.is_set():
        return False
    with _lock:
        if _stop_event.is_set():
            return False
        _window_apply_generation += 1
        apply_generation = _window_apply_generation

    body = build_heading_body(app, title)
    if body is None:
        _set_pause(app=True)
        return False

    with _secure_app_lock:
        context_before = _frontmost_context_for_window_test_compat(app, title)
        if _stop_event.is_set():
            return False
        if context_before is None or not _window_context_matches(app, title, context_before):
            _set_pause(app=True)
            return False

        with _secure_field_lock:
            secure_field_status = refresh_secure_field_focus(force=True)
            context_after = _frontmost_context_for_window_test_compat(app, title)
            context_stable = (
                context_after == context_before
                and context_after is not None
                and _window_context_matches(app, title, context_after)
            )
            if _stop_event.is_set():
                return False
            if not context_stable:
                _set_pause(app=True)
                return False

            is_secure_app = _is_secure_app_name(app, title)
            is_secure_field = secure_field_status is not False
            new_heading = body
            if is_secure_app:
                new_heading = f"🔒 [SECURE APP PAUSED] {body}"
            elif is_secure_field:
                new_heading = f"🔒 [SECURE FIELD PAUSED] {body}"

            with _lock:
                if _stop_event.is_set() or apply_generation != _window_apply_generation:
                    return False
                heading_changed = new_heading != _current_heading
                _set_pause(app=is_secure_app, field=is_secure_field)
                if not _storage_blocked:
                    _apply_heading_change_locked(new_heading)
                    _heading_native_context = (
                        context_after if not is_secure_app and not is_secure_field else None
                    )
                need_flush = _buffers_need_file_flush_locked()

    # Skip AX scan enqueue when heading unchanged (debounce still applies if enqueued).
    if heading_changed and not _stop_event.is_set() and not is_paused():
        _enqueue_ax(("scan", context_after))
    if need_flush:
        flush_to_file()
    return True


def _seal_open_events_locked(trigger: str) -> None:
    """Seal `_current_events` into `_sections`. Caller holds `_lock`.

    Always stores the trigger internally. The legacy field remains feature-gated.
    Do not pass ``typing_pause`` from F3 key-flush paths (reserved; unused in F3 v1).
    """
    if not _current_events:
        return
    if trigger not in CAPTURE_TRIGGERS:
        raise ValueError(f"unknown capture trigger: {trigger!r}")
    if trigger == "typing_pause":
        raise ValueError("typing_pause is reserved; do not emit as section trigger")
    captured_at = datetime.now().astimezone()
    section: dict = {
        "heading": _current_heading or FALLBACK_HEADING,
        "events": list(_current_events),
        "timestamp": captured_at.strftime("%H:%M:%S"),
        "captured_at": captured_at,
        "_trigger": trigger,
        "_analysis_order": min(
            (
                event.sequence
                for event in _current_events
                if isinstance(event, CapturedEvent) and event.sequence is not None
            ),
            default=next(_analysis_sequence),
        ),
    }
    if CAPTURE_TRIGGERS_ENABLED:
        section["trigger"] = trigger
    _sections.append(section)
    _current_events.clear()


def _flush_keys(*, cause: str = "unknown") -> None:
    """Join key buffer into `_current_events` and clear buffer. Caller holds `_lock`."""
    global _last_key_flush_cause, _last_key_activity_mono
    if not _current_keystrokes:
        return
    payload = "".join(_current_keystrokes)
    _current_events.append(
        CapturedEvent(
            payload,
            kind="type",
            payload=payload,
            sequence=next(_analysis_sequence),
        )
    )
    _current_keystrokes.clear()
    _last_key_flush_cause = cause
    _last_key_activity_mono = None
    _key_deadline_changed.set()
    hook = _key_flush_hook
    if hook is not None:
        hook(cause)


def _buffers_need_file_flush_locked() -> bool:
    """True when soft caps require a durable flush. Caller holds `_lock`."""
    if len(_current_keystrokes) >= MAX_KEYSTROKES:
        _flush_keys(cause="buffer_cap")
    return len(_current_events) >= MAX_EVENTS or len(_sections) >= MAX_SECTIONS


def _maybe_flush_for_buffer_caps() -> None:
    """Flush keys under lock; force file flush when event/section caps hit."""
    need_file = False
    with _lock:
        need_file = _buffers_need_file_flush_locked()
    if need_file:
        flush_to_file()


def note_key_activity(now: float | None = None) -> None:
    """Record buffer-mutating key activity (monotonic). Used by on_press and tests."""
    with _lock:
        _note_key_activity_locked(now)


def _note_key_activity_locked(now: float | None = None) -> None:
    global _last_key_activity_mono
    _last_key_activity_mono = time.monotonic() if now is None else now
    _key_deadline_changed.set()


def check_typing_pause_idle(now: float | None = None) -> bool:
    """If idle ≥ typing_pause_sec and buffer non-empty, flush keys → events only.

    Does not seal `_sections` and does not write Markdown.
    `now` is injectable monotonic time for tests.
    """
    with _lock:
        return _check_typing_pause_idle_locked(now)


def _check_typing_pause_idle_locked(now: float | None = None) -> bool:
    if _is_paused:
        return False
    if not _current_keystrokes:
        return False
    if _last_key_activity_mono is None:
        return False
    t = time.monotonic() if now is None else now
    if (t - _last_key_activity_mono) < TYPING_PAUSE_SEC:
        return False
    _flush_keys(cause="typing_pause")
    return True


def _append_analysis_marker_locked(
    kind: str,
    payload: str = "",
    captured_at: datetime | None = None,
    heading_override: str | None = None,
) -> None:
    """Add one shadow-only timeline marker. Caller holds `_lock`."""
    if not _analysis_runtime_enabled or _storage_blocked:
        return
    stamp = captured_at or datetime.now().astimezone()
    heading = heading_override or (
        "[PRIVATE CONTEXT]" if _is_paused else (_current_heading or FALLBACK_HEADING)
    )
    sequence = next(_analysis_sequence)
    _analysis_markers.append(
        {
            "heading": heading,
            "events": [
                CapturedEvent(
                    "",
                    kind=kind,
                    payload=payload,
                    captured_at=stamp,
                    sequence=sequence,
                )
            ],
            "timestamp": stamp.strftime("%H:%M:%S"),
            "captured_at": stamp,
            "_trigger": "timeline",
            "analysis_only": True,
            "_analysis_order": sequence,
        }
    )
    if len(_analysis_markers) > MAX_ANALYSIS_MARKERS:
        dropped = _analysis_markers.pop(0)
        _analysis_marker_overflow_days.add(_section_captured_at(dropped).date())


def observe_system_idle(seconds: float | None = None, now: datetime | None = None) -> None:
    """Record only transitions across the local five-minute idle threshold."""
    global _analysis_idle_active
    if not _analysis_runtime_enabled or not SYSTEM_IDLE_AVAILABLE:
        return
    try:
        idle_seconds = (
            float(seconds)
            if seconds is not None
            else float(
                CGEventSourceSecondsSinceLastEventType(
                    kCGEventSourceStateCombinedSessionState,
                    kCGAnyInputEventType,
                )
            )
        )
    except Exception as e:
        _diag_rate_limited(f"system idle observation failed [{_exception_category(e)}]")
        return
    idle_now = idle_seconds >= WORKLOAD_IDLE_SEC
    if idle_now == _analysis_idle_active:
        return
    stamp = now or datetime.now().astimezone()
    with _lock:
        if idle_now:
            idle_since = stamp - timedelta(seconds=max(0.0, idle_seconds))
            _append_analysis_marker_locked(
                "idle_start", idle_since.isoformat(), captured_at=stamp
            )
        else:
            _append_analysis_marker_locked("idle_end", captured_at=stamp)
        _analysis_idle_active = idle_now
    _writer_wakeup.set()


def maybe_record_analysis_heartbeat(
    now_mono: float | None = None, stamp: datetime | None = None
) -> None:
    """Write one low-overhead continuity marker per hour."""
    global _analysis_last_heartbeat_mono
    if not _analysis_runtime_enabled:
        return
    current = time.monotonic() if now_mono is None else now_mono
    if (
        _analysis_last_heartbeat_mono is not None
        and current - _analysis_last_heartbeat_mono < ANALYSIS_HEARTBEAT_SEC
    ):
        return
    with _lock:
        _append_analysis_marker_locked("heartbeat", captured_at=stamp)
        _analysis_last_heartbeat_mono = current
    _writer_wakeup.set()


def observe_wall_clock_gap(now_wall: float | None = None) -> None:
    """Lazy sleep detection: a wall-clock jump between checks means the Mac was suspended.

    Monotonic time pauses during sleep, so heartbeats cannot see it. Reuses the idle pair
    because analysis_log rejects unknown marker kinds. The suspension start goes in the
    idle_start payload, as observe_system_idle does. Both markers stamp the wake time.
    """
    global _wall_clock_last, _analysis_last_heartbeat_mono
    if not _analysis_runtime_enabled:
        return
    current = time.time() if now_wall is None else now_wall
    previous, _wall_clock_last = _wall_clock_last, current
    # Only the excess over the normal check interval counts as suspension.
    # ponytail: a manual clock change looks the same as sleep, accepted for now.
    if previous is None or current - previous - WINDOW_CHECK_SEC <= SUSPEND_GAP_SEC:
        return
    stamp = datetime.fromtimestamp(current).astimezone()
    suspended_since = datetime.fromtimestamp(previous).astimezone()
    with _lock:
        # An open idle span already covers the gap and closes on the next idle observation.
        if not _analysis_idle_active:
            _append_analysis_marker_locked(
                "idle_start", suspended_since.isoformat(), captured_at=stamp
            )
            _append_analysis_marker_locked("idle_end", captured_at=stamp)
        _analysis_last_heartbeat_mono = None
    _writer_wakeup.set()


def _apply_heading_change_locked(new_heading: str) -> None:
    """Flush keys, seal events, set heading. Caller holds `_lock`."""
    global _current_heading, _last_screen_text, _last_key_activity_mono
    global _heading_native_context
    if new_heading == _current_heading:
        return
    # F6: flush open scroll into prior section before heading switch.
    _flush_scroll_burst_locked()
    _flush_keys(cause="app_switch")
    _seal_open_events_locked("app_switch")
    _current_heading = new_heading
    _heading_native_context = None
    _append_analysis_marker_locked("focus")
    _last_screen_text = ""
    _last_key_activity_mono = None


def apply_heading_change(new_heading: str) -> None:
    """Flush keys, seal open events under the old heading, set new heading.

    Resets typing-pause idle state for the new context.
    """
    need_flush = False
    with _lock:
        _apply_heading_change_locked(new_heading)
        need_flush = _buffers_need_file_flush_locked()
    if need_flush:
        flush_to_file()


def _add_event_locked(ev: str, seal_trigger: str | None = None) -> bool:
    if _stop_event.is_set() or _is_paused or _storage_blocked:
        return False
    cause = seal_trigger or "add_event"
    _flush_keys(cause=cause)
    if isinstance(ev, CapturedEvent) and ev.sequence is None:
        ev = CapturedEvent(
            str(ev),
            kind=ev.kind,
            payload=ev.payload,
            captured_at=ev.captured_at,
            sequence=next(_analysis_sequence),
        )
    elif not isinstance(ev, CapturedEvent):
        ev = CapturedEvent(
            str(ev), kind="event", payload=str(ev), sequence=next(_analysis_sequence)
        )
    _current_events.append(ev)
    if seal_trigger and CAPTURE_TRIGGERS_ENABLED:
        _seal_open_events_locked(seal_trigger)
    return _buffers_need_file_flush_locked()


def add_event(ev: str, seal_trigger: str | None = None) -> None:
    """Append an event. Optional seal_trigger seals when F5 flag is ON."""
    with _lock:
        need_flush = _add_event_locked(ev, seal_trigger)
    if need_flush:
        flush_to_file()


def record_click_event(desc: str) -> None:
    """Append a click line; seal with ``click`` when capture_triggers_enabled."""
    add_event(
        CapturedEvent(f"🖱️ **Клік:** {desc}", kind="click", payload=desc),
        seal_trigger="click",
    )


def record_clipboard_event(event: str) -> None:
    """Append a clipboard event; seal with ``clipboard`` when capture_triggers_enabled."""
    captured = (
        event
        if isinstance(event, CapturedEvent)
        else CapturedEvent(event, kind="clipboard", payload=event)
    )
    add_event(captured, seal_trigger="clipboard")


def record_url_event(event: str) -> None:
    """Append a URL event; seal with ``url_change`` when capture_triggers_enabled (F4+F5)."""
    add_event(CapturedEvent(event, kind="url", payload=event), seal_trigger="url_change")


def on_scroll_tick(
    *,
    dx: float,
    dy: float,
    now: float | None = None,
    app: str = "",
    heading: str = "",
) -> None:
    """Accumulate one scroll tick when F6 is enabled and not paused."""
    global _scroll_burst
    if _stop_event.is_set() or not SCROLL_COALESCE_ENABLED:
        return
    with _lock:
        if _is_paused or _storage_blocked:
            return
        t = time.monotonic() if now is None else now
        app_name = app
        head = heading or _current_heading
        if not app_name and head:
            app_name = head.split(" \N{EM DASH} ", 1)[0].strip()
        _scroll_burst = scroll_accumulate(
            _scroll_burst,
            dx=dx,
            dy=dy,
            now=t,
            app=app_name,
            heading=head,
        )
        _scroll_deadline_changed.set()


def on_scroll(x, y, dx, dy) -> None:
    """pynput scroll callback, with no AX scan or screenshot."""
    if not SCROLL_COALESCE_ENABLED:
        return
    context = _capture_context()
    if context is None:
        return
    with _lock:
        if not _capture_context_matches_locked(context):
            return
        on_scroll_tick(dx=dx, dy=dy, app=context[1], heading=_current_heading)


def on_mouse_move_stub(x, y) -> None:
    """Test hook: moves are intentionally ignored (F6 must not log trails)."""
    return None


def _flush_scroll_burst_locked() -> bool:
    """Flush open scroll burst → event + seal. Caller holds `_lock`.

    Defense in depth: if paused, discard and return False (T-F6-08).
    """
    global _scroll_burst
    if _scroll_burst is None or not _scroll_burst.is_open:
        return False
    if _is_paused:
        _scroll_burst = scroll_discard(_scroll_burst)
        return False
    line = format_burst_line(_scroll_burst)
    _scroll_burst = None
    _scroll_deadline_changed.set()
    # Inline add_event path while holding lock (avoid re-entrant lock).
    # Always seal: F5 ON stores trigger scroll_coalesce; F5 OFF seals with no trigger field.
    _flush_keys(cause="scroll_coalesce")
    _current_events.append(
        CapturedEvent(
            line,
            kind="scroll",
            payload=line,
            sequence=next(_analysis_sequence),
        )
    )
    _seal_open_events_locked("scroll_coalesce")
    return True


def flush_scroll_burst(*, now: float | None = None) -> bool:
    """Flush open scroll burst if any (pause-safe). Used by tests and shutdown."""
    need_file = False
    with _lock:
        flushed = _flush_scroll_burst_locked()
        if flushed:
            need_file = _buffers_need_file_flush_locked()
    if need_file:
        flush_to_file()
    return flushed


def check_scroll_coalesce_idle(now: float | None = None) -> bool:
    """If quiet ≥ scroll_coalesce_ms, flush the open burst and seal."""
    if not SCROLL_COALESCE_ENABLED:
        return False
    need_file = False
    with _lock:
        if _is_paused:
            return False
        t = time.monotonic() if now is None else now
        if not scroll_should_flush(
            _scroll_burst, now=t, coalesce_ms=SCROLL_COALESCE_MS
        ):
            return False
        flushed = _flush_scroll_burst_locked()
        if flushed:
            need_file = _buffers_need_file_flush_locked()
    if need_file:
        flush_to_file()
    return flushed


def flush_scroll_burst_on_shutdown() -> bool:
    """Orderly shutdown / durable path: flush if not paused; discard if paused."""
    global _scroll_burst
    if not SCROLL_COALESCE_ENABLED:
        return False
    with _lock:
        if _is_paused:
            _scroll_burst = scroll_discard(_scroll_burst)
            return False
        return _flush_scroll_burst_locked()


def mouse_listener_kwargs_for_config(*, on_click=None) -> dict:
    """Listener kwargs for current config. Never includes on_move."""
    click_cb = on_click if on_click is not None else globals()["on_click"]
    on_scroll_cb = on_scroll if SCROLL_COALESCE_ENABLED else None
    return mouse_listener_kwargs(on_click=click_cb, on_scroll=on_scroll_cb)


def create_mouse_listener_safe(*, on_click):
    """Create mouse.Listener; soft-fail scroll attach (FR-F6-011).

    Returns ``(listener, diagnostic_or_None)``. Emits at most one scroll
    diagnostic per process (``_scroll_diag_emitted``).
    """
    global _scroll_diag_emitted
    if not PYNPUT_AVAILABLE or mouse_Listener is None:
        return None, "pynput unavailable"
    kwargs = mouse_listener_kwargs_for_config(on_click=on_click)
    try:
        return mouse_Listener(**kwargs), None
    except Exception as e:
        if SCROLL_COALESCE_ENABLED and not _scroll_diag_emitted:
            _scroll_diag_emitted = True
            note = f"scroll coalesce unavailable [{_exception_category(e)}]"
            try:
                _diag(note)
            except Exception:
                pass
            # Fall back to click-only
            try:
                return mouse_Listener(on_click=kwargs["on_click"]), note
            except Exception:
                return None, note
        # Already diagnosed, or feature off
        try:
            return mouse_Listener(on_click=kwargs["on_click"]), None
        except Exception:
            return None, None


def scroll_coalesce_idle_loop() -> None:
    """Sleep until the exact open-scroll deadline or a state change."""
    while not _stop_event.is_set():
        _scroll_deadline_changed.clear()
        if _stop_event.is_set():
            return
        with _lock:
            burst = _scroll_burst
            deadline = (
                burst.last_mono + SCROLL_COALESCE_MS / 1000.0
                if SCROLL_COALESCE_ENABLED and burst is not None and burst.is_open
                else None
            )
        timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        _scroll_deadline_changed.wait(timeout)
        if _stop_event.is_set():
            return
        if not _scroll_deadline_changed.is_set():
            check_scroll_coalesce_idle()


def maybe_capture_browser_url(app: str, *, url_provider=None) -> None:
    """When F4 flag ON and app is a browser, observe/emit URL (pause-safe).

    Flag OFF: return without calling ``url_provider`` (no Automation prompts).
    """
    if _stop_event.is_set() or not BROWSER_URL_CAPTURE:
        return
    if not is_browser_app(app):
        return
    context = _capture_context()
    if context is None or (context[0] != 0 and context[1].casefold() != app.casefold()):
        return
    with _lock:
        if _is_paused:
            return
        privacy_generation = _privacy_generation
    try:
        if url_provider is not None:
            if callable(url_provider) and not hasattr(url_provider, "get_url"):
                raw = url_provider(app)
            else:
                raw = url_provider.get_url(app)
        else:
            raw = get_frontmost_browser_url(app)
    except Exception as e:
        _diag_rate_limited(f"browser url error [{_exception_category(e)}]")
        return
    final_context = _capture_context(context)
    record_browser_url_observation(
        raw,
        privacy_generation=privacy_generation,
        allow_capture=final_context is not None,
        context=context,
    )


def _coerce_url_provider(url_provider):
    """Wrap a bare callable as a BrowserUrlProvider-like object."""
    if url_provider is None:
        return None
    if callable(url_provider) and not hasattr(url_provider, "get_url"):

        class _FnProvider:
            def get_url(self, app_name: str):
                return url_provider(app_name)

        return _FnProvider()
    return url_provider


def process_window_check_cycle(
    app: str,
    title: str,
    *,
    url_provider=None,
    url: str | None = None,
) -> bool:
    """Single public window-check cycle: heading/section first, then optional URL."""
    ok = apply_resolved_window(app, title)
    if url is not None:
        record_browser_url_observation(url)
    else:
        maybe_capture_browser_url(app, url_provider=_coerce_url_provider(url_provider))
    return ok


def record_browser_url_observation(
    url: str,
    *,
    privacy_generation: int | None = None,
    allow_capture: bool = True,
    context: tuple[int, str, str] | None = None,
) -> None:
    """Test/helper: emit a URL observation through the same path as live capture."""
    global _last_emitted_url
    if _stop_event.is_set() or not BROWSER_URL_CAPTURE:
        return
    need_flush = False
    with _lock:
        if _stop_event.is_set():
            return
        spanned_pause = (
            privacy_generation is not None
            and privacy_generation != _privacy_generation
        )
        if context is not None and not _capture_context_matches_locked(context):
            allow_capture = False
        new_last, event = apply_url_observation(
            enabled=True,
            paused=_is_paused or _storage_blocked or spanned_pause or not allow_capture,
            candidate=url,
            last_emitted=_last_emitted_url or None,
        )
        _last_emitted_url = new_last
        if event:
            need_flush = _add_event_locked(
                CapturedEvent(event, kind="url", payload=new_last or event),
                "url_change",
            )
    if need_flush:
        flush_to_file()


def _maybe_pause_secure_app_on_key(
    now: float | None = None,
) -> tuple[int, str, str] | None:
    """Verify the frontmost PID on every key and cache only its classification."""
    t = time.monotonic() if now is None else now
    with _secure_app_lock:
        identity = _frontmost_app_identity()
        if _stop_event.is_set():
            return None
        if identity is None:
            if _state.last_secure_app_pid == 0 and _state.last_secure_app_is_secure is False:
                context = (0, "test", "")
                _set_pause(app=False)
                return context
            _state.last_secure_app_context = None
            _state.last_secure_app_is_secure = None
            _set_pause(app=True)
            return None
        if len(identity) == 2:
            pid, app = identity
            context = (pid, app, "")
        else:
            context = identity
        pid, app, title = context
        if not app or title is None:
            _set_pause(app=True)
            return None
        unchanged = context == _state.last_secure_app_context
        if unchanged and (t - _state.last_secure_app_check_mono) < SECURE_APP_CHECK_SEC:
            secure = _state.last_secure_app_is_secure
        else:
            secure = _is_secure_app_name(app, title)
            _state.last_secure_app_pid = pid
            _state.last_secure_app_context = context
            _state.last_secure_app_is_secure = secure
            _state.last_secure_app_check_mono = t
        if secure is None:
            _set_pause(app=True)
            return None
        _set_pause(app=secure)
        if secure:
            return None
        return context


def _apply_cached_secure_field_pause_locked() -> None:
    """Apply pause from cached secure-field flag only (no AX). Caller holds `_lock`."""
    global _pause_secure_field
    if _secure_field_cache:
        _pause_secure_field = True
        _recompute_paused_locked()


def _secure_field_is_safe_for_key() -> bool:
    if _stop_event.is_set():
        return False
    now = time.monotonic()
    with _secure_field_lock:
        fresh = (
            _secure_field_cache_known
            and (now - _secure_field_cache_at) < SECURE_FIELD_CACHE_SEC
        )
        focused = _secure_field_cache if fresh else None
        if focused is True:
            _set_pause(field=True)
            return False
    if focused is None or focused is False:
        focused = sync_secure_field_from_focus(force=True)
    if focused is None:
        # ponytail: unresolved focus drops one key; add a bounded native event tap
        # cache only if synchronous AX checks become measurably expensive.
        with _secure_field_lock:
            if not _stop_event.is_set():
                _set_pause(field=True)
        return False
    if focused:
        with _secure_field_lock:
            if not _stop_event.is_set():
                _set_pause(field=True)
        return False
    return True


def _capture_context(
    expected: tuple[int, str, str] | None = None,
    *,
    allow_storage_blocked: bool = False,
) -> tuple[int, str, str] | None:
    """Verify one native context and bind its heading before accepting capture."""
    global _heading_native_context
    with _lock:
        if (
            _stop_event.is_set()
            or _pause_manual
            or _pause_review_center
            or (_storage_blocked and not allow_storage_blocked)
        ):
            return None
    with _secure_app_lock:
        context = _maybe_pause_secure_app_on_key()
        if context is None or not _secure_field_is_safe_for_key():
            return None
        final_context = _maybe_pause_secure_app_on_key()
        if context != final_context or (expected is not None and context != expected):
            return None
        with _lock:
            if (
                _stop_event.is_set()
                or _is_paused
                or (_storage_blocked and not allow_storage_blocked)
            ):
                return None
            # PID zero is the existing isolated-test context, never a native PID.
            if context[0] != 0 and not _storage_blocked:
                if context != _heading_native_context or context[2]:
                    heading = build_heading_body(context[1], context[2])
                    if heading is None:
                        return None
                    _apply_heading_change_locked(heading)
                _heading_native_context = context
        return context


def _capture_context_matches_locked(context: tuple[int, str, str]) -> bool:
    """Reject an admission superseded by another callback before its append."""
    return (
        not _stop_event.is_set()
        and not _is_paused
        and not _storage_blocked
        and (
            context[0] == 0
            or (
                context == _heading_native_context
                and (
                    not context[2]
                    or _current_heading == build_heading_body(context[1], context[2])
                )
            )
        )
    )


def _press_modifier_locked(key, logical: str) -> None:
    if key in _physical_modifiers:
        if _modifier_counts.get(logical, 0) > 0:
            _current_modifiers.add(logical)
        return
    _physical_modifiers.add(key)
    _modifier_counts[logical] = _modifier_counts.get(logical, 0) + 1
    _current_modifiers.add(logical)


def _release_modifier_locked(key, logical: str) -> None:
    if key not in _physical_modifiers:
        return
    _physical_modifiers.remove(key)
    remaining = _modifier_counts.get(logical, 0) - 1
    if remaining > 0:
        _modifier_counts[logical] = remaining
    else:
        _modifier_counts.pop(logical, None)
        _current_modifiers.discard(logical)


def on_press(key) -> None:
    """Keyboard path with synchronous, fail-closed privacy validation."""
    if _stop_event.is_set():
        return
    context = _capture_context()
    if context is None:
        return

    need_flush = False
    with _lock:
        _apply_cached_secure_field_pause_locked()
        if not _capture_context_matches_locked(context):
            return
        mutated = False
        if isinstance(key, keyboard.Key):
            mod = _MODIFIER_KEYS.get(key)
            if mod:
                _press_modifier_locked(key, mod)
            elif key == keyboard.Key.enter:
                _current_keystrokes.append("\n[ENTER]\n")
                mutated = True
            elif key == keyboard.Key.tab:
                _current_keystrokes.append("[TAB]")
                mutated = True
            elif key == keyboard.Key.space:
                _current_keystrokes.append(" ")
                mutated = True
            elif key == keyboard.Key.backspace:
                if _current_keystrokes:
                    _current_keystrokes.pop()
                    mutated = True
            elif key == keyboard.Key.esc:
                _current_keystrokes.append("[ESC]")
                mutated = True
        elif hasattr(key, "char"):
            char = key.char
            if char is None and hasattr(key, "vk") and key.vk is not None:
                char = f"VK_{key.vk}"
            if char:
                if _current_modifiers.difference({"SHIFT"}):
                    mods = "+".join(sorted(_current_modifiers))
                    _current_keystrokes.append(f"[{mods}+{char.upper()}]")
                else:
                    _current_keystrokes.append(char)
                mutated = True
        if mutated:
            _note_key_activity_locked()
            need_flush = _buffers_need_file_flush_locked()
    if need_flush:
        flush_to_file()


def on_release(key) -> None:
    if _stop_event.is_set():
        return
    with _lock:
        if isinstance(key, keyboard.Key):
            mod = _MODIFIER_KEYS.get(key)
            if mod:
                _release_modifier_locked(key, mod)


def extract_text(element, depth=0) -> str:
    """Extract bounded AX text iteratively, never traversing secure subtrees."""
    if depth > AX_MAX_DEPTH:
        return ""
    deadline = time.monotonic() + 0.25
    char_limit = max(2000, SCREEN_COMPARE_MAX_CHARS)
    extracted: list[str] = []
    chars = 0
    visited = 0
    stack = [(element, depth)]
    roles = {"AXStaticText", "AXTextArea", "AXTextField", "AXHeading", "AXLink", "AXButton"}
    while stack and visited < 1000 and chars < char_limit and time.monotonic() < deadline:
        current, current_depth = stack.pop()
        visited += 1
        try:
            secure_status = _element_secure_status(current)
            if secure_status is True:
                hidden = "[SECURE_FIELD_HIDDEN]"
                extracted.append(hidden)
                chars += len(hidden)
                continue
            if secure_status is None:
                continue
            err, role = AXUIElementCopyAttributeValue(current, "AXRole", None)
            if err != 0:
                continue
            if role in roles:
                err, value = AXUIElementCopyAttributeValue(current, "AXValue", None)
                if err != 0 or not isinstance(value, str) or not value:
                    err, value = AXUIElementCopyAttributeValue(current, "AXTitle", None)
                if err == 0 and isinstance(value, str) and value:
                    remaining = char_limit - chars
                    extracted.append(value[:remaining])
                    chars += min(len(value), remaining)
            if current_depth >= AX_MAX_DEPTH:
                continue
            err, children = AXUIElementCopyAttributeValue(current, "AXChildren", None)
            if err == 0 and children:
                limited = list(itertools.islice(children, AX_MAX_CHILDREN))
                stack.extend((child, current_depth + 1) for child in reversed(limited))
        except Exception:
            continue
    return " ".join(extracted)[:char_limit]


def scan_screen(expected_context: tuple[int, str, str] | None = None) -> None:
    if _stop_event.is_set() or not AX_AVAILABLE:
        return
    context = _capture_context(expected_context)
    if context is None:
        return
    with _lock:
        if _is_paused:
            return
        privacy_generation = _privacy_generation
    try:
        pid = context[0]
        if pid == 0:
            front_app = NSWorkspace.sharedWorkspace().frontmostApplication()
            if not front_app:
                return
            pid = front_app.processIdentifier()
        app_elem = AXUIElementCreateApplication(pid)
        err, window = AXUIElementCopyAttributeValue(app_elem, "AXFocusedWindow", None)
        if err != 0 or not window:
            return

        text = extract_text(window)
        text = " ".join(text.split())
        if not text:
            return
        if _capture_context(context) is None:
            return

        global _last_screen_text
        with _lock:
            if _is_paused or privacy_generation != _privacy_generation:
                return
            prev = _last_screen_text
        if prev[:SCREEN_COMPARE_MAX_CHARS] != text[:SCREEN_COMPARE_MAX_CHARS]:
            payload = text[:2000]
            event = CapturedEvent(
                f"💻 **Екран:**\n{format_markdown_fenced_text(payload)}",
                kind="screen",
                payload=payload,
            )
            with _lock:
                if (
                    _stop_event.is_set()
                    or not _capture_context_matches_locked(context)
                    or privacy_generation != _privacy_generation
                ):
                    return
                _last_screen_text = text
                need_flush = _add_event_locked(event)
            if need_flush:
                flush_to_file()
    except Exception as e:
        _diag_rate_limited(f"scan_screen error [{_exception_category(e)}]")


def _discard_pending_click(pending_id: int) -> None:
    with _lock:
        section = _pending_clicks.pop(pending_id, None)
        if section is not None:
            try:
                _sections.remove(section)
            except ValueError:
                pass


def _expire_pending_clicks(now: float | None = None) -> int:
    current = time.monotonic() if now is None else now
    with _lock:
        expired = [
            pending_id
            for pending_id, section in _pending_clicks.items()
            if section.get("expires_mono", current + 1.0) <= current
        ]
        for pending_id in expired:
            section = _pending_clicks.pop(pending_id)
            try:
                _sections.remove(section)
            except ValueError:
                pass
    if expired:
        _diag_rate_limited(f"click enrichment timeout: discarded {len(expired)} click(s)")
    return len(expired)


def _resolve_pending_click(
    pending_id: int, desc: str, context: tuple[int, str, str] | None = None
) -> bool:
    need_file = False
    with _lock:
        section = _pending_clicks.pop(pending_id, None)
        if section is None:
            return False
        if (
            _stop_event.is_set()
            or section.get("privacy_generation") != _privacy_generation
            or _is_paused
            or (context is not None and section.get("click_context") != context)
        ):
            try:
                _sections.remove(section)
            except ValueError:
                pass
            return False
        section.pop("pending_click", None)
        section.pop("privacy_generation", None)
        section.pop("click_context", None)
        section.pop("expires_mono", None)
        clean_desc = sanitize_markdown_inline(desc, "Unknown")
        section["events"].append(
            CapturedEvent(
                f"🖱️ **Клік:** {clean_desc}",
                kind="click",
                payload=clean_desc,
                captured_at=section.get("captured_at"),
                sequence=section.get("_analysis_order"),
            )
        )
        section["_trigger"] = "click"
        if CAPTURE_TRIGGERS_ENABLED:
            section["trigger"] = "click"
        need_file = _buffers_need_file_flush_locked()
    if need_file:
        flush_to_file()
    return True


def _reserve_pending_click(context: tuple[int, str, str]) -> int | None:
    with _lock:
        if not _capture_context_matches_locked(context):
            return None
        _flush_keys(cause="click")
        _seal_open_events_locked("click")
        captured_at = datetime.now().astimezone()
        pending_id = next(_click_sequence)
        section = {
            "heading": _current_heading or FALLBACK_HEADING,
            "events": [],
            "timestamp": captured_at.strftime("%H:%M:%S"),
            "captured_at": captured_at,
            "_trigger": "click",
            "_analysis_order": next(_analysis_sequence),
            "pending_click": pending_id,
            "privacy_generation": _privacy_generation,
            "click_context": context,
            "expires_mono": time.monotonic() + CLICK_RESOLVE_TIMEOUT_SEC,
        }
        _sections.append(section)
        _pending_clicks[pending_id] = section
        _writer_wakeup.set()
        return pending_id


def _process_click(x, y, pending_id: int | None = None) -> None:
    if _stop_event.is_set() or not AX_AVAILABLE or _is_paused:
        if pending_id is not None:
            _discard_pending_click(pending_id)
        return
    try:
        with _lock:
            reservation = _pending_clicks.get(pending_id)
            expected = reservation.get("click_context") if reservation else None
        context = _capture_context(expected, allow_storage_blocked=reservation is not None)
        if context is None:
            if pending_id is not None:
                _discard_pending_click(pending_id)
            return
        with _lock:
            pending = _pending_clicks.get(pending_id) if pending_id is not None else None
            context_mismatch = pending is not None and pending.get("click_context") != context
        if context_mismatch:
            _discard_pending_click(pending_id)
            return
        system_wide = AXUIElementCreateSystemWide()
        err, element = AXUIElementCopyElementAtPosition(system_wide, float(x), float(y), None)
        if err != 0 or not element:
            if pending_id is not None:
                _discard_pending_click(pending_id)
            return

        secure_status = _element_secure_status(element)
        if _stop_event.is_set():
            if pending_id is not None:
                _discard_pending_click(pending_id)
            return
        if secure_status is not False:
            with _secure_field_lock:
                if secure_status is True:
                    _mark_secure_field_cache(True)
                _set_pause(field=True)
            if pending_id is not None:
                _discard_pending_click(pending_id)
            return

        with _secure_field_lock:
            _mark_secure_field_cache(False)
            _set_pause(field=False)
        if _is_paused:
            if pending_id is not None:
                _discard_pending_click(pending_id)
            return

        err, role = AXUIElementCopyAttributeValue(element, "AXRole", None)
        role = role if err == 0 and role else "Unknown"
        err, title = AXUIElementCopyAttributeValue(element, "AXTitle", None)
        name = title if err == 0 and title and isinstance(title, str) else ""
        if not name:
            err, val = AXUIElementCopyAttributeValue(element, "AXValue", None)
            name = val if err == 0 and val and isinstance(val, str) else ""

        role_clean = str(role).replace("AX", "")
        desc = f"{role_clean} '{name}'" if name else role_clean
        final_context = _capture_context(context, allow_storage_blocked=reservation is not None)
        if (
            final_context is None
            or _stop_event.is_set()
        ):
            if pending_id is not None:
                _discard_pending_click(pending_id)
            return
        if pending_id is None:
            record_click_event(desc)
        else:
            _resolve_pending_click(pending_id, desc, final_context)
        if not _stop_event.is_set() and not is_paused():
            _enqueue_ax(("scan", final_context))
    except Exception as e:
        if pending_id is not None:
            _discard_pending_click(pending_id)
        _diag_rate_limited(f"process_click error [{_exception_category(e)}]")


def _enqueue_ax(job: tuple) -> bool:
    global _scan_pending
    if _stop_event.is_set():
        return False
    if job[0] == "scan":
        now = time.monotonic()
        if (
            _state.last_ax_scan_mono is not None
            and (now - _state.last_ax_scan_mono) < AX_SCAN_DEBOUNCE_SEC
        ):
            return False
        with _ax_meta_lock:
            if _scan_pending:
                return False
            try:
                _ax_jobs.put_nowait(job)
                _scan_pending = True
                return True
            except queue.Full:
                return False
    try:
        _ax_jobs.put_nowait(job)
        return True
    except queue.Full:
        return False


def _ax_worker_loop() -> None:
    global _scan_pending
    while not _stop_event.is_set():
        try:
            job = _ax_jobs.get(timeout=0.5)
        except queue.Empty:
            if _stop_event.is_set():
                return
            _expire_pending_clicks()
            continue
        try:
            if _stop_event.is_set():
                if job[0] == "scan":
                    with _ax_meta_lock:
                        _scan_pending = False
                continue
            if job[0] == "scan":
                with _ax_meta_lock:
                    _scan_pending = False
                _state.last_ax_scan_mono = time.monotonic()
                if len(job) > 1:
                    scan_screen(job[1])
                else:
                    scan_screen()
            elif job[0] == "click":
                _process_click(job[1], job[2], job[3] if len(job) > 3 else None)
        except Exception as e:
            _diag_rate_limited(f"ax_worker error [{_exception_category(e)}]")
        finally:
            _ax_jobs.task_done()


def on_click(x, y, button, pressed) -> None:
    if _stop_event.is_set() or not pressed:
        return
    context = _capture_context()
    if context is None:
        return
    pending_id = _reserve_pending_click(context)
    try:
        enqueued = pending_id is not None and _enqueue_ax(("click", x, y, pending_id))
    except Exception as e:
        enqueued = False
        _diag_rate_limited(f"click queue error [{_exception_category(e)}]")
    if pending_id is not None and not enqueued:
        _discard_pending_click(pending_id)
        _diag_rate_limited("click queue full: unresolved click discarded")
    _maybe_flush_for_buffer_caps()


def apply_clipboard_change(
    count: int,
    text: str,
    paused: bool,
    last_count: int,
    last_text: str,
) -> tuple[int, str, str | None]:
    """Testable clipboard update: advance markers while paused; never log paused secrets later."""
    if count == last_count:
        return last_count, last_text, None
    new_text = text if text else last_text
    if paused:
        return count, new_text, None
    if text and text != last_text:
        payload = text[:2000]
        return count, text, CapturedEvent(
            f"> [CLIPBOARD]:\n{format_markdown_fenced_text(payload)}",
            kind="clipboard",
            payload=payload,
        )
    return count, new_text, None


def _clipboard_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _apply_clipboard_change_digest(
    count: int,
    text: str,
    paused: bool,
    last_count: int,
    last_digest: str,
) -> tuple[int, str, str | None]:
    if count == last_count:
        return last_count, last_digest, None
    digest = _clipboard_digest(text) if text else last_digest
    if paused or not text or digest == last_digest:
        return count, digest, None
    payload = text[:2000]
    event = CapturedEvent(
        f"> [CLIPBOARD]:\n{format_markdown_fenced_text(payload)}",
        kind="clipboard",
        payload=payload,
    )
    return count, digest, event


def clipboard_checker_loop() -> None:
    if not AX_AVAILABLE:
        return
    global _last_clipboard_count, _last_clipboard_digest
    global _last_clipboard_privacy_generation

    retry = 1.0
    pb = None
    while not _stop_event.is_set() and pb is None:
        try:
            candidate = NSPasteboard.generalPasteboard()
            initial_count = candidate.changeCount()
            with _lock:
                if _stop_event.is_set():
                    return
                _last_clipboard_count = initial_count
                _last_clipboard_privacy_generation = _privacy_generation
            pb = candidate
        except Exception as e:
            _diag_rate_limited(
                f"clipboard initialization error [{_exception_category(e)}]"
            )
            if _stop_event.wait(retry):
                return
            retry = min(60.0, retry * 2.0)

    while not _stop_event.wait(1.0):
        try:
            count = pb.changeCount()
            if _stop_event.is_set():
                return
            if count == _last_clipboard_count:
                with _lock:
                    if _stop_event.is_set():
                        return
                    _last_clipboard_privacy_generation = _privacy_generation
                continue
            with _lock:
                privacy_generation = _privacy_generation
                paused_before_read = _is_paused
                spanned_pause = (
                    _last_clipboard_privacy_generation != privacy_generation
                )
            context = _capture_context()
            text = pb.stringForType_(NSStringPboardType) or ""
            final_context = _capture_context(context) if context is not None else None
            need_flush = False
            with _lock:
                if _stop_event.is_set():
                    continue
                spanned_pause = spanned_pause or privacy_generation != _privacy_generation
                new_count, new_digest, event = _apply_clipboard_change_digest(
                    count,
                    text,
                    paused_before_read
                    or _is_paused
                    or _storage_blocked
                    or spanned_pause
                    or final_context is None
                    or not _capture_context_matches_locked(final_context),
                    _last_clipboard_count,
                    _last_clipboard_digest,
                )
                _last_clipboard_count = new_count
                _last_clipboard_digest = new_digest
                _last_clipboard_privacy_generation = _privacy_generation
                if event:
                    need_flush = _add_event_locked(event, "clipboard")
            if need_flush:
                flush_to_file()
        except Exception as e:
            _diag_rate_limited(f"clipboard error [{_exception_category(e)}]")
        finally:
            text = ""
            event = None


def window_checker_loop() -> None:
    while not _stop_event.wait(WINDOW_CHECK_SEC):
        observe_wall_clock_gap()
        app, title = resolve_window()
        process_window_check_cycle(app=app, title=title)
        recheck_secure_field_pause()
        observe_system_idle()
        maybe_record_analysis_heartbeat()


def typing_pause_idle_loop() -> None:
    """Sleep until the exact typing deadline or a state change."""
    while not _stop_event.is_set():
        _key_deadline_changed.clear()
        if _stop_event.is_set():
            return
        with _lock:
            deadline = (
                _last_key_activity_mono + TYPING_PAUSE_SEC
                if not _is_paused
                and _current_keystrokes
                and _last_key_activity_mono is not None
                else None
            )
        timeout = None if deadline is None else max(0.0, deadline - time.monotonic())
        _key_deadline_changed.wait(timeout)
        if _stop_event.is_set():
            return
        if not _key_deadline_changed.is_set():
            check_typing_pause_idle()


def _sanitize_diag_message(msg: object) -> str:
    printable = "".join(ch if ch.isprintable() else " " for ch in str(msg))
    return " ".join(printable.split())[:_DIAG_MAX_CHARS]


def _exception_category(exc: BaseException) -> str:
    name = type(exc).__name__
    if not name or not all(ch.isalnum() or ch == "_" for ch in name):
        return "Exception"
    return name[:80]


def _diag_rate_limited(msg: str) -> None:
    clean = _sanitize_diag_message(msg)
    key = clean.split(":", 1)[0]
    now = time.monotonic()
    if now - _diag_last.get(key, 0.0) < _DIAG_MIN_INTERVAL:
        return
    _diag_last[key] = now
    _diag(clean)


def _diag(msg: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {_sanitize_diag_message(msg)}\n"
    try:
        ensure_log_dir(LOG_DIR)
        _write_to_file(LOG_DIR / "diagnostics.log", [line])
    except Exception:
        pass
    print(line.strip(), file=sys.stderr, flush=True)


def _get_filepath(captured_at: datetime | None = None) -> Path:
    ensure_log_dir(LOG_DIR)
    stamp = captured_at or datetime.now().astimezone()
    return LOG_DIR / f"daily_log_{stamp.strftime('%Y-%m-%d')}.md"


def _analysis_only_day(day: date) -> bool:
    return day >= ANALYSIS_ONLY_START_DAY


def _initialize_analysis_persistence(day: date) -> dict[date, str | None]:
    headings = recover_authoritative_transaction(LOG_DIR)
    if _analysis_only_day(day):
        headings[day] = validate_authoritative_day(LOG_DIR, day)
    return headings


def _log_header_lines(
    *, captured_at: datetime | None = None, include_started: bool = False
) -> list[str]:
    stamp = captured_at or datetime.now().astimezone()
    lines = [
        f"# Work Log - {stamp.strftime('%Y-%m-%d')}\n\n",
        f"> Auto-generated by Interleaved Logger v{__version__} "
        f"(AX + Clipboard + Security + Hotkeys)\n\n---\n\n",
    ]
    if include_started:
        lines.append(f"*Logger started at {datetime.now().strftime('%H:%M:%S')}*\n\n---\n\n")
    return lines


def _write_to_file(filepath: Path, lines: list[str], append: bool = True) -> bool:
    with _io_lock:
        return _write_to_file_locked(filepath, lines, append)


def _write_to_file_locked(filepath: Path, lines: list[str], append: bool) -> bool:
    fd = None
    original = b""
    original_size = 0
    mutated = False
    try:
        data = "".join(lines).encode("utf-8")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(filepath, flags, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise OSError("refusing non-regular or foreign-owned log file")
        os.fchmod(fd, 0o600)
        original_size = info.st_size
        if append:
            os.lseek(fd, 0, os.SEEK_END)
        else:
            if original_size:
                os.lseek(fd, 0, os.SEEK_SET)
                original = os.read(fd, original_size)
            os.ftruncate(fd, 0)
            os.lseek(fd, 0, os.SEEK_SET)
        mutated = True
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("short log write")
            offset += written
        os.fsync(fd)
        return True
    except Exception as e:
        if fd is not None and mutated:
            try:
                os.ftruncate(fd, 0 if not append else original_size)
                if not append and original:
                    os.lseek(fd, 0, os.SEEK_SET)
                    offset = 0
                    while offset < len(original):
                        offset += os.write(fd, original[offset:])
                os.fsync(fd)
            except OSError:
                pass
        print(
            f"[ActivityLogger] WRITE ERROR [{_exception_category(e)}]",
            file=sys.stderr,
            flush=True,
        )
        return False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def _restore_sections(to_write: list) -> int:
    if not to_write:
        return 0
    with _lock:
        ready = to_write + list(_sections)
        dropped = max(0, len(ready) - MAX_SECTIONS)
        if dropped:
            for section in ready[:dropped]:
                pending_id = section.get("pending_click")
                if pending_id is not None:
                    _pending_clicks.pop(pending_id, None)
            ready = ready[-MAX_SECTIONS:]
        _sections[:] = ready
    return dropped


def _section_captured_at(section: dict) -> datetime:
    captured = section.get("captured_at")
    if isinstance(captured, datetime):
        return captured
    return datetime.now().astimezone()


def _format_sections(sections: list[dict] | tuple[SectionSnapshot, ...]) -> list[str]:
    snapshots = sections if sections and isinstance(sections[0], SectionSnapshot) else snapshot_sections(sections)
    lines: list[str] = []
    for section in snapshots:
        if section.analysis_only:
            continue
        trigger = section.trigger if CAPTURE_TRIGGERS_ENABLED and section.trigger != "unknown" else None
        ts_line = format_section_timestamp_line(section.timestamp, trigger)
        lines.append(f"## {section.heading}\n{ts_line}\n\n")
        for event in section.events:
            lines.append(f"{event.legacy.strip()}\n\n")
        lines.append("---\n\n")
    return lines


def _write_section_group(day: date, captured_at: datetime, sections: list[dict]) -> bool:
    snapshots = snapshot_sections(sections)
    if (
        captured_at.date() != day
        or _analysis_only_day(day)
        or any(snapshot.captured_at.date() != day for snapshot in snapshots)
    ):
        raise ValueError("legacy writer is disabled for this captured day")
    legacy_lines = _format_sections(snapshots)
    filepath = _get_filepath(captured_at)
    legacy_ok = not legacy_lines
    is_new = not filepath.exists() or filepath.stat().st_size == 0
    if legacy_lines and is_new and not _write_to_file(
        filepath, _log_header_lines(captured_at=captured_at), append=False
    ):
        return False
    if legacy_lines:
        legacy_ok = _write_to_file(filepath, legacy_lines)
    if not legacy_ok:
        return False
    return True


def _write_analysis_group(
    day: date,
    snapshots: tuple[SectionSnapshot, ...],
    trial: tuple[str, tuple] | None,
) -> None:
    """Best-effort shadow write after authoritative legacy data commits."""
    if not ANALYSIS_SHADOW_ENABLED or not snapshots or trial is None:
        return
    try:
        _batch_id, records = trial
        _analysis_heading_by_day[day] = commit_trial_batch(
            LOG_DIR,
            day,
            records,
            __version__,
            _analysis_heading_by_day.get(day),
        )
    except Exception as e:
        try:
            mark_invalid(LOG_DIR, day, f"shadow {_exception_category(e)}")
        except Exception:
            pass
        _diag_rate_limited(f"analysis shadow write failed [{_exception_category(e)}]")


def _reconcile_completed_days(healthy_day: date, candidates: set[date]) -> None:
    """Close existing valid past days after a later healthy local session."""
    global _readiness_reconciled_day
    from analysis_log import completed_analysis_days, inspect_analysis_day

    _readiness_candidates.update(candidates)
    if _readiness_reconciled_day != healthy_day:
        _readiness_candidates.update(completed_analysis_days(LOG_DIR, before=healthy_day))
        _readiness_reconciled_day = healthy_day
    for day in sorted(_readiness_candidates):
        inspection = inspect_analysis_day(LOG_DIR, day, today=healthy_day)
        if inspection.integrity_ok and not inspection.invalid_marker and not inspection.ready:
            publish_day_ready(LOG_DIR, day)
        _readiness_candidates.discard(day)


def flush_to_file() -> bool:
    """Persist resolved sections, with manifest ownership for analysis-only days."""
    global _flush_failed, _scroll_burst
    global _storage_blocked, _storage_gap_started_at, _pending_storage_gap
    global _file_flush_deadline, _file_retry_delay
    with _flush_lock:
        if (
            _storage_blocked
            and _file_flush_deadline is not None
            and time.monotonic() < _file_flush_deadline
        ):
            return False
        with _lock:
            if _pending_storage_gap is not None and _analysis_runtime_enabled and not _storage_blocked:
                start, end = _pending_storage_gap
                _append_analysis_marker_locked(
                    "heartbeat", f"storage_gap start={start.isoformat()} end={end.isoformat()}"
                )
                _pending_storage_gap = None
        detached = False
        authoritative_owned = False
        authoritative_committed = False
        pre_sections: list[dict] = []
        pre_markers: list[dict] = []
        uncommitted: list[dict] = []
        marker_overflow_days: set[date] = set()
        ready_days: set[date] = set()
        mixed_legacy_error = False
        try:
            try:
                recovered = recover_authoritative_transaction(LOG_DIR)
                _analysis_heading_by_day.update(recovered)
            except Exception as e:
                _flush_failed = True
                _fatal_worker_event.set()
                _request_stop()
                _diag_rate_limited(
                    "authoritative recovery failed "
                    f"[{_exception_category(e)}]"
                )
                return False

            with _lock:
                if SCROLL_COALESCE_ENABLED:
                    if _is_paused:
                        _scroll_burst = scroll_discard(_scroll_burst)
                    else:
                        _flush_scroll_burst_locked()
                _flush_keys(cause="file_flush")
                _seal_open_events_locked("file_flush")
                now = time.monotonic()
                for pending_id, section in list(_pending_clicks.items()):
                    if section.get("expires_mono", now + 1.0) <= now:
                        _pending_clicks.pop(pending_id, None)
                        try:
                            _sections.remove(section)
                        except ValueError:
                            pass
                barrier = next(
                    (
                        index
                        for index, section in enumerate(_sections)
                        if section.get("pending_click")
                    ),
                    len(_sections),
                )
                has_pending = barrier < len(_sections)
                to_write = list(_sections[:barrier])
                marker_write: list[dict] = []
                marker_overflow_days: set[date] = set()
                if not has_pending:
                    marker_write = list(_analysis_markers)
                    marker_overflow_days = set(_analysis_marker_overflow_days)

                analysis_sections = list(to_write) + marker_write
                analysis_sections.sort(
                    key=lambda section: (
                        int(section.get("_analysis_order") or sys.maxsize),
                        _section_captured_at(section),
                    )
                )
                analysis_by_day: dict[date, list[dict]] = {}
                for section in analysis_sections:
                    day = _section_captured_at(section).date()
                    analysis_by_day.setdefault(day, []).append(section)
                analysis_groups = list(analysis_by_day.items())
                pre_groups = [
                    group for group in analysis_groups if not _analysis_only_day(group[0])
                ]
                authoritative_groups = [
                    group for group in analysis_groups if _analysis_only_day(group[0])
                ]
                pre_sections = [
                    section
                    for section in to_write
                    if not _analysis_only_day(_section_captured_at(section).date())
                ]
                uncommitted = list(pre_sections)
                pre_markers = [
                    section
                    for section in marker_write
                    if not _analysis_only_day(_section_captured_at(section).date())
                ]
                guard_error: Exception | None = None
                authoritative_guard = False
                for overflow_day in marker_overflow_days:
                    if _analysis_only_day(overflow_day):
                        guard_error = RuntimeError("authoritative timeline marker overflow")
                        authoritative_guard = True
                        break
                    try:
                        mark_invalid(
                            LOG_DIR, overflow_day, "timeline marker overflow"
                        )
                    except Exception as e:
                        guard_error = e
                        break
                shadow_trials: list[
                    tuple[date, tuple[SectionSnapshot, ...], tuple | None]
                ] = []
                intent_errors: list[Exception] = []
                for day, sections in pre_groups:
                    snapshots = snapshot_sections(sections)
                    trial = None
                    if ANALYSIS_SHADOW_ENABLED and guard_error is None:
                        try:
                            trial = prepare_trial_intent(
                                LOG_DIR, day, snapshots, __version__
                            )
                        except Exception as e:
                            intent_errors.append(e)
                            try:
                                mark_invalid(
                                    LOG_DIR,
                                    day,
                                    f"intent {_exception_category(e)}",
                                )
                            except Exception as marker_error:
                                guard_error = marker_error
                    shadow_trials.append((day, snapshots, trial))
                if authoritative_groups and pre_sections and guard_error is None:
                    legacy_groups: list[tuple[date, datetime, list[dict]]] = []
                    for section in pre_sections:
                        captured_at = _section_captured_at(section)
                        day = captured_at.date()
                        if legacy_groups and legacy_groups[-1][0] == day:
                            legacy_groups[-1][2].append(section)
                        else:
                            legacy_groups.append((day, captured_at, [section]))
                    for day, captured_at, sections in legacy_groups:
                        try:
                            legacy_ok = _write_section_group(
                                day, captured_at, sections
                            )
                        except Exception:
                            legacy_ok = False
                        if not legacy_ok:
                            mixed_legacy_error = True
                            break
                        committed_ids = {id(section) for section in sections}
                        _sections[:] = [
                            section
                            for section in _sections
                            if id(section) not in committed_ids
                        ]
                    if not mixed_legacy_error:
                        for day, snapshots, trial in shadow_trials:
                            _write_analysis_group(day, snapshots, trial)
                        shadow_trials = []
                        pre_marker_ids = {id(section) for section in pre_markers}
                        _analysis_markers[:] = [
                            section
                            for section in _analysis_markers
                            if id(section) not in pre_marker_ids
                        ]
                        _analysis_marker_overflow_days.difference_update(
                            day
                            for day in marker_overflow_days
                            if not _analysis_only_day(day)
                        )
                        pre_sections = []
                        pre_markers = []
                        uncommitted = []
                authoritative_error: Exception | None = None
                authoritative_uncertain = False
                if (
                    authoritative_groups
                    and guard_error is None
                    and not mixed_legacy_error
                ):
                    try:
                        transaction_groups = [
                            (day, records_from_sections(snapshot_sections(sections)))
                            for day, sections in authoritative_groups
                        ]
                        ready_days = {
                            day - timedelta(days=1)
                            for day, records in transaction_groups
                            if any(record.kind == "heartbeat" for record in records)
                            and _analysis_only_day(day - timedelta(days=1))
                        }
                        prepare_authoritative_transaction(
                            LOG_DIR,
                            transaction_groups,
                            __version__,
                        )
                        authoritative_owned = True
                        authoritative_section_ids = {
                            id(section)
                            for section in to_write
                            if _analysis_only_day(
                                _section_captured_at(section).date()
                            )
                        }
                        _sections[:] = [
                            section
                            for section in _sections
                            if id(section) not in authoritative_section_ids
                        ]
                        if not has_pending:
                            authoritative_marker_ids = {
                                id(section)
                                for section in marker_write
                                if _analysis_only_day(
                                    _section_captured_at(section).date()
                                )
                            }
                            _analysis_markers[:] = [
                                section
                                for section in _analysis_markers
                                if id(section) not in authoritative_marker_ids
                            ]
                            _analysis_marker_overflow_days.intersection_update(
                                day
                                for day in marker_overflow_days
                                if not _analysis_only_day(day)
                            )
                    except Exception as e:
                        authoritative_error = e
                        try:
                            pending_was_published = authoritative_transaction_pending(
                                LOG_DIR
                            )
                        except Exception as pending_error:
                            authoritative_error = pending_error
                            pending_was_published = False
                            authoritative_uncertain = True
                        if pending_was_published:
                            authoritative_owned = True
                            authoritative_uncertain = True
                            authoritative_section_ids = {
                                id(section)
                                for section in to_write
                                if _analysis_only_day(
                                    _section_captured_at(section).date()
                                )
                            }
                            _sections[:] = [
                                section
                                for section in _sections
                                if id(section) not in authoritative_section_ids
                            ]
                            if not has_pending:
                                authoritative_marker_ids = {
                                    id(section)
                                    for section in marker_write
                                    if _analysis_only_day(
                                        _section_captured_at(section).date()
                                    )
                                }
                                _analysis_markers[:] = [
                                    section
                                    for section in _analysis_markers
                                    if id(section) not in authoritative_marker_ids
                                ]
                                _analysis_marker_overflow_days.intersection_update(
                                    day
                                    for day in marker_overflow_days
                                    if not _analysis_only_day(day)
                                )
                if (
                    guard_error is None
                    and authoritative_error is None
                    and not detached
                    and not authoritative_owned
                    and not mixed_legacy_error
                ):
                    del _sections[:barrier]
                    if not has_pending:
                        _analysis_markers.clear()
                        _analysis_marker_overflow_days.clear()
                    detached = True

            for error in intent_errors:
                _diag_rate_limited(
                    f"analysis shadow intent failed [{_exception_category(error)}]"
                )
            if guard_error is not None:
                _flush_failed = True
                if authoritative_guard:
                    _fatal_worker_event.set()
                    _request_stop()
                _diag_rate_limited(
                    "persistence guard failed "
                    f"[{_exception_category(guard_error)}]"
                )
                return False
            if mixed_legacy_error:
                for trial_day, _snapshots, trial in shadow_trials:
                    if trial is not None:
                        try:
                            mark_invalid(LOG_DIR, trial_day, "legacy write failed")
                        except Exception:
                            pass
                _flush_failed = True
                _diag_rate_limited("persistence write failed")
                return False
            if authoritative_error is not None:
                _flush_failed = True
                if authoritative_uncertain:
                    _fatal_worker_event.set()
                    _request_stop()
                _diag_rate_limited(
                    "authoritative prepare failed "
                    f"[{_exception_category(authoritative_error)}]"
                )
                return False

            if authoritative_owned:
                try:
                    committed = commit_authoritative_transaction(LOG_DIR)
                    _analysis_heading_by_day.update(committed)
                    authoritative_committed = True
                    if committed or ready_days:
                        healthy_day = max(
                            set(committed)
                            | {day + timedelta(days=1) for day in ready_days}
                        )
                        _reconcile_completed_days(healthy_day, ready_days)
                except Exception as e:
                    with _lock:
                        pre_ids = {id(section) for section in pre_sections}
                        _sections[:] = [
                            section
                            for section in _sections
                            if id(section) not in pre_ids
                        ]
                        marker_ids = {id(section) for section in pre_markers}
                        _analysis_markers[:] = [
                            section
                            for section in _analysis_markers
                            if id(section) not in marker_ids
                        ]
                        _analysis_markers[:0] = pre_markers
                        _analysis_marker_overflow_days.update(
                            day
                            for day in marker_overflow_days
                            if not _analysis_only_day(day)
                        )
                    dropped = _restore_sections(pre_sections)
                    _flush_failed = True
                    _fatal_worker_event.set()
                    _request_stop()
                    _diag_rate_limited(
                        "authoritative finalization failed "
                        f"[{_exception_category(e)}]"
                        + (
                            f"; dropped {dropped} oldest buffered sections"
                            if dropped
                            else ""
                        )
                    )
                    return False
                with _lock:
                    pre_ids = {id(section) for section in pre_sections}
                    _sections[:] = [
                        section
                        for section in _sections
                        if id(section) not in pre_ids
                    ]
                    marker_ids = {id(section) for section in pre_markers}
                    _analysis_markers[:] = [
                        section
                        for section in _analysis_markers
                        if id(section) not in marker_ids
                    ]
                    _analysis_marker_overflow_days.difference_update(
                        day
                        for day in marker_overflow_days
                        if not _analysis_only_day(day)
                    )
                detached = True

            groups: list[tuple[date, datetime, list[dict]]] = []
            for section in pre_sections:
                captured_at = _section_captured_at(section)
                day = captured_at.date()
                if groups and groups[-1][0] == day:
                    groups[-1][2].append(section)
                else:
                    groups.append((day, captured_at, [section]))

            for index, (day, captured_at, sections) in enumerate(groups):
                uncommitted = sections[:]
                for _, _, remaining in groups[index + 1 :]:
                    uncommitted.extend(remaining)
                if _write_section_group(day, captured_at, sections):
                    uncommitted = uncommitted[len(sections) :]
                    continue
                dropped = _restore_sections(uncommitted)
                _flush_failed = True
                _diag_rate_limited(
                    "persistence write failed"
                    + (f": dropped {dropped} oldest buffered sections" if dropped else "")
                )
                with _lock:
                    _analysis_markers[:0] = pre_markers
                    _analysis_marker_overflow_days.update(
                        overflow_day
                        for overflow_day in marker_overflow_days
                        if not _analysis_only_day(overflow_day)
                    )
                for trial_day, _snapshots, trial in shadow_trials:
                    if trial is not None:
                        try:
                            mark_invalid(LOG_DIR, trial_day, "legacy write failed")
                        except Exception:
                            pass
                return False
            for day, snapshots, trial in shadow_trials:
                _write_analysis_group(day, snapshots, trial)
            pre_markers = []
            _flush_failed = False
            return True
        except Exception as e:
            dropped = _restore_sections(uncommitted if detached else [])
            if detached:
                with _lock:
                    _analysis_markers[:0] = pre_markers
                    _analysis_marker_overflow_days.update(
                        overflow_day
                        for overflow_day in marker_overflow_days
                        if not _analysis_only_day(overflow_day)
                    )
            _flush_failed = True
            if authoritative_owned and not authoritative_committed:
                _fatal_worker_event.set()
                _request_stop()
            _diag_rate_limited(
                f"persistence flush error [{_exception_category(e)}]"
                + (f"; dropped {dropped} oldest buffered sections" if dropped else "")
            )
            return False
        finally:
            with _lock:
                if _flush_failed:
                    _file_retry_delay = min(
                        60.0, max(1.0, (_file_retry_delay or float(FLUSH_INTERVAL_SEC)) * 2.0)
                    )
                    if not _fatal_worker_event.is_set() and not _storage_blocked:
                        _storage_blocked = True
                        _storage_gap_started_at = datetime.now().astimezone()
                        _manual_state_dirty.set()
                else:
                    _file_retry_delay = 0.0
                    if _storage_blocked and not (
                        _current_keystrokes or _current_events or _sections or _analysis_markers
                    ):
                        _storage_blocked = False
                        if _storage_gap_started_at is not None:
                            _pending_storage_gap = (
                                _storage_gap_started_at, datetime.now().astimezone()
                            )
                        _storage_gap_started_at = None
                        _manual_state_dirty.set()
                _file_flush_deadline = time.monotonic() + (
                    _file_retry_delay or float(FLUSH_INTERVAL_SEC)
                )
            _writer_wakeup.set()


def file_writer_loop() -> None:
    global _file_flush_deadline
    if _file_flush_deadline is None:
        _file_flush_deadline = time.monotonic() + float(FLUSH_INTERVAL_SEC)
    while not _stop_event.is_set():
        _writer_wakeup.clear()
        if _stop_event.is_set():
            return
        with _lock:
            expiries = [
                section.get("expires_mono")
                for section in _pending_clicks.values()
                if isinstance(section.get("expires_mono"), (int, float))
            ]
        timeout = max(0.0, _file_flush_deadline - time.monotonic())
        if expiries:
            timeout = min(timeout, max(0.0, min(expiries) - time.monotonic()))
        _writer_wakeup.wait(timeout)
        if _stop_event.is_set():
            return
        expired = _expire_pending_clicks()
        if expired or time.monotonic() >= _file_flush_deadline:
            flush_to_file()


def acquire_instance_lock() -> bool:
    global _instance_lock_file
    fd = None
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        lock_dir = home / "Library" / "Application Support" / "ActivityLogger"
        lock_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        info = lock_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise OSError("unsafe instance lock directory")
        os.chmod(lock_dir, 0o700)
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(lock_dir / "activitylogger.lock", flags, 0o600)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise OSError("unsafe instance lock file")
        os.fchmod(fd, 0o600)
        _instance_lock_file = os.fdopen(fd, "r+", encoding="utf-8")
        fd = None
        fcntl.flock(_instance_lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        _instance_lock_file.seek(0)
        _instance_lock_file.truncate()
        _instance_lock_file.write(str(os.getpid()))
        _instance_lock_file.flush()
        return True
    except BlockingIOError:
        if _instance_lock_file is not None:
            _instance_lock_file.close()
            _instance_lock_file = None
        return False
    except OSError as e:
        if fd is not None:
            os.close(fd)
        if _instance_lock_file is not None:
            _instance_lock_file.close()
            _instance_lock_file = None
        _diag(f"instance lock error [{_exception_category(e)}]")
        return False


def _request_stop(signum=None, _frame=None) -> None:
    global _shutdown_reason
    if signum is not None and _shutdown_reason is None:
        try:
            signal_name = signal.Signals(signum).name
        except (TypeError, ValueError):
            signal_name = "UNKNOWN"
        _shutdown_reason = f"signal={signal_name}"
    _stop_event.set()
    _key_deadline_changed.set()
    _scroll_deadline_changed.set()
    _writer_wakeup.set()


def _request_manual_control(signum, _frame=None) -> None:
    """Apply manual privacy control through the shared capture gate."""
    global _manual_control_pending, _manual_control_revision
    global _manual_state_retry_at, _manual_state_retry_delay
    requested = signum == signal.SIGUSR1
    _manual_control_revision += 1
    _manual_control_pending = requested
    _manual_state_retry_at = 0.0
    _manual_state_retry_delay = 0.0
    if requested:
        _set_pause(manual=True)
    _manual_state_dirty.set()


def _publish_runtime_state(
    *,
    running: bool,
    manual_paused: bool | None = None,
    capture_paused: bool | None = None,
    control_revision: int | None = None,
) -> bool:
    try:
        manual = _pause_manual if manual_paused is None else manual_paused
        reasons = tuple(
            name
            for name, active in (
                ("manual", manual),
                ("secure_app", _pause_secure_app),
                ("secure_field", _pause_secure_field),
                ("review_window", _pause_review_center),
                ("storage", _storage_blocked),
            )
            if active
        )
        write_runtime_state(
            running=running,
            manual_paused=manual,
            capture_paused=is_paused() if capture_paused is None else capture_paused,
            storage_blocked=_storage_blocked,
            pause_reasons=reasons,
            control_revision=(
                _manual_control_revision
                if control_revision is None
                else control_revision
            ),
        )
        return True
    except Exception as exc:
        _diag_rate_limited(
            f"operator state error [{_exception_category(exc)}]"
        )
        return False


def _apply_pending_manual_control() -> None:
    global _manual_control_pending
    global _manual_state_retry_at, _manual_state_retry_delay
    if time.monotonic() < _manual_state_retry_at:
        return
    requested = _manual_control_pending
    _manual_state_dirty.clear()
    if requested is None:
        if _publish_runtime_state(running=True):
            _manual_state_retry_at = 0.0
            _manual_state_retry_delay = 0.0
        else:
            _manual_state_retry_delay = min(30.0, max(1.0, _manual_state_retry_delay * 2.0))
            _manual_state_retry_at = time.monotonic() + _manual_state_retry_delay
            _manual_state_dirty.set()
        return
    revision = _manual_control_revision
    if requested:
        published = _publish_runtime_state(
            running=True,
            manual_paused=True,
            capture_paused=True,
            control_revision=revision,
        )
    else:
        with _lock:
            capture_after_resume = (
                _pause_secure_app
                or _pause_secure_field
                or _pause_review_center
                or _storage_blocked
            )
        published = _publish_runtime_state(
            running=True,
            manual_paused=False,
            capture_paused=capture_after_resume,
            control_revision=revision,
        )
    if not published:
        _manual_state_retry_delay = min(30.0, max(1.0, _manual_state_retry_delay * 2.0))
        _manual_state_retry_at = time.monotonic() + _manual_state_retry_delay
        _manual_state_dirty.set()
        return
    _manual_state_retry_at = 0.0
    _manual_state_retry_delay = 0.0
    if _manual_control_revision != revision or _manual_control_pending is not requested:
        _manual_state_dirty.set()
        return
    if not requested:
        _set_pause(manual=False)
    _manual_control_pending = None


def _run_worker(target) -> None:
    try:
        target()
        if not _stop_event.is_set():
            raise RuntimeError(f"worker exited unexpectedly: {target.__name__}")
    except Exception as e:
        _diag(f"FATAL worker {target.__name__} [{_exception_category(e)}]")
        _fatal_worker_event.set()
        _request_stop()


def _discard_all_pending_clicks() -> None:
    with _lock:
        for section in list(_pending_clicks.values()):
            try:
                _sections.remove(section)
            except ValueError:
                pass
        _pending_clicks.clear()


def _close_instance_lock() -> None:
    global _instance_lock_file
    if _instance_lock_file is not None:
        try:
            _instance_lock_file.close()
        finally:
            _instance_lock_file = None


def _stop_and_join_listeners(
    *listeners, timeout: float = WORKER_JOIN_TIMEOUT_SEC
) -> bool:
    active = [listener for listener in listeners if listener is not None]
    ok = True
    for listener in active:
        try:
            listener.stop()
        except Exception as e:
            _diag_rate_limited(
                f"listener stop error [{_exception_category(e)}]"
            )
            ok = False
    for listener in active:
        try:
            listener.join(timeout=timeout)
            if listener.is_alive():
                raise RuntimeError(f"listener did not stop within {timeout:g} seconds")
        except Exception as e:
            _diag(f"FATAL listener shutdown [{_exception_category(e)}]")
            ok = False
    return ok


def main() -> int:
    global _analysis_idle_active, _analysis_last_heartbeat_mono
    global _analysis_runtime_enabled, _shutdown_reason
    global _manual_control_pending, _manual_control_revision, _pause_manual
    global _pause_review_center
    global _manual_state_retry_at, _manual_state_retry_delay
    global _file_flush_deadline, _file_retry_delay, _readiness_reconciled_day
    status = 0
    workers: list[threading.Thread] = []
    m_listener = None
    k_listener = None
    review_center_runtime = None
    acquired_instance_lock = False
    previous_handlers: dict[int, object] = {}
    os.umask(0o077)
    _stop_event.clear()
    _shutdown_reason = None
    _pause_manual = False
    _pause_review_center = False
    _manual_control_revision = 0
    _manual_control_pending = None
    _manual_state_dirty.clear()
    _manual_state_retry_at = 0.0
    _manual_state_retry_delay = 0.0
    _file_flush_deadline = None
    _file_retry_delay = 0.0
    _readiness_reconciled_day = None
    _readiness_candidates.clear()
    _fatal_worker_event.clear()
    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, _request_stop)

        try:
            cfg = load_config(warn=lambda msg: _diag(msg))
        except ConfigError as e:
            # Best-effort before LOG_DIR may be final
            category = _exception_category(e)
            print(f"FATAL config [{category}]", file=sys.stderr)
            try:
                _diag(f"FATAL config [{category}]")
            except Exception:
                pass
            return 1
        if _stop_event.is_set():
            return status

        apply_config(cfg)
        if cfg.config_path is None:
            _diag("config: using defaults")
        _diag(startup_diag_line(cfg))
        _diag(f"ActivityLogger v{__version__} starting, LOG_DIR={LOG_DIR}")

        if not acquire_instance_lock():
            _diag("FATAL: another ActivityLogger instance holds the lock, exiting")
            return 1
        acquired_instance_lock = True
        _pause_manual = initial_manual_pause()
        _set_pause(manual=_pause_manual)
        for signum in (signal.SIGUSR1, signal.SIGUSR2):
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, _request_manual_control)
        if not _publish_runtime_state(running=True):
            _manual_state_dirty.set()
        startup_stamp = datetime.now().astimezone()
        startup_day = startup_stamp.date()
        try:
            _analysis_heading_by_day.update(
                _initialize_analysis_persistence(startup_day)
            )
        except Exception as e:
            _diag(
                "FATAL authoritative startup validation "
                f"[{_exception_category(e)}]"
            )
            return 1
        _analysis_runtime_enabled = ANALYSIS_SHADOW_ENABLED
        _analysis_idle_active = False
        _analysis_last_heartbeat_mono = None
        with _lock:
            _append_analysis_marker_locked("session_start", f"version={__version__}")
        if not PYNPUT_AVAILABLE:
            _diag("FATAL: pynput is not installed")
            return 1

        if _analysis_only_day(startup_day):
            _diag(f"Analysis v2 is authoritative for {startup_day.isoformat()}")
        else:
            filepath = _get_filepath(startup_stamp)
            if not filepath.exists() or filepath.stat().st_size == 0:
                if _write_to_file(
                    filepath,
                    _log_header_lines(
                        captured_at=startup_stamp,
                        include_started=True,
                    ),
                    append=False,
                ):
                    _diag(f"Log file created: {filepath}")
                else:
                    _diag(f"Failed to create log file at {filepath}")
                    return 1
            else:
                _diag(f"Log file exists: {filepath}")

        app, title = resolve_window()
        body = build_heading_body(app, title)
        if body:
            applied = apply_resolved_window(app, title)
            if not applied:
                _diag("Window context could not be verified; capture remains paused")
            elif app and title:
                _diag("Native window context verified")
            elif app:
                _diag("Native app verified; window title empty")
            else:
                _diag("Window context resolved by enricher")
            if ACTIVITYWATCH_ENRICHER:
                _diag("ActivityWatch enricher enabled")
            else:
                _diag("ActivityWatch enricher disabled")
        else:
            _diag("No frontmost app detected, events will use fallback heading")
            if ACTIVITYWATCH_ENRICHER:
                _diag("ActivityWatch enricher enabled but no app/title yet")
            else:
                _diag("ActivityWatch enricher disabled; native titles empty")

        targets = [
            (_ax_worker_loop, "ax-worker"),
            (window_checker_loop, "window-checker"),
            (clipboard_checker_loop, "clipboard-checker"),
            (file_writer_loop, "file-writer"),
            (typing_pause_idle_loop, "typing-pause"),
        ]
        if SCROLL_COALESCE_ENABLED:
            targets.append((scroll_coalesce_idle_loop, "scroll-coalesce"))
        for target, name in targets:
            worker = threading.Thread(
                target=_run_worker, args=(target,), daemon=True, name=name
            )
            worker.start()
            workers.append(worker)

        m_listener, _scroll_note = create_mouse_listener_safe(on_click=on_click)
        if m_listener is None:
            _diag("FATAL: could not start mouse listener")
            return 1
        k_listener = keyboard.Listener(on_press=on_press, on_release=on_release)
        m_listener.start()
        k_listener.start()
        _diag("Keyboard and mouse listeners started")

        try:
            from review_center import create_review_center_runtime

            review_center_runtime = create_review_center_runtime(
                LOG_DIR,
                pause_callback=lambda active: _set_pause(review=active),
            )
            _diag("Review Center ready")
        except Exception as e:
            _diag_rate_limited(
                f"Review Center unavailable [{_exception_category(e)}]"
            )

        while not _stop_event.is_set():
            if review_center_runtime is not None:
                review_center_runtime.pump()
            if _manual_state_dirty.is_set():
                _apply_pending_manual_control()
            if _fatal_worker_event.is_set():
                status = 1
                break
            if hasattr(k_listener, "is_alive") and not k_listener.is_alive():
                _diag("FATAL: keyboard listener stopped unexpectedly")
                status = 1
                break
            if hasattr(m_listener, "is_alive") and not m_listener.is_alive():
                _diag("FATAL: mouse listener stopped unexpectedly")
                status = 1
                break
            _stop_event.wait(0.05 if review_center_runtime is not None else 0.5)
        if _fatal_worker_event.is_set():
            status = 1
    except Exception as e:
        _diag(f"FATAL runtime [{_exception_category(e)}]")
        status = 1
    finally:
        if review_center_runtime is not None:
            try:
                review_center_runtime.close()
            except Exception as e:
                _diag_rate_limited(
                    f"Review Center cleanup failed [{_exception_category(e)}]"
                )
        _request_stop()
        if not _stop_and_join_listeners(m_listener, k_listener):
            status = 1
        for worker in workers:
            worker.join(timeout=WORKER_JOIN_TIMEOUT_SEC)
            if worker.is_alive():
                _diag(f"FATAL: worker did not stop: {worker.name}")
                status = 1
        if acquired_instance_lock:
            _discard_all_pending_clicks()
            flush_scroll_burst_on_shutdown()
            with _lock:
                reason = _shutdown_reason or "normal"
                _append_analysis_marker_locked("session_stop", reason)
            _file_flush_deadline = None
            if not flush_to_file():
                status = 1
            elif _pending_storage_gap is not None and not flush_to_file():
                status = 1
            _analysis_runtime_enabled = False
            _analysis_idle_active = False
            _analysis_last_heartbeat_mono = None
            _publish_runtime_state(running=False)
            _close_instance_lock()
        if _shutdown_reason is not None:
            _diag(f"shutdown requested {_shutdown_reason}")
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    return status


if __name__ == "__main__":
    sys.exit(main())
