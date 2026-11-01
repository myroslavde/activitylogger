"""Importable test helpers (not pytest conftest, safe to ``import helpers``)."""

from __future__ import annotations

import itertools
import queue
from dataclasses import replace
from pathlib import Path
from typing import Any

import interleaved_logger as il
from config import default_config


def enable_features(tmp_path: Path, **flags: Any) -> None:
    """Apply default_config with log_dir under tmp_path and feature flags."""
    cfg = replace(default_config(), log_dir=Path(tmp_path) / "logs", **flags)
    il.apply_config(cfg)


def seed_keys(tokens: list[str], *, at: float | None = None) -> None:
    """Fill the keystroke buffer; optionally mark activity at monotonic ``at``."""
    with il._lock:
        il._current_keystrokes.clear()
        il._current_keystrokes.extend(tokens)
    if at is not None:
        il.note_key_activity(now=at)


# Back-compat alias for older test call sites.
_seed_keys = seed_keys


def clear_logger_runtime() -> None:
    """Clear buffers, pause/url/scroll state, and drain the AX queue."""
    with il._lock:
        il._current_heading = "App - Window"
        il._heading_native_context = None
        il._current_keystrokes.clear()
        il._current_events.clear()
        il._sections.clear()
        il._last_screen_text = ""
        il._last_clipboard_count = 0
        il._last_clipboard_text = ""
        il._last_clipboard_digest = ""
        il._last_clipboard_privacy_generation = 0
        il._last_emitted_url = None
        il._pause_secure_app = False
        il._pause_secure_field = False
        il._pause_manual = False
        il._pause_review_center = False
        il._is_paused = False
        il._current_modifiers.clear()
        il._physical_modifiers.clear()
        il._modifier_counts.clear()
        il._secure_field_cache = False
        il._secure_field_cache_known = False
        il._secure_field_cache_at = 0.0
        il._secure_field_generation = 0
        il._secure_field_recheck_mono = None
        il._privacy_generation = 0
        il._manual_control_revision = 0
        il._manual_control_pending = None
        il._manual_state_retry_at = 0.0
        il._manual_state_retry_delay = 0.0
        il._window_bucket = None
        il._scan_pending = False
        il._last_key_activity_mono = None
        il._last_key_flush_cause = None
        il._key_flush_hook = None
        il._scroll_burst = None
        il._scroll_diag_emitted = False
        il._pending_clicks.clear()
        il._analysis_heading_by_day.clear()
        il._analysis_markers.clear()
        il._analysis_marker_overflow_days.clear()
        il._analysis_runtime_enabled = False
        il._analysis_idle_active = False
        il._analysis_last_heartbeat_mono = None
        il._wall_clock_last = None
        il._analysis_sequence = itertools.count(1)
        il._window_apply_generation = 0
        il._flush_failed = False
        il._storage_blocked = False
        il._storage_gap_started_at = None
        il._pending_storage_gap = None
        il._file_flush_deadline = None
        il._file_retry_delay = 0.0
        il._readiness_reconciled_day = None
        il._readiness_candidates.clear()
    il._stop_event.clear()
    il._shutdown_reason = None
    il._key_deadline_changed.clear()
    il._scroll_deadline_changed.clear()
    il._writer_wakeup.clear()
    il._fatal_worker_event.clear()
    il._manual_state_dirty.clear()
    il._state.reset_runtime_controls()
    # Unit tests exercise key encoding without a live NSWorkspace frontmost app.
    il._state.last_secure_app_pid = 0
    il._state.last_secure_app_context = (0, "test", "")
    il._state.last_secure_app_is_secure = False
    while True:
        try:
            il._ax_jobs.get_nowait()
            il._ax_jobs.task_done()
        except queue.Empty:
            break


def apply_reset_logger_state(tmp_path: Path, **config_overrides: Any) -> None:
    """apply_config(log_dir under tmp_path, **overrides) then clear runtime state."""
    enable_features(tmp_path, **config_overrides)
    clear_logger_runtime()
