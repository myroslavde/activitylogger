"""Native, payload-free Review Center for ActivityLogger operators."""

from __future__ import annotations

import json
import os
import stat
import sys
import threading
import time
from dataclasses import dataclass, replace
from datetime import date, datetime, timedelta
from pathlib import Path

from analysis_log import ANALYSIS_FORMAT_V2
from analysis_view import DEFAULT_OUTPUT_DIR, workload_view_path
from operator_controls import (
    OUTCOMES_NAME,
    health_report,
    record_review_outcome,
    set_manual_pause,
    storage_report,
)
from operator_errors import OperatorError, safe_error_message
from private_files import open_private_file, read_private_bytes
from weekly_review import (
    INDEX_NAME,
    PROMPT_NAME,
    WEEKLY_PACK_FORMAT,
    create_weekly_review_pack,
    weekly_pack_name,
    weekly_window_dates,
    weekly_window_status,
)

try:
    import objc
    from AppKit import (
        NSAccessibilityPostNotification,
        NSAccessibilityHeadingRole,
        NSAccessibilityValueChangedNotification,
        NSAnyEventMask,
        NSApplication,
        NSApplicationActivationPolicyAccessory,
        NSBackingStoreBuffered,
        NSBezelStyleRounded,
        NSButton,
        NSDatePicker,
        NSDatePickerStyleTextFieldAndStepper,
        NSDefaultRunLoopMode,
        NSFont,
        NSLayoutAttributeLeading,
        NSLayoutConstraint,
        NSLineBreakByWordWrapping,
        NSMakePoint,
        NSMakeRect,
        NSMakeSize,
        NSNoBorder,
        NSObject,
        NSPopUpButton,
        NSScrollView,
        NSStackView,
        NSTextField,
        NSTabView,
        NSTabViewItem,
        NSUserInterfaceLayoutOrientationHorizontal,
        NSUserInterfaceLayoutOrientationVertical,
        NSView,
        NSViewHeightSizable,
        NSViewWidthSizable,
        NSWindow,
        NSWindowStyleMaskClosable,
        NSWindowStyleMaskMiniaturizable,
        NSWindowStyleMaskResizable,
        NSWindowStyleMaskTitled,
        NSYearMonthDayDatePickerElementFlag,
        NSWorkspace,
    )
    from Foundation import NSDate, NSURL
    from PyObjCTools import AppHelper

    APPKIT_AVAILABLE = True
except ImportError:
    APPKIT_AVAILABLE = False


@dataclass(frozen=True)
class ReviewCenterSnapshot:
    health: str
    freshness: str
    pause_state: str
    manual_paused: bool | None
    can_toggle_pause: bool
    pack_state: str
    coverage: str
    can_prepare: bool
    can_show: bool
    storage: str
    capture_state: str = "unknown"
    pack_status: str = "unready"
    pause_reasons: tuple[str, ...] = ()
    checked_at: str = "Not checked"
    problems: str = ""
    quality: str = ""
    can_show_results: bool = False
    runtime_state_updated_at: str | None = None
    runtime_state_age_seconds: int | None = None


OUTCOME_VALUES = {
    "Found an idea to try": "accepted",
    "Tried a change": "tried",
    "No action": "ignored",
}
MAX_REVIEW_INDEX_BYTES = 1024 * 1024
MAX_OUTCOME_CHARACTERS = 4000
PAUSE_REASON_TEXT = {
    "manual": "manual pause",
    "secure_app": "secure app",
    "secure_field": "secure or unverified field",
    "review_window": "Review Center window",
    "storage": "storage needs attention",
}


def _capture_status(state: str, reasons: tuple[str, ...], window_paused: bool) -> str:
    if state == "stopped":
        return "Capture is stopped."
    labels = [PAUSE_REASON_TEXT[reason] for reason in reasons if reason in PAUSE_REASON_TEXT]
    if window_paused and "Review Center window" not in labels:
        labels.append("Review Center window")
    if window_paused or state == "paused":
        detail = ", ".join(labels) or "privacy check"
        suffix = " Other capture state is unverified." if state == "unknown" else ""
        return f"Capture is paused: {detail}.{suffix}"
    return "Capture is active." if state == "active" else "Capture state is unverified."


def _private_file_is_safe(path: Path) -> bool:
    try:
        fd, _info = open_private_file(path)
    except OSError:
        return False
    os.close(fd)
    return True


def _private_index_bytes(path: Path) -> bytes | None:
    try:
        return read_private_bytes(path, max_bytes=MAX_REVIEW_INDEX_BYTES)
    except OSError:
        return None


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _format_bytes(value: object) -> str:
    try:
        size = max(0, int(value))
    except (TypeError, ValueError):
        return "unknown"
    amount = float(size)
    for unit in ("bytes", "KB", "MB", "GB"):
        if amount < 1024 or unit == "GB":
            return f"{amount:.0f} {unit}" if unit == "bytes" else f"{amount:.1f} {unit}"
        amount /= 1024
    return "unknown"


def _health_issues(health: dict[str, object]) -> tuple[str, ...]:
    issues: list[str] = []
    if health.get("invalid_marker") is True:
        issues.append("the current log has an invalid marker")
    if health.get("format") != ANALYSIS_FORMAT_V2:
        issues.append("the current log format could not be verified")
    if health.get("intent_match") is not True:
        issues.append("the intent journal does not match the current log")

    expected_modes = {
        "log_dir_mode": frozenset({"700", "missing"}),
        "analysis_mode": frozenset({"600", "missing"}),
        "intent_mode": frozenset({"600", "missing"}),
        "ready_mode": frozenset({"600", "missing"}),
        "runtime_dir_mode": frozenset({"700", "missing"}),
        "lock_mode": frozenset({"600", "missing"}),
        "state_mode": frozenset({"600", "missing"}),
    }
    if any(
        name in health and health[name] not in allowed
        for name, allowed in expected_modes.items()
    ):
        issues.append("private file or directory permissions are unsafe")
    return tuple(issues)


class ReviewCenterModel:
    """Payload-free data and actions shared by the native window and tests."""

    def __init__(
        self,
        log_dir: Path,
        *,
        output_dir: Path = DEFAULT_OUTPUT_DIR,
        home: Path | None = None,
    ) -> None:
        self.log_dir = Path(log_dir)
        self.output_dir = Path(output_dir)
        self.home = home

    def snapshot(
        self,
        end: date,
        days: int,
        *,
        today: date | None = None,
    ) -> ReviewCenterSnapshot:
        current_day = today or datetime.now().astimezone().date()
        checked_at = datetime.now().astimezone().isoformat(timespec="seconds")
        inspections = {}
        errors = {}
        try:
            health = health_report(
                self.log_dir, current_day, home=self.home, inspections=inspections
            )
        except Exception as error:
            health = {}
            errors["health"] = safe_error_message(error)
        try:
            storage = storage_report(
                self.log_dir, output_dir=self.output_dir, today=current_day,
                inspections=inspections,
            )
        except Exception as error:
            storage = {}
            errors["storage"] = safe_error_message(error)
        try:
            window = weekly_window_status(
                self.log_dir, end, days, today=current_day, inspections=inspections
            )
        except Exception as error:
            window = None
            errors["window"] = safe_error_message(error)

        running = health.get("running") is True
        valid_state = health.get("runtime_state_valid") is True
        manual = health.get("manual_paused") if valid_state else None
        manual_paused = manual if type(manual) is bool else None
        capture = health.get("capture_paused") if valid_state else None
        capture_state = (
            "unknown" if not health or (running and type(capture) is not bool)
            else "stopped" if not running
            else "paused" if capture or health.get("storage_blocked") is True
            else "active"
        )
        reasons = tuple(
            reason for reason in health.get("pause_reasons", ())
            if reason in PAUSE_REASON_TEXT
        )
        issues = _health_issues(health) if health else ()
        if "health" in errors:
            health_text = "Logger health is unavailable. " + errors["health"]
        elif issues:
            prefix = "Logger is running" if running else "Logger is not running"
            health_text = f"{prefix}, but health is degraded: {'; '.join(issues)}."
        else:
            health_text = "Logger is running." if running else "Logger is not running."
        freshness_value = health.get("freshness_seconds")
        freshness = (
            f"Last verified safe write was {freshness_value} seconds ago."
            if isinstance(freshness_value, int)
            else "Last verified safe write is not available."
        )
        pause_state = (
            "Manual privacy pause is on." if manual_paused is True
            else "Manual privacy pause is off." if manual_paused is False
            else "Manual privacy state is unverified."
        )

        prepared_pack = self.prepared_pack(end, days, today=current_day)
        pack_path = self.output_dir / weekly_pack_name(end, days)
        pack_present = pack_path.exists() or pack_path.is_symlink()
        if prepared_pack is not None:
            pack_status = "prepared"
            selected = weekly_window_dates(end, days)
            pack_state = f"Review files are ready for {selected[0]} through {selected[-1]}."
        elif pack_present:
            pack_status = "blocked"
            pack_state = "The selected review files are incomplete or unsafe."
        elif window is not None and window.ready:
            pack_status = "ready"
            pack_state = f"Ready to create files for {window.start} through {window.end}."
        elif window is not None:
            pack_status = "unready"
            issue_count = sum(item.state != "ready" for item in window.day_statuses)
            noun = "day needs" if issue_count == 1 else "days need"
            pack_state = f"Not ready. {issue_count} selected {noun} attention."
        else:
            pack_status = "unavailable"
            pack_state = "Selected day checks are unavailable. " + errors["window"]

        if "storage" in errors:
            storage_text = "Storage summary is unavailable. " + errors["storage"]
        else:
            storage_text = (
                f"{_format_bytes(storage.get('total_private_log_bytes'))} of private logs. "
                f"{_format_bytes(storage.get('private_review_bytes', 0))} of review files. "
                f"{storage.get('completed_days', 0)} completed day(s), "
                f"{storage.get('review_packs', 0)} review folder(s)."
            )
        problem_lines = [
            f"{item['day']}: {item['state']} ({item['reason']})."
            for item in storage.get("problem_days", ())
        ]
        for key, label in (
            ("malformed_day_count", "file(s) with an invalid date"),
            ("unsafe_files", "unsafe log item(s)"),
            ("unsafe_review_items", "unsafe review item(s)"),
            ("incomplete_review_packs", "incomplete review folder(s)"),
        ):
            if storage.get(key):
                problem_lines.append(f"{storage[key]} {label}.")
        problems = "\n".join(problem_lines) or "No storage or completed-day problems reported."
        if "storage" in errors:
            problems = "Storage and completed-day problems could not be checked."
        state_help = {
            "active": "is still active. Choose an earlier end date.",
            "unsupported": "uses an older format. Choose newer dates.",
            "invalid": "failed a safety check. Use Recovery help before changing its files.",
            "missing": "is missing required files. Restore them or choose other dates; see Recovery help.",
            "unready": "has not passed its safety check. Use Recovery help before changing its files.",
        }
        coverage = ["File checks do not prove that every activity was captured."]
        quality = []
        total_bytes = total_workload = 0
        for item in window.day_statuses if window is not None else ():
            if item.state != "ready":
                coverage.append(f"{item.day} {state_help.get(item.state, 'needs attention.')}")
            data = getattr(item, "quality", {})
            total_bytes += data.get("source_bytes", 0)
            total_workload += data.get("workload_events", 0)
            quality.extend(f"{item.day}: {warning}" for warning in data.get("warnings", ()))
        if window is not None:
            quality.insert(0, f"Source size: {_format_bytes(total_bytes)}. {total_workload} observed workload events.")
            if len(quality) == 1:
                quality.append("No extra context quality warnings reported. This does not prove full capture.")
        else:
            quality.append("Context quality could not be checked. Use the pack's quality and loss notes.")
        return ReviewCenterSnapshot(
            health=health_text, freshness=freshness, pause_state=pause_state,
            manual_paused=manual_paused, can_toggle_pause=running,
            pack_state=pack_state, coverage="\n".join(coverage),
            can_prepare=pack_status == "ready", can_show=prepared_pack is not None,
            storage=storage_text, capture_state=capture_state, pack_status=pack_status,
            pause_reasons=reasons, checked_at=checked_at, problems=problems,
            quality="\n".join(quality), can_show_results=self.saved_results() is not None,
            runtime_state_updated_at=health.get("state_updated_at") if valid_state else None,
            runtime_state_age_seconds=health.get("state_age_seconds") if valid_state else None,
        )

    def prepared_pack(
        self,
        end: date,
        days: int,
        *,
        today: date | None = None,
    ) -> Path | None:
        """Return the exact selected pack only when every private path is safe."""
        if days not in (5, 7):
            return None
        selected_days = weekly_window_dates(end, days)
        pack_dir = self.output_dir / weekly_pack_name(end, days)
        for path in (self.output_dir, pack_dir):
            try:
                info = path.lstat()
            except OSError:
                return None
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700
            ):
                return None

        workload_files = tuple(
            workload_view_path(pack_dir, selected_day) for selected_day in selected_days
        )
        expected_files = (pack_dir / PROMPT_NAME, *workload_files)
        indexed_names = {path.name for path in expected_files}
        known_names = indexed_names | {INDEX_NAME}
        try:
            extras = tuple(
                path for path in pack_dir.iterdir() if path.name not in known_names
            )
        except OSError:
            return None
        if any(not _private_file_is_safe(path) for path in extras):
            return None
        index_bytes = _private_index_bytes(pack_dir / INDEX_NAME)
        if index_bytes is None:
            return None
        try:
            index = json.loads(index_bytes.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError, RecursionError):
            return None
        if not isinstance(index, dict) or index.get("format") != WEEKLY_PACK_FORMAT:
            return None
        if index.get("window") != {
            "start": selected_days[0].isoformat(),
            "end": selected_days[-1].isoformat(),
            "calendar_days": days,
            "complete_fixed_window": True,
            "older_day_substitution": False,
        }:
            return None

        files = index.get("files")
        if (
            not isinstance(files, dict)
            or set(files) != indexed_names
            or not all(_is_sha256(digest) for digest in files.values())
        ):
            return None

        day_entries = index.get("days")
        if not isinstance(day_entries, list) or len(day_entries) != days:
            return None
        for entry, selected_day, workload_file in zip(
            day_entries,
            selected_days,
            workload_files,
            strict=True,
        ):
            if (
                not isinstance(entry, dict)
                or entry.get("day") != selected_day.isoformat()
            ):
                return None
            output = entry.get("output")
            sources = entry.get("sources")
            if (
                not isinstance(output, dict)
                or output.get("file") != workload_file.name
                or output.get("sha256") != files[workload_file.name]
                or not isinstance(sources, dict)
                or not sources
                or not all(_is_sha256(digest) for digest in sources.values())
            ):
                return None

        # Safe redaction is expected. Stored hashes describe creation time only,
        # so reopening must not compare them with edited file contents.
        if any(not _private_file_is_safe(path) for path in expected_files):
            return None
        return pack_dir

    def prepare(self, end: date, days: int):
        return create_weekly_review_pack(
            self.log_dir,
            self.output_dir,
            end=end,
            days=days,
        )

    def set_manual_pause(self, paused: bool):
        return set_manual_pause(paused, home=self.home)

    def saved_results(self) -> Path | None:
        try:
            info = self.output_dir.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                return None
        except OSError:
            return None
        path = self.output_dir / OUTCOMES_NAME
        return path if _private_file_is_safe(path) else None

    def record_outcome(
        self, week: date, days: int, outcome: str, value_result: str, notes: str,
    ) -> Path:
        if self.prepared_pack(week, days) is None:
            raise OperatorError("incomplete_window")
        return record_review_outcome(
            week, outcome, value_result, notes, days=days, output_dir=self.output_dir,
        )


if APPKIT_AVAILABLE:

    def _label(text: str, *, bold: bool = False, wrap: bool = False):
        field = NSTextField.labelWithString_(text)
        if bold:
            field.setFont_(NSFont.boldSystemFontOfSize_(13))
        if wrap:
            field.setLineBreakMode_(NSLineBreakByWordWrapping)
            field.setMaximumNumberOfLines_(0)
            field.setPreferredMaxLayoutWidth_(560)
        return field

    def _row(*views):
        stack = NSStackView.stackViewWithViews_(list(views))
        stack.setOrientation_(NSUserInterfaceLayoutOrientationHorizontal)
        stack.setSpacing_(8)
        return stack

    def _column(*views):
        stack = NSStackView.stackViewWithViews_(list(views))
        stack.setOrientation_(NSUserInterfaceLayoutOrientationVertical)
        stack.setAlignment_(NSLayoutAttributeLeading)
        stack.setSpacing_(7)
        return stack

    def _heading(text: str):
        field = _label(text, bold=True)
        field.setAccessibilityRole_(NSAccessibilityHeadingRole)
        field.setAccessibilityLabel_(text)
        return field

    def _scroll_column(views):
        root = _column(*views)
        root.setSpacing_(16)
        root.setTranslatesAutoresizingMaskIntoConstraints_(False)
        scroll = NSScrollView.alloc().initWithFrame_(NSMakeRect(0, 0, 640, 500))
        scroll.setBorderType_(NSNoBorder)
        scroll.setHasVerticalScroller_(True)
        scroll.setAutohidesScrollers_(True)
        scroll.setAutoresizingMask_(NSViewWidthSizable | NSViewHeightSizable)
        document = NSView.alloc().initWithFrame_(scroll.bounds())
        document.setAutoresizingMask_(NSViewWidthSizable)
        document.addSubview_(root)
        scroll.setDocumentView_(document)
        NSLayoutConstraint.activateConstraints_([
            root.leadingAnchor().constraintEqualToAnchor_constant_(document.leadingAnchor(), 16),
            root.trailingAnchor().constraintEqualToAnchor_constant_(document.trailingAnchor(), -16),
            root.topAnchor().constraintEqualToAnchor_constant_(document.topAnchor(), 16),
            root.bottomAnchor().constraintLessThanOrEqualToAnchor_constant_(document.bottomAnchor(), -16),
        ])
        for view in views:
            view.widthAnchor().constraintEqualToAnchor_(root.widthAnchor()).setActive_(True)
        return scroll, document, root

    def _button(title: str, target, action: bytes):
        button = NSButton.buttonWithTitle_target_action_(title, target, action)
        button.setBezelStyle_(NSBezelStyleRounded)
        return button

    def _show_review_prompt_in_finder(prompt: Path) -> None:
        NSWorkspace.sharedWorkspace().activateFileViewerSelectingURLs_(
            [NSURL.fileURLWithPath_(str(prompt))]
        )

    class ReviewCenterWindowController(NSObject):
        def initWithModel_(self, model):
            return self.initWithModel_pauseCallback_(model, None)

        def initWithModel_pauseCallback_(self, model, pause_callback):
            self = objc.super(ReviewCenterWindowController, self).init()
            if self is None:
                return None
            self.model = model
            self.pause_callback = pause_callback
            self.window_privacy_active = False
            self.busy = False
            self.last_snapshot = None
            self.initial_scroll_pending = True
            self.displayed_selection = None
            self._build_window()
            return self

        @objc.python_method
        def _build_window(self) -> None:
            mask = (
                NSWindowStyleMaskTitled
                | NSWindowStyleMaskClosable
                | NSWindowStyleMaskMiniaturizable
                | NSWindowStyleMaskResizable
            )
            self.window = NSWindow.alloc().initWithContentRect_styleMask_backing_defer_(
                NSMakeRect(0, 0, 680, 760),
                mask,
                NSBackingStoreBuffered,
                False,
            )
            self.window.setTitle_("ActivityLogger Review Center")
            self.window.setMinSize_(NSMakeSize(620, 620))
            self.window.setReleasedWhenClosed_(False)
            self.window.setDelegate_(self)
            self.window.center()

            title = _heading("ActivityLogger")
            title.setFont_(NSFont.boldSystemFontOfSize_(20))
            subtitle = _label(
                "Create private review files from recent activity. Use the files with "
                "a tool you trust to look for repeated work, friction, and useful "
                "small changes.",
                wrap=True,
            )
            self.limit_label = _label(
                "ActivityLogger creates the files. It does not analyze or send them.",
                wrap=True,
            )
            self.limit_label.setAccessibilityLabel_("Review limit")
            self.review_pause_notice = _label(
                "While this window is visible, it adds a privacy pause. Closing or "
                "minimizing removes this window's pause. Capture may stay paused for "
                "manual, secure, or storage reasons.",
                wrap=True,
            )
            self.review_pause_notice.setAccessibilityLabel_(
                "Review Center privacy pause"
            )

            self.step_one_heading = _heading("1. Create review files")
            step_one_text = _label(
                "Choose an end date and include 5 or 7 completed calendar days.",
                wrap=True,
            )
            self.end_picker = NSDatePicker.alloc().init()
            self.end_picker.setDatePickerStyle_(NSDatePickerStyleTextFieldAndStepper)
            self.end_picker.setDatePickerElements_(NSYearMonthDayDatePickerElementFlag)
            self.end_picker.setAccessibilityLabel_("Weekly review end date")
            yesterday = datetime.now().astimezone().date() - timedelta(days=1)
            self.date_limit = yesterday
            self.end_picker.setDateValue_(self._date_to_nsdate(yesterday))
            self.end_picker.setMaxDate_(self._date_to_nsdate(yesterday))
            self.end_picker.setTarget_(self)
            self.end_picker.setAction_(b"selectionAction:")

            self.days_popup = NSPopUpButton.alloc().initWithFrame_pullsDown_(
                NSMakeRect(0, 0, 100, 28), False
            )
            self.days_popup.addItemsWithTitles_(["5 days", "7 days"])
            self.days_popup.setAccessibilityLabel_("Weekly review period")
            self.days_popup.setTarget_(self)
            self.days_popup.setAction_(b"selectionAction:")
            self.prepare_button = _button(
                "Create review files", self, b"prepareAction:"
            )
            self.prepare_button.setAccessibilityHelp_(
                "Create private review files for the selected completed days."
            )
            self.prepare_help_label = _label("Checking selected days...", wrap=True)
            self.prepare_help_label.setAccessibilityLabel_(
                "Create review files availability"
            )
            self.pack_state_label = _label("Loading review file status...", wrap=True)
            self.pack_state_label.setAccessibilityLabel_("Review file status")
            self.coverage_label = _label("Loading source checks...", wrap=True)
            self.coverage_label.setAccessibilityLabel_("Source check details")

            self.step_two_heading = _heading("2. Review the files")
            step_two_text = _label(
                "Start with REVIEW_PROMPT.md in a trusted local tool. Review and redact "
                "private text before using any online tool.",
                wrap=True,
            )
            self.step_two_text = step_two_text
            pack_warning = _label(
                "These files may contain captured private text. Review and redact them "
                "before sharing.",
                wrap=True,
            )
            pack_warning.setAccessibilityLabel_("Weekly pack privacy warning")
            self.show_button = _button(
                "Show review files in Finder", self, b"showReviewAction:"
            )
            self.show_button.setAccessibilityHelp_(
                "Show the safe selected review folder and select REVIEW_PROMPT.md."
            )
            self.show_help_label = _label("Create Step 1 first.", wrap=True)
            self.show_help_label.setAccessibilityLabel_(
                "Show review files availability"
            )

            self.step_three_heading = _heading("3. Record what happened")
            step_three_text = _label(
                "After you review the files, save the result and any value you found.",
                wrap=True,
            )
            self.outcome_popup = NSPopUpButton.alloc().initWithFrame_pullsDown_(
                NSMakeRect(0, 0, 160, 28), False
            )
            self.outcome_popup.addItemsWithTitles_(["Choose a result", *OUTCOME_VALUES])
            self.outcome_popup.setAccessibilityLabel_("Weekly review outcome")
            self.outcome_popup.setTarget_(self)
            self.outcome_popup.setAction_(b"outcomeAction:")
            self.value_field = NSTextField.alloc().init()
            self.value_field.setPlaceholderString_(
                "Example: Saved 20 minutes each Friday"
            )
            self.value_field.setAccessibilityLabel_("Weekly review value result")
            self.value_field.setDelegate_(self)
            self.notes_field = NSTextField.alloc().init()
            self.notes_field.setPlaceholderString_("Optional notes")
            self.notes_field.setAccessibilityLabel_("Weekly review notes")
            self.notes_field.setDelegate_(self)
            self.length_label = _label("Each text field allows up to 4,000 characters.", wrap=True)
            self.length_label.setAccessibilityLabel_("Review text limits")
            self.clear_draft_button = _button("Clear draft", self, b"clearDraftAction:")
            self.clear_draft_button.setAccessibilityHelp_("Clear this unsaved result and its notes.")
            self.show_results_button = _button("Show saved results", self, b"showResultsAction:")
            self.show_results_button.setAccessibilityHelp_("Select the private saved-result journal in Finder.")
            self.record_button = _button(
                "Save review result", self, b"recordOutcomeAction:"
            )
            self.record_button.setAccessibilityHelp_(
                "Choose a result after safe review files are ready."
            )
            self.record_help_label = _label("Create Step 1 first.", wrap=True)
            self.record_help_label.setAccessibilityLabel_(
                "Save review result availability"
            )

            self.action_status_label = _label("Loading local status...", wrap=True)
            self.action_status_label.setAccessibilityLabel_("Action status")
            self.action_status_label.setSelectable_(False)

            self.health_label = _label("Loading logger health...", wrap=True)
            self.health_label.setAccessibilityLabel_("Logger health")
            self.capture_label = _label("Capture state is unverified.", wrap=True)
            self.capture_label.setAccessibilityLabel_("Capture state and pause reasons")
            self.checked_label = _label("Status has not been checked.", wrap=True)
            self.checked_label.setAccessibilityLabel_("Status checked time")
            self.freshness_label = _label("Loading freshness...", wrap=True)
            self.freshness_label.setAccessibilityLabel_("Logger freshness")
            self.pause_state_label = _label("Loading manual pause...", wrap=True)
            self.pause_state_label.setAccessibilityLabel_("Manual privacy state")
            self.storage_label = _label("Loading storage summary...", wrap=True)
            self.storage_label.setAccessibilityLabel_("Private storage summary")
            self.problems_label = _label("Checking completed days...", wrap=True)
            self.problems_label.setAccessibilityLabel_("Storage and completed-day problems")
            self.quality_label = _label("Checking context quality...", wrap=True)
            self.quality_label.setAccessibilityLabel_("Selected review context quality")
            self.recovery_button = _button("Recovery help", self, b"recoveryAction:")
            self.recovery_button.setAccessibilityHelp_("Open the local guide for day checks and safe recovery.")
            self.pause_button = _button("Turn on manual pause", self, b"pauseAction:")
            self.pause_button.setAccessibilityHelp_(
                "Pause or resume capture through the shared manual privacy control."
            )
            self.refresh_button = _button("Refresh status", self, b"refreshAction:")
            self.refresh_button.setAccessibilityHelp_(
                "Refresh logger, review file, and storage status."
            )

            step_one = _column(
                self.step_one_heading,
                step_one_text,
                _row(
                    _label("Last day"),
                    self.end_picker,
                    _label("Period"),
                    self.days_popup,
                ),
                self.pack_state_label,
                self.coverage_label,
                self.quality_label,
                self.prepare_button,
                self.prepare_help_label,
            )
            step_two = _column(
                self.step_two_heading,
                step_two_text,
                pack_warning,
                self.show_button,
                self.show_help_label,
            )
            step_three = _column(
                self.step_three_heading,
                step_three_text,
                _row(_label("Result"), self.outcome_popup),
                _label("What value did you get? (optional)"),
                self.value_field,
                _label("Notes (optional)"),
                self.notes_field,
                self.length_label,
                _row(self.record_button, self.clear_draft_button),
                self.show_results_button,
                self.record_help_label,
            )
            daily_views = [
                _heading("Daily status"), self.health_label, self.capture_label,
                self.checked_label, self.freshness_label, self.pause_state_label,
                _row(self.pause_button, self.refresh_button),
                _heading("Private storage and completed days"), self.storage_label,
                self.problems_label, self.recovery_button,
            ]
            weekly_views = [
                _heading("Weekly Activity Review"), subtitle, self.limit_label,
                step_one, step_two, step_three,
            ]
            for section, fields in (
                (step_one, (step_one_text, self.pack_state_label, self.coverage_label,
                            self.quality_label, self.prepare_help_label)),
                (step_two, (step_two_text, pack_warning, self.show_help_label)),
                (step_three, (step_three_text, self.value_field, self.notes_field,
                              self.length_label, self.record_help_label)),
            ):
                for field in fields:
                    field.widthAnchor().constraintEqualToAnchor_(
                        section.widthAnchor()
                    ).setActive_(True)
            self.daily_panel = _scroll_column(daily_views)
            self.weekly_panel = _scroll_column(weekly_views)
            self.panels = (self.daily_panel, self.weekly_panel)
            self.tab_view = NSTabView.alloc().initWithFrame_(NSMakeRect(0, 0, 640, 520))
            self.tab_view.setTranslatesAutoresizingMaskIntoConstraints_(False)
            self.tab_view.setAccessibilityLabel_("ActivityLogger tasks")
            for identifier, name, panel in (
                ("daily", "Daily status", self.daily_panel),
                ("weekly", "Weekly review", self.weekly_panel),
            ):
                item = NSTabViewItem.alloc().initWithIdentifier_(identifier)
                item.setLabel_(name)
                item.setView_(panel[0])
                item.setInitialFirstResponder_(self.pause_button if identifier == "daily" else self.end_picker)
                self.tab_view.addTabViewItem_(item)
            self.tab_view.selectTabViewItemAtIndex_(0)
            self.tab_view.setDelegate_(self)
            shell = _column(title, self.review_pause_notice, self.tab_view, self.action_status_label)
            shell.setSpacing_(12)
            shell.setTranslatesAutoresizingMaskIntoConstraints_(False)
            content = self.window.contentView()
            content.addSubview_(shell)
            NSLayoutConstraint.activateConstraints_([
                shell.leadingAnchor().constraintEqualToAnchor_constant_(content.leadingAnchor(), 20),
                shell.trailingAnchor().constraintEqualToAnchor_constant_(content.trailingAnchor(), -20),
                shell.topAnchor().constraintEqualToAnchor_constant_(content.topAnchor(), 18),
                shell.bottomAnchor().constraintEqualToAnchor_constant_(content.bottomAnchor(), -18),
                self.tab_view.heightAnchor().constraintGreaterThanOrEqualToConstant_(300),
            ])
            for view in (title, self.review_pause_notice, self.tab_view, self.action_status_label):
                view.widthAnchor().constraintEqualToAnchor_(shell.widthAnchor()).setActive_(True)
            self.tab_view.setContentHuggingPriority_forOrientation_(1, NSUserInterfaceLayoutOrientationVertical)
            self.pack_warning = pack_warning
            self.displayed_selection = (self._selected_date(), self._selected_days())
            self._select_active_panel()
            self._layout_scroll_content()
            self.window.setAutorecalculatesKeyViewLoop_(False)
            self.window.setInitialFirstResponder_(self.pause_button)
            self._update_key_loop()
            self._set_busy(False)

        @objc.python_method
        def _select_active_panel(self) -> None:
            weekly = self.tab_view.selectedTabViewItem().identifier() == "weekly"
            self.scroll_view, self.scroll_document, self.root_stack = (
                self.weekly_panel if weekly else self.daily_panel
            )

        @objc.python_method
        def _update_key_loop(self) -> None:
            if self.tab_view.selectedTabViewItem().identifier() == "weekly":
                controls = (self.tab_view, self.end_picker, self.days_popup,
                            self.prepare_button, self.show_button, self.outcome_popup,
                            self.value_field, self.notes_field, self.record_button,
                            self.clear_draft_button, self.show_results_button)
            else:
                controls = (self.tab_view, self.pause_button, self.refresh_button,
                            self.recovery_button)
            for current, following in zip(controls, (*controls[1:], controls[0])):
                current.setNextKeyView_(following)

        def tabView_didSelectTabViewItem_(self, _tab_view, _item):
            if not hasattr(self, "panels"):
                return
            self._select_active_panel()
            self._update_key_loop()
            self._layout_scroll_content()
            self._scroll_to_visual_top()
            self._set_action_status("Daily status selected." if _item.identifier() == "daily"
                                    else "Weekly review selected.")

        @objc.python_method
        def _layout_scroll_content(self) -> None:
            for scroll, document, root in self.panels:
                clip = scroll.contentSize()
                document.setFrameSize_(NSMakeSize(clip.width, document.frame().size.height))
                needed = root.fittingSize().height + 32
                document.setFrameSize_(NSMakeSize(clip.width, max(clip.height, needed)))

        @objc.python_method
        def _scroll_to_visual_top(self) -> None:
            clip = self.scroll_view.contentSize()
            height = self.scroll_document.frame().size.height
            self.scroll_view.contentView().scrollToPoint_(NSMakePoint(0, max(0, height - clip.height)))
            self.scroll_view.reflectScrolledClipView_(self.scroll_view.contentView())

        @objc.python_method
        def _date_to_nsdate(self, value: date):
            stamp = (
                datetime.combine(
                    value,
                    datetime.min.time(),
                )
                .astimezone()
                .replace(hour=12)
            )
            return NSDate.dateWithTimeIntervalSince1970_(stamp.timestamp())

        @objc.python_method
        def _selected_date(self) -> date:
            stamp = self.end_picker.dateValue().timeIntervalSince1970()
            return datetime.fromtimestamp(stamp).astimezone().date()

        @objc.python_method
        def _selected_days(self) -> int:
            return (5, 7)[self.days_popup.indexOfSelectedItem()]

        @objc.python_method
        def _refresh_date_limit(self, today: date | None = None) -> None:
            new_limit = (today or datetime.now().astimezone().date()) - timedelta(
                days=1
            )
            selected = self._selected_date()
            picker_limit = max(selected, new_limit) if self._has_draft() else new_limit
            self.end_picker.setMaxDate_(self._date_to_nsdate(picker_limit))
            if selected == self.date_limit and not self._has_draft() and not self.busy:
                self.end_picker.setDateValue_(self._date_to_nsdate(new_limit))
            elif self._has_draft():
                self.end_picker.setDateValue_(self._date_to_nsdate(selected))
            self.date_limit = new_limit
            self._accept_review_selection((self._selected_date(), self._selected_days()))
            self._update_action_controls()

        @objc.python_method
        def _accept_review_selection(self, selection: tuple[date, int]) -> None:
            if selection == self.displayed_selection:
                return
            self.displayed_selection = selection
            pack_state = "Selected review dates have not been checked. Refresh status."
            coverage = "File checks do not prove that every activity was captured."
            quality = "Context quality has not been checked for these dates."
            if self.last_snapshot is not None:
                self.last_snapshot = replace(
                    self.last_snapshot, pack_state=pack_state, pack_status="unavailable",
                    coverage=coverage, quality=quality, can_prepare=False, can_show=False,
                )
            for label, value in ((self.pack_state_label, pack_state),
                                 (self.coverage_label, coverage), (self.quality_label, quality)):
                label.setStringValue_(value)
                NSAccessibilityPostNotification(label, NSAccessibilityValueChangedNotification)
            self._update_action_controls()
            self._layout_scroll_content()

        @objc.python_method
        def _set_window_privacy(self, active: bool) -> None:
            if self.window_privacy_active == active:
                return
            if self.pause_callback is not None:
                self.pause_callback(active)
            self.window_privacy_active = active

        @objc.python_method
        def _set_action_status(self, text: str) -> None:
            self.action_status_label.setStringValue_(text)
            NSAccessibilityPostNotification(
                self.action_status_label,
                NSAccessibilityValueChangedNotification,
            )

        @objc.python_method
        def _set_busy(self, busy: bool) -> None:
            self.busy = busy
            if busy:
                self.window.makeFirstResponder_(None)
            self._update_action_controls()

        @objc.python_method
        def _restore_focus(self, control) -> None:
            if control is not None and control.isEnabled() and not control.isHiddenOrHasHiddenAncestor():
                self.window.makeFirstResponder_(control)

        @objc.python_method
        def _clear_result_fields(self) -> None:
            self.outcome_popup.selectItemAtIndex_(0)
            self.value_field.setStringValue_("")
            self.notes_field.setStringValue_("")
            self._update_action_controls()

        @objc.python_method
        def _has_draft(self) -> bool:
            return bool(self.outcome_popup.indexOfSelectedItem() or
                        self.value_field.stringValue() or self.notes_field.stringValue())

        @objc.python_method
        def _text_within_limit(self) -> bool:
            return all(len(str(field.stringValue())) <= MAX_OUTCOME_CHARACTERS
                       for field in (self.value_field, self.notes_field))

        def controlTextDidChange_(self, _notification):
            self._update_action_controls()

        def clearDraftAction_(self, _sender):
            if not self.busy:
                self._clear_result_fields()
                self.end_picker.setMaxDate_(self._date_to_nsdate(self.date_limit))
                if (self._selected_date(), self._selected_days()) != self.displayed_selection:
                    self.selectionAction_(self.end_picker)
                self._set_action_status("Draft cleared. You can choose other review dates.")

        @objc.python_method
        def _selected_outcome(self) -> str | None:
            return (None, *OUTCOME_VALUES.values())[self.outcome_popup.indexOfSelectedItem()]

        @objc.python_method
        def _update_action_controls(self) -> None:
            snapshot = self.last_snapshot
            prepared = snapshot is not None and snapshot.can_show
            can_prepare = snapshot is not None and snapshot.can_prepare
            chosen = self._selected_outcome() is not None
            available = not self.busy
            complete = self._selected_date() <= self.date_limit
            within_limit = self._text_within_limit()

            self.refresh_button.setEnabled_(available)
            self.pause_button.setEnabled_(
                available and snapshot is not None and snapshot.can_toggle_pause
            )
            self.prepare_button.setEnabled_(available and can_prepare)
            self.show_button.setEnabled_(available and prepared)
            self.record_button.setEnabled_(available and prepared and chosen and within_limit and complete)
            self.clear_draft_button.setEnabled_(available and self._has_draft())
            self.show_results_button.setEnabled_(
                available and snapshot is not None and snapshot.can_show_results
            )
            self.end_picker.setEnabled_(available)
            self.days_popup.setEnabled_(available)
            editable = available and (prepared or self._has_draft())
            self.outcome_popup.setEnabled_(editable)
            self.value_field.setEnabled_(editable)
            self.notes_field.setEnabled_(editable)
            self.length_label.setStringValue_(
                "Each text field allows up to 4,000 characters."
                if within_limit else "Too much text. Shorten each field to 4,000 characters or fewer. Your draft is kept."
            )

            if self.busy:
                prepare_help = show_help = record_help = "Please wait for this action."
            elif snapshot is None:
                prepare_help = "Checking selected days..."
                show_help = record_help = "Wait for the selected day check."
            else:
                blocked_existing = snapshot.pack_status == "blocked"
                if blocked_existing:
                    recovery = (
                        "Use Recovery help on Daily status before repairing or moving "
                        "this folder, then refresh."
                    )
                    prepare_help = show_help = record_help = recovery
                elif prepared:
                    prepare_help = "Review files already exist for these dates."
                    show_help = "Opens Finder and selects REVIEW_PROMPT.md."
                    record_help = (
                        "The selected end date must be a completed day. Your draft is kept."
                        if not complete else "Shorten the text before saving. Your draft is kept."
                        if not within_limit else "Choose a result first."
                        if not chosen
                        else "Saves this result locally."
                    )
                elif can_prepare:
                    prepare_help = "Ready. This creates private files only."
                    show_help = record_help = "Create the review files in Step 1 first."
                else:
                    prepare_help = snapshot.pack_state
                    show_help = record_help = (
                        "Fix the Step 1 issue or choose other dates, then refresh."
                    )
            for button, label, help_text in (
                (self.prepare_button, self.prepare_help_label, prepare_help),
                (self.show_button, self.show_help_label, show_help),
                (self.record_button, self.record_help_label, record_help),
            ):
                label.setStringValue_(help_text)
                button.setAccessibilityHelp_(help_text)

        @objc.python_method
        def _apply_snapshot(
            self,
            snapshot: ReviewCenterSnapshot,
            message: str,
            focus=None,
            selection: tuple[date, int] | None = None,
        ) -> None:
            current_selection = (self._selected_date(), self._selected_days())
            if selection is not None and selection != current_selection:
                self._accept_review_selection(current_selection)
                self._set_busy(False)
                self._start_refresh("Review dates changed. Status refreshed.", focus=focus)
                return
            self.last_snapshot = snapshot
            self.health_label.setStringValue_(snapshot.health)
            self.capture_label.setStringValue_(
                _capture_status(snapshot.capture_state, snapshot.pause_reasons, self.window_privacy_active)
            )
            checked = f"Status checked: {snapshot.checked_at}"
            if snapshot.runtime_state_updated_at is not None:
                checked += f"\nRuntime state updated: {snapshot.runtime_state_updated_at}"
                if snapshot.runtime_state_age_seconds is not None:
                    checked += f" ({snapshot.runtime_state_age_seconds} seconds old at check time)."
            self.checked_label.setStringValue_(checked)
            self.freshness_label.setStringValue_(snapshot.freshness)
            self.pause_state_label.setStringValue_(snapshot.pause_state)
            self.pause_button.setTitle_(
                "Turn off manual pause"
                if snapshot.manual_paused is True
                else "Turn on manual pause"
            )
            self.pack_state_label.setStringValue_(snapshot.pack_state)
            self.coverage_label.setStringValue_(snapshot.coverage)
            self.storage_label.setStringValue_(snapshot.storage)
            self.problems_label.setStringValue_(snapshot.problems)
            self.quality_label.setStringValue_(snapshot.quality)
            self.window.contentView().layoutSubtreeIfNeeded()
            self._layout_scroll_content()
            if self.initial_scroll_pending:
                self._scroll_to_visual_top()
                self.initial_scroll_pending = False
            self._set_busy(False)
            self._set_action_status(message)
            self._restore_focus(focus)
            for field in (self.pack_state_label, self.coverage_label, self.capture_label,
                          self.pause_state_label, self.problems_label, self.quality_label):
                NSAccessibilityPostNotification(
                    field,
                    NSAccessibilityValueChangedNotification,
                )

        @objc.python_method
        def _finish_with_snapshot(self, snapshot, message: str, focus=None, selection=None) -> None:
            AppHelper.callAfter(self._apply_snapshot, snapshot, message, focus, selection)

        @objc.python_method
        def _finish_error(self, action: str, error: Exception, focus=None) -> None:
            message = f"{action}: {safe_error_message(error)}"
            AppHelper.callAfter(self._apply_action_result, message, focus)

        @objc.python_method
        def _apply_action_result(self, message: str, focus=None) -> None:
            self._set_busy(False)
            self._set_action_status(message)
            self._restore_focus(focus)

        @objc.python_method
        def _finish_action(self, message: str, focus=None) -> None:
            AppHelper.callAfter(self._apply_action_result, message, focus)

        @objc.python_method
        def _apply_outcome_result(self) -> None:
            if self.last_snapshot is not None:
                self.last_snapshot = replace(self.last_snapshot, can_show_results=True)
            self._clear_result_fields()
            self._apply_action_result(
                "Review result saved locally.",
                self.show_results_button,
            )

        @objc.python_method
        def _finish_outcome(self) -> None:
            AppHelper.callAfter(self._apply_outcome_result)

        @objc.python_method
        def _start_refresh(
            self, message: str = "Status refreshed.", focus=None
        ) -> None:
            if self.busy:
                return
            if focus is None:
                focus = self.refresh_button
            end = self._selected_date()
            days = self._selected_days()
            self._set_busy(True)
            self._set_action_status("Reading local status...")

            def work() -> None:
                try:
                    snapshot = self.model.snapshot(end, days)
                except Exception as error:
                    self._finish_error("Refresh", error, focus)
                    return
                self._finish_with_snapshot(snapshot, message, focus, (end, days))

            threading.Thread(
                target=work, daemon=True, name="review-center-refresh"
            ).start()

        def refreshAction_(self, _sender):
            self._start_refresh(focus=self.refresh_button)

        def selectionAction_(self, _sender):
            selection = (self._selected_date(), self._selected_days())
            if self._has_draft() and selection != self.displayed_selection:
                end, days = self.displayed_selection
                self.end_picker.setDateValue_(self._date_to_nsdate(end))
                self.days_popup.selectItemAtIndex_(0 if days == 5 else 1)
                self._set_action_status("Save or clear this draft before changing review dates. Your draft is kept.")
                return
            self._accept_review_selection(selection)
            focus = (
                _sender
                if _sender in (self.end_picker, self.days_popup)
                else self.end_picker
            )
            self._start_refresh("Review dates updated.", focus=focus)

        def outcomeAction_(self, _sender):
            self._update_action_controls()
            if self._selected_outcome() is not None:
                self._set_action_status(
                    "Result selected. Add optional detail, then save."
                )
            else:
                self._set_action_status("Choose a result before saving.")

        def prepareAction_(self, _sender):
            if (
                self.busy
                or self.last_snapshot is None
                or not self.last_snapshot.can_prepare
            ):
                return
            end = self._selected_date()
            days = self._selected_days()
            self._set_busy(True)
            self._set_action_status("Creating private review files...")

            def work() -> None:
                try:
                    result = self.model.prepare(end, days)
                    snapshot = self.model.snapshot(end, days)
                except Exception as error:
                    self._finish_error("Prepare", error, self.prepare_button)
                    return
                self._finish_with_snapshot(
                    snapshot,
                    f"Created {result.pack_dir.name}. Continue to Step 2.",
                    self.show_button,
                    (end, days),
                )

            threading.Thread(
                target=work, daemon=True, name="review-center-prepare"
            ).start()

        def showReviewAction_(self, _sender):
            if self.busy:
                return
            end = self._selected_date()
            days = self._selected_days()
            try:
                pack_dir = self.model.prepared_pack(end, days)
                if pack_dir is None:
                    self._set_action_status(
                        "Review files are missing, incomplete, or unsafe. Use Recovery "
                        "help on Daily status, then refresh."
                    )
                    return
                _show_review_prompt_in_finder(pack_dir / PROMPT_NAME)
            except Exception as error:
                self._set_action_status(safe_error_message(error))
                return
            self._set_action_status(
                "Finder selected REVIEW_PROMPT.md. Review and redact private text "
                "before sharing."
            )

        def showResultsAction_(self, _sender):
            if self.busy:
                return
            try:
                path = self.model.saved_results()
                if path is None:
                    raise OperatorError("missing_file")
                _show_review_prompt_in_finder(path)
            except Exception as error:
                self._set_action_status(safe_error_message(error))
                return
            self._set_action_status("Finder selected your private saved results.")

        def recoveryAction_(self, _sender):
            path = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent)) / "docs" / "V2_RECOVERY.md"
            try:
                if not path.is_file() or not NSWorkspace.sharedWorkspace().openURL_(NSURL.fileURLWithPath_(str(path))):
                    raise OperatorError("missing_file")
            except Exception as error:
                self._set_action_status(safe_error_message(error))
                return
            self._set_action_status("Opened the local recovery guide.")

        def pauseAction_(self, _sender):
            if self.busy:
                return
            pause = self.last_snapshot is None or self.last_snapshot.manual_paused is not True
            end = self._selected_date()
            days = self._selected_days()
            self._set_busy(True)
            self._set_action_status(
                "Applying manual privacy pause..."
                if pause
                else "Resuming manual privacy control..."
            )

            def work() -> None:
                try:
                    self.model.set_manual_pause(pause)
                    snapshot = self.model.snapshot(end, days)
                except Exception as error:
                    self._finish_error("Privacy control", error, self.pause_button)
                    return
                self._finish_with_snapshot(
                    snapshot,
                    "Manual privacy pause is on."
                    if pause
                    else "Manual privacy pause is off.",
                    self.pause_button,
                    (end, days),
                )

            threading.Thread(
                target=work, daemon=True, name="review-center-pause"
            ).start()

        def recordOutcomeAction_(self, _sender):
            if self.busy:
                return
            week = self._selected_date()
            days = self._selected_days()
            outcome = self._selected_outcome()
            if outcome is None:
                self._set_action_status("Choose a result first.")
                return
            if not self._text_within_limit():
                self._set_action_status(safe_error_message(OperatorError("text_too_long")))
                return
            if week >= datetime.now().astimezone().date():
                self._set_action_status("The selected end date must be a completed day. Your draft is kept.")
                return
            try:
                prepared_pack = self.model.prepared_pack(week, days)
            except Exception as error:
                self._set_action_status(safe_error_message(error))
                return
            if prepared_pack is None:
                self._set_action_status(
                    "Safe review files are required before saving a result."
                )
                return
            value_result = str(self.value_field.stringValue())
            notes = str(self.notes_field.stringValue())
            self._set_busy(True)
            self._set_action_status("Saving the review result locally...")

            def work() -> None:
                try:
                    self.model.record_outcome(
                        week,
                        days,
                        outcome,
                        value_result,
                        notes,
                    )
                except Exception as error:
                    self._finish_error("Outcome", error, self.record_button)
                    return
                self._finish_outcome()

            threading.Thread(
                target=work, daemon=True, name="review-center-outcome"
            ).start()

        @objc.python_method
        def show(self) -> None:
            self._refresh_date_limit()
            if self.window.isMiniaturized():
                self.window.deminiaturize_(None)
            self._set_window_privacy(True)
            self.window.makeKeyAndOrderFront_(None)
            NSApplication.sharedApplication().activateIgnoringOtherApps_(True)
            self.window.contentView().layoutSubtreeIfNeeded()
            self._layout_scroll_content()
            if self.initial_scroll_pending:
                self._scroll_to_visual_top()
            self._start_refresh("Review Center opened.", focus=self.pause_button)

        def windowShouldClose_(self, _sender):
            self.window.orderOut_(None)
            self._set_window_privacy(False)
            return False

        def windowDidBecomeKey_(self, _notification):
            self._set_window_privacy(True)
            if not self.busy and self.last_snapshot is not None:
                self._apply_snapshot(
                    self.last_snapshot,
                    "Review Center is active.",
                )

        def windowDidResignKey_(self, _notification):
            pass

        def windowDidMiniaturize_(self, _notification):
            self._set_window_privacy(False)

        def windowDidDeminiaturize_(self, _notification):
            self._set_window_privacy(True)

        def windowDidResize_(self, _notification):
            self._layout_scroll_content()

    class _ReviewCenterAppDelegate(NSObject):
        def initWithController_delay_(self, controller, delay):
            self = objc.super(_ReviewCenterAppDelegate, self).init()
            if self is None:
                return None
            self.controller = controller
            self.reopen_after = time.monotonic() + float(delay)
            return self

        def applicationShouldHandleReopen_hasVisibleWindows_(
            self,
            _application,
            _has_visible_windows,
        ):
            if time.monotonic() >= self.reopen_after:
                self.controller.show()
            return True

    class ReviewCenterRuntime:
        def __init__(self, model: ReviewCenterModel, pause_callback=None) -> None:
            self.app = NSApplication.sharedApplication()
            self.previous_delegate = self.app.delegate()
            if self.previous_delegate is not None:
                raise RuntimeError("cannot replace the existing application delegate")
            self.app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)
            self.controller = (
                ReviewCenterWindowController.alloc().initWithModel_pauseCallback_(
                    model,
                    pause_callback,
                )
            )
            self.delegate = _ReviewCenterAppDelegate.alloc().initWithController_delay_(
                self.controller,
                2.0,
            )
            self.app.setDelegate_(self.delegate)
            self.app.finishLaunching()
            self.pump()

        def pump(self, limit: int = 100) -> None:
            for _ in range(limit):
                event = self.app.nextEventMatchingMask_untilDate_inMode_dequeue_(
                    NSAnyEventMask,
                    NSDate.distantPast(),
                    NSDefaultRunLoopMode,
                    True,
                )
                if event is None:
                    break
                self.app.sendEvent_(event)
            self.app.updateWindows()

        def close(self) -> None:
            try:
                self.controller.window.orderOut_(None)
            finally:
                try:
                    self.controller._set_window_privacy(False)
                finally:
                    if self.app.delegate() is self.delegate:
                        self.app.setDelegate_(self.previous_delegate)


else:
    ReviewCenterWindowController = None
    ReviewCenterRuntime = None


def create_review_center_runtime(
    log_dir: Path,
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    home: Path | None = None,
    pause_callback=None,
):
    if not APPKIT_AVAILABLE:
        raise RuntimeError("AppKit is unavailable")
    model = ReviewCenterModel(log_dir, output_dir=output_dir, home=home)
    return ReviewCenterRuntime(model, pause_callback=pause_callback)
