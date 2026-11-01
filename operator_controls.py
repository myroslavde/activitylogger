"""Private, payload-free operator controls and reports."""

from __future__ import annotations

import fcntl
import json
import os
import pwd
import signal
import stat
import time
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path

from analysis_log import (
    ANALYSIS_ONLY_START_DAY,
    AnalysisDayInspection,
    analysis_day_inventory,
    analysis_paths,
    intent_path,
    inspect_analysis_day,
    ready_path,
)
from analysis_view import DEFAULT_OUTPUT_DIR, _stage_private_text
from operator_errors import OperatorError
from private_files import open_private_file, read_private_bytes
from weekly_review import weekly_pack_name, weekly_window_dates

RUNTIME_STATE_SCHEMA = 1
RUNTIME_DIR_NAME = "ActivityLogger"
LOCK_NAME = "activitylogger.lock"
STATE_NAME = "operator_state.json"
STATE_PENDING_NAME = ".operator_state.pending"
OUTCOMES_NAME = "weekly_review_outcomes.md"
_OUTCOMES = frozenset({"accepted", "ignored", "tried"})
PAUSE_REASONS = frozenset({"manual", "secure_app", "secure_field", "review_window", "storage"})


@dataclass(frozen=True)
class ProcessState:
    running: bool
    pid: int | None


def runtime_dir(home: Path | None = None) -> Path:
    base = home or Path(pwd.getpwuid(os.getuid()).pw_dir)
    return base / "Library" / "Application Support" / RUNTIME_DIR_NAME


def _ensure_private_dir(path: Path, *, parents: bool = False) -> Path:
    if path.is_symlink():
        raise OSError("refusing symlinked private directory")
    path.mkdir(mode=0o700, parents=parents, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise OSError("refusing unsafe private directory")
    os.chmod(path, 0o700)
    return path


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_runtime_state(
    *,
    running: bool,
    manual_paused: bool,
    capture_paused: bool,
    control_revision: int,
    storage_blocked: bool = False,
    pause_reasons: tuple[str, ...] = (),
    home: Path | None = None,
) -> Path:
    root = _ensure_private_dir(runtime_dir(home), parents=True)
    destination = root / STATE_NAME
    document = {
        "schema": RUNTIME_STATE_SCHEMA,
        "pid": os.getpid(),
        "running": running,
        "manual_paused": manual_paused,
        "capture_paused": capture_paused,
        "control_revision": control_revision,
        "storage_blocked": storage_blocked,
        "pause_reasons": list(pause_reasons),
        "updated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
    }
    if not _valid_runtime_state(document):
        raise ValueError("invalid runtime state")
    staged = None
    pending_staged = None
    pending = root / STATE_PENDING_NAME
    try:
        staged = _stage_private_text(root, STATE_NAME, json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n")
        pending_staged = _stage_private_text(root, STATE_PENDING_NAME, "")
        os.replace(pending_staged, pending)
        _fsync_dir(root)
        os.replace(staged, destination)
        os.chmod(destination, 0o600, follow_symlinks=False)
        _fsync_dir(root)
    finally:
        for temporary in (staged, pending_staged):
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
    # The marker covers replacement, sync and cleanup failures. A crash that
    # restores its directory entry causes an unverified state on next startup.
    # No fallible publication work may follow successful removal.
    pending.unlink()
    return destination


def _read_private_json(path: Path) -> dict[str, object] | None:
    try:
        raw = read_private_bytes(path, max_bytes=4096)
    except FileNotFoundError:
        return None
    value = json.loads(raw)
    return value if isinstance(value, dict) else None


def _valid_runtime_state(state: dict[str, object]) -> bool:
    if type(state.get("schema")) is not int or state["schema"] != RUNTIME_STATE_SCHEMA:
        return False
    if type(state.get("pid")) is not int or state["pid"] <= 0:
        return False
    if type(state.get("control_revision")) is not int or state["control_revision"] < 0:
        return False
    if any(type(state.get(name)) is not bool for name in ("running", "manual_paused", "capture_paused")):
        return False
    storage = state.get("storage_blocked", False)
    if type(storage) is not bool or ((storage or state["manual_paused"]) and not state["capture_paused"]):
        return False
    reasons = state.get("pause_reasons", [])
    if not isinstance(reasons, list) or any(type(reason) is not str or reason not in PAUSE_REASONS for reason in reasons):
        return False
    if len(set(reasons)) != len(reasons) or (reasons and not state["capture_paused"]):
        return False
    if ("manual" in reasons and not state["manual_paused"]) or ("storage" in reasons and not storage):
        return False
    try:
        return isinstance(state.get("updated_at"), str) and datetime.fromisoformat(state["updated_at"]).utcoffset() is not None
    except ValueError:
        return False


def _runtime_state_pending(home: Path | None = None) -> bool:
    try:
        (runtime_dir(home) / STATE_PENDING_NAME).lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return True


def read_runtime_state(home: Path | None = None) -> dict[str, object] | None:
    try:
        if _runtime_state_pending(home):
            return None
        state = _read_private_json(runtime_dir(home) / STATE_NAME)
        if state is None or not _valid_runtime_state(state) or _runtime_state_pending(home):
            return None
        return state
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        return None


def initial_manual_pause(home: Path | None = None) -> bool:
    """Keep a prior pause, and fail closed if an existing state is unreadable."""
    if _runtime_state_pending(home):
        return True
    path = runtime_dir(home) / STATE_NAME
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return True
    state = read_runtime_state(home)
    if state is None or type(state.get("manual_paused")) is not bool:
        return True
    return bool(state["manual_paused"])


def process_state(home: Path | None = None) -> ProcessState:
    path = runtime_dir(home) / LOCK_NAME
    try:
        fd, _info = open_private_file(path, max_bytes=32)
    except OSError:
        return ProcessState(False, None)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            return ProcessState(False, None)
        raw = os.read(fd, 32).decode("ascii", "strict").strip()
        pid = int(raw)
        if pid <= 0:
            return ProcessState(False, None)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            try:
                os.kill(pid, 0)
            except (ProcessLookupError, PermissionError):
                return ProcessState(False, None)
            return ProcessState(True, pid)
        fcntl.flock(fd, fcntl.LOCK_UN)
        return ProcessState(False, None)
    except (OSError, UnicodeError, ValueError):
        return ProcessState(False, None)
    finally:
        os.close(fd)


def set_manual_pause(paused: bool, *, home: Path | None = None, timeout: float = 5.0) -> dict[str, object]:
    process = process_state(home)
    if not process.running or process.pid is None:
        raise OperatorError("logger_stopped")
    before = read_runtime_state(home) or {}
    if before.get("pid") != process.pid:
        before = {}
    revision = int(before.get("control_revision", -1))
    os.kill(process.pid, signal.SIGUSR1 if paused else signal.SIGUSR2)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = read_runtime_state(home)
        if (
            state is not None
            and state.get("pid") == process.pid
            and state.get("manual_paused") is paused
            and int(state.get("control_revision", -1)) > revision
        ):
            return state
        if not process_state(home).running:
            break
        time.sleep(0.05)
    raise OperatorError("control_unconfirmed")


def _mode(path: Path) -> str:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "missing"
    if info.st_uid != os.getuid() or stat.S_ISLNK(info.st_mode):
        return "unsafe"
    return f"{stat.S_IMODE(info.st_mode):03o}"


def health_report(
    log_dir: Path,
    day: date,
    *,
    home: Path | None = None,
    inspections: dict[date, AnalysisDayInspection] | None = None,
) -> dict[str, object]:
    checked_at = datetime.now().astimezone()
    process = process_state(home)
    analysis_file, invalid_file = analysis_paths(log_dir, day)
    intent_file = intent_path(log_dir, day)
    proof_file = ready_path(log_dir, day)
    checked = inspect_analysis_day(log_dir, day, today=checked_at.date(), inspections=inspections)
    state = read_runtime_state(home)
    valid_state = bool(
        process.running and state and state["running"] and state["pid"] == process.pid
    )
    report: dict[str, object] = {
        "running": process.running,
        "pid": process.pid,
        "day": day.isoformat(),
        "format": checked.format_name,
        "intent_match": checked.intent_match,
        "invalid_marker": checked.invalid_marker,
        "readiness": checked.ready,
        "day_state": checked.state,
        "quality": checked.quality,
        "last_safe_write": "unknown",
        "freshness_seconds": "unknown",
        "checked_at": checked_at.isoformat(timespec="seconds"),
        "runtime_state_valid": valid_state,
        "state_updated_at": state["updated_at"] if valid_state else None,
        "state_age_seconds": None,
        "manual_paused": state["manual_paused"] if valid_state else None,
        "capture_paused": state["capture_paused"] if valid_state else None,
        "storage_blocked": state.get("storage_blocked", False) if valid_state else None,
        "pause_reasons": tuple(state.get("pause_reasons", ())) if valid_state else (),
        "log_dir_mode": _mode(log_dir),
        "analysis_mode": _mode(analysis_file),
        "intent_mode": _mode(intent_file),
        "ready_mode": _mode(proof_file),
        "runtime_dir_mode": _mode(runtime_dir(home)),
        "lock_mode": _mode(runtime_dir(home) / LOCK_NAME),
        "state_mode": _mode(runtime_dir(home) / STATE_NAME),
    }
    if valid_state:
        report["state_age_seconds"] = max(
            0, int((checked_at - datetime.fromisoformat(state["updated_at"])).total_seconds())
        )
    if checked.integrity_ok and checked.last_safe_write_ns is not None:
        safe_write = checked.last_safe_write_ns / 1_000_000_000
        report["last_safe_write"] = datetime.fromtimestamp(safe_write).astimezone().isoformat(timespec="seconds")
        report["freshness_seconds"] = max(0, int(checked_at.timestamp() - safe_write))
    return report


def _private_tree_size(root: Path, *, exclude: Path | None = None) -> tuple[int, int]:
    """Count safe private file bytes without reading any captured content."""
    total = 0
    unsafe = 0
    try:
        info = root.lstat()
    except FileNotFoundError:
        return 0, 0
    except OSError:
        return 0, 1
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        return 0, 1
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            children = tuple(current.iterdir())
        except OSError:
            unsafe += 1
            continue
        for path in children:
            if exclude is not None and path.absolute() == exclude.absolute():
                continue
            try:
                info = path.lstat()
            except OSError:
                unsafe += 1
                continue
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                unsafe += 1
            elif stat.S_ISDIR(info.st_mode):
                pending.append(path)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                total += info.st_size
            else:
                unsafe += 1
    return total, unsafe


def _review_pack_counts(output_dir: Path) -> tuple[int, int]:
    try:
        info = output_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            return 0, 0
        children = tuple(output_dir.iterdir())
    except OSError:
        return 0, 0
    complete = incomplete = 0
    for path in children:
        try:
            parts = path.name.split("_")
            if len(parts) != 5 or parts[:2] != ["weekly", "review"] or parts[4] not in {"5d", "7d"}:
                continue
            if weekly_pack_name(date.fromisoformat(parts[3]), int(parts[4][0])) != path.name:
                continue
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                incomplete += 1
                continue
        except (OSError, ValueError):
            continue
        try:
            fd, _info = open_private_file(path / "INDEX.json")
            os.close(fd)
            complete += 1
        except OSError:
            incomplete += 1
    return complete, incomplete


def storage_report(
    log_dir: Path,
    *,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    today: date | None = None,
    inspections: dict[date, AnalysisDayInspection] | None = None,
) -> dict[str, object]:
    current_day = today or datetime.now().astimezone().date()
    days, malformed = analysis_day_inventory(log_dir)
    completed = [day for day in days if day < current_day]
    checked_days = [
        inspect_analysis_day(log_dir, day, today=current_day, inspections=inspections)
        for day in completed if day >= ANALYSIS_ONLY_START_DAY
    ]
    problem_days = [
        {"day": item.day, "state": item.state, "reason": item.reason}
        for item in checked_days if not item.ready
    ]
    total_bytes, unsafe_files = _private_tree_size(log_dir)
    review_bytes, unsafe_review = _private_tree_size(output_dir)
    # The common case has sibling roots. A custom nested root is counted once.
    if output_dir.absolute().is_relative_to(log_dir.absolute()):
        unique_review_bytes = 0
    elif log_dir.absolute().is_relative_to(output_dir.absolute()):
        unique_review_bytes, _ = _private_tree_size(output_dir, exclude=log_dir)
    else:
        unique_review_bytes = review_bytes
    packs, incomplete_packs = _review_pack_counts(output_dir)
    return {
        "total_private_log_bytes": total_bytes,
        "private_review_bytes": review_bytes,
        "total_log_and_review_bytes": total_bytes + unique_review_bytes,
        "unsafe_files": unsafe_files,
        "unsafe_review_items": unsafe_review,
        "oldest_day": days[0].isoformat() if days else "none",
        "newest_day": days[-1].isoformat() if days else "none",
        "completed_days": len(completed),
        "review_packs": packs,
        "incomplete_review_packs": incomplete_packs,
        "missing_readiness_proofs": len(problem_days),
        "missing_readiness_days": ",".join(item["day"] for item in problem_days) or "none",
        "malformed_day_count": len(malformed),
        "malformed_day_files": malformed,
        "problem_days": problem_days,
    }


def record_review_outcome(
    week: date,
    outcome: str,
    value_result: str,
    notes: str,
    *,
    days: int | None = None,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
) -> Path:
    if type(week) is not date:
        raise OperatorError("invalid_window")
    window = weekly_window_dates(week, days) if days is not None else None
    if outcome not in _OUTCOMES:
        raise OperatorError("outcome_invalid")
    if len(value_result) > 4000 or len(notes) > 4000:
        raise OperatorError("text_too_long")
    dash_map = {0x2014: "-", 0x2013: "-"}
    value_result = value_result.translate(dash_map)
    notes = notes.translate(dash_map)
    root = _ensure_private_dir(output_dir)
    destination = root / OUTCOMES_NAME
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(destination, flags, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise OSError("refusing unsafe review outcome file")
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        empty = os.fstat(fd).st_size == 0
        entry = {
            "week": week.isoformat(),
            "window": {"start": window[0].isoformat() if window else None, "end": week.isoformat(), "calendar_days": days},
            "pack": weekly_pack_name(week, days) if window else None,
            "recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "outcome": outcome,
            "value_result": value_result,
            "notes": notes,
        }
        text = ("# Weekly review outcomes\n\n" if empty else "") + f"- {json.dumps(entry, ensure_ascii=False, sort_keys=True)}\n"
        data = text.encode("utf-8")
        offset = 0
        while offset < len(data):
            written = os.write(fd, data[offset:])
            if written <= 0:
                raise OSError("short review outcome write")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)
    _fsync_dir(root)
    return destination
