from __future__ import annotations

import fcntl
import json
import os
import signal
import stat
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone

import pytest

import analysis_log as al
import interleaved_logger as il
import operator_controls as controls


DAY = date(2026, 8, 27)


def _record(day: date) -> al.AnalysisRecord:
    captured = datetime.combine(
        day,
        datetime.min.time(),
        tzinfo=timezone(timedelta(hours=2)),
    ) + timedelta(hours=10)
    return al.AnalysisRecord(
        heading="App",
        kind="heartbeat",
        payload="",
        captured_at=captured,
        trigger="timeline",
        section_captured_at=captured,
        section_start=True,
    )


def _commit_ready_day(log_dir, day: date) -> None:
    log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    al.prepare_authoritative_transaction(log_dir, ((day, (_record(day),)),), "test")
    al.commit_authoritative_transaction(log_dir)
    al.publish_day_ready(log_dir, day)


def test_manual_pause_uses_shared_fail_closed_gate_without_replay(
    reset_logger_state,
    monkeypatch,
):
    reset_logger_state()
    monkeypatch.setattr(il, "_publish_runtime_state", lambda **_kwargs: True)
    with il._lock:
        il._current_keystrokes.extend(["secret"])
    generation = il._privacy_generation

    il._request_manual_control(signal.SIGUSR1)
    il._apply_pending_manual_control()

    assert il._pause_manual is True
    assert il.is_paused() is True
    assert il._current_keystrokes == []
    assert il._privacy_generation == generation + 1
    count, digest, event = il._apply_clipboard_change_digest(
        2,
        "copied while paused",
        True,
        1,
        "",
    )
    assert event is None

    il._request_manual_control(signal.SIGUSR2)
    il._apply_pending_manual_control()

    assert il._pause_manual is False
    assert il.is_paused() is False
    assert il._current_keystrokes == []
    assert il._apply_clipboard_change_digest(
        count,
        "copied while paused",
        False,
        count,
        digest,
    )[2] is None


def test_manual_resume_never_clears_secure_pause(reset_logger_state, monkeypatch):
    reset_logger_state()
    monkeypatch.setattr(il, "_publish_runtime_state", lambda **_kwargs: True)
    il._set_pause(field=True)
    il._request_manual_control(signal.SIGUSR1)
    il._apply_pending_manual_control()
    il._request_manual_control(signal.SIGUSR2)
    il._apply_pending_manual_control()

    assert il._pause_manual is False
    assert il._pause_secure_field is True
    assert il.is_paused() is True


def test_manual_resume_stays_paused_until_state_is_durable(
    reset_logger_state,
    monkeypatch,
):
    reset_logger_state()
    il._set_pause(manual=True)
    il._request_manual_control(signal.SIGUSR2)
    clock = [100.0]
    monkeypatch.setattr(il.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(il, "_publish_runtime_state", lambda **_kwargs: False)

    il._apply_pending_manual_control()

    assert il._pause_manual is True
    assert il.is_paused() is True
    assert il._manual_state_dirty.is_set()

    monkeypatch.setattr(il, "_publish_runtime_state", lambda **_kwargs: True)
    il._apply_pending_manual_control()
    assert il._pause_manual is True
    clock[0] = il._manual_state_retry_at
    il._apply_pending_manual_control()
    assert il._pause_manual is False
    assert il.is_paused() is False


def test_runtime_state_and_instance_lock_are_private(tmp_path):
    root = controls.runtime_dir(tmp_path)
    root.mkdir(mode=0o700, parents=True)
    lock_path = root / controls.LOCK_NAME
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.write(fd, str(os.getpid()).encode("ascii"))
        assert controls.process_state(tmp_path) == controls.ProcessState(True, os.getpid())

        state_path = controls.write_runtime_state(
            running=True,
            manual_paused=True,
            capture_paused=True,
            control_revision=2,
            home=tmp_path,
        )
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert stat.S_IMODE(state_path.stat().st_mode) == 0o600
        assert controls.read_runtime_state(tmp_path)["control_revision"] == 2
    finally:
        os.close(fd)
    assert controls.process_state(tmp_path).running is False


def test_manual_pause_survives_restart_and_corrupt_state_fails_closed(tmp_path):
    controls.write_runtime_state(
        running=False,
        manual_paused=True,
        capture_paused=True,
        control_revision=3,
        home=tmp_path,
    )
    assert controls.initial_manual_pause(tmp_path) is True

    state_path = controls.runtime_dir(tmp_path) / controls.STATE_NAME
    state_path.write_text("broken\n", encoding="utf-8")
    os.chmod(state_path, 0o600)
    assert controls.initial_manual_pause(tmp_path) is True


def test_health_and_storage_reports_are_payload_free(tmp_path):
    log_dir = tmp_path / "logs"
    _commit_ready_day(log_dir, DAY)
    second = DAY + timedelta(days=1)
    al.prepare_authoritative_transaction(
        log_dir,
        ((second, (_record(second),)),),
        "test",
    )
    al.commit_authoritative_transaction(log_dir)
    output_dir = tmp_path / "private_review"
    pack = output_dir / "weekly_review_2026-08-24_2026-08-28_5d"
    pack.mkdir(mode=0o700, parents=True)
    output_dir.chmod(0o700)
    (pack / "INDEX.json").write_text("{}\n", encoding="utf-8")
    os.chmod(pack / "INDEX.json", 0o600)

    health = controls.health_report(log_dir, DAY, home=tmp_path)
    storage = controls.storage_report(
        log_dir,
        output_dir=output_dir,
        today=second + timedelta(days=1),
    )
    rendered = json.dumps({"health": health, "storage": storage})

    assert health["format"] == al.ANALYSIS_FORMAT_V2
    assert health["intent_match"] is True
    assert health["readiness"] is True
    assert health["analysis_mode"] == "600"
    assert health["intent_mode"] == "600"
    assert health["ready_mode"] == "600"
    assert storage["completed_days"] == 2
    assert storage["review_packs"] == 1
    assert storage["missing_readiness_proofs"] == 1
    assert storage["missing_readiness_days"] == second.isoformat()
    assert storage["problem_days"] == [{"day": second.isoformat(), "state": "unready", "reason": "proof_missing"}]
    assert "App" not in rendered

    analysis_file = al.analysis_paths(log_dir, DAY)[0]
    os.chmod(analysis_file, 0o644)
    unsafe = controls.health_report(log_dir, DAY, home=tmp_path)
    assert unsafe["analysis_mode"] == "644"
    assert unsafe["intent_match"] is False


def test_review_outcome_is_manual_private_markdown(tmp_path):
    output_dir = tmp_path / "private_review"
    path = controls.record_review_outcome(
        DAY,
        "tried",
        "saved one step",
        "keep this local",
        output_dir=output_dir,
    )

    text = path.read_text(encoding="utf-8")
    assert path.name == controls.OUTCOMES_NAME
    assert stat.S_IMODE(output_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert '"outcome": "tried"' in text
    assert '"value_result": "saved one step"' in text
    assert '"notes": "keep this local"' in text


@pytest.mark.parametrize("state_change", [None, {"pid": 12345678}, {"running": False}, {"manual_paused": "false"}, {"schema": True}, {"control_revision": True}, {"updated_at": "2026-08-27"}, {"pause_reasons": ["private sentinel"]}])
def test_live_process_with_missing_stale_or_invalid_state_is_unknown(tmp_path, monkeypatch, state_change):
    monkeypatch.setattr(controls, "process_state", lambda _home: controls.ProcessState(True, os.getpid()))
    if state_change is not None:
        path = controls.write_runtime_state(running=True, manual_paused=False, capture_paused=False, control_revision=0, home=tmp_path)
        state = json.loads(path.read_text())
        state.update(state_change)
        path.write_text(json.dumps(state))
    report = controls.health_report(tmp_path / "logs", DAY, home=tmp_path)
    assert report["running"] is True
    assert report["runtime_state_valid"] is False
    assert report["manual_paused"] is None
    assert report["capture_paused"] is None
    assert report["state_updated_at"] is None
    assert "private sentinel" not in json.dumps(report)


def test_current_pid_runtime_state_preserves_closed_reasons_and_legacy_shape(tmp_path, monkeypatch):
    monkeypatch.setattr(controls, "process_state", lambda _home: controls.ProcessState(True, os.getpid()))
    path = controls.write_runtime_state(running=True, manual_paused=False, capture_paused=True, storage_blocked=True, pause_reasons=("storage", "review_window"), control_revision=2, home=tmp_path)
    health = controls.health_report(tmp_path / "logs", DAY, home=tmp_path)
    assert health["runtime_state_valid"] is True
    assert health["pause_reasons"] == ("storage", "review_window")
    assert health["storage_blocked"] is True
    assert health["state_age_seconds"] >= 0
    state = json.loads(path.read_text())
    del state["storage_blocked"], state["pause_reasons"]
    path.write_text(json.dumps(state))
    assert controls.read_runtime_state(tmp_path) == state


@pytest.mark.parametrize("operation", ["write", "fsync"])
def test_runtime_state_write_failure_preserves_previous_state_and_cleans_temp(tmp_path, monkeypatch, operation):
    path = controls.write_runtime_state(running=True, manual_paused=True, capture_paused=True, control_revision=1, home=tmp_path)
    original = path.read_bytes()

    def fail(*_args):
        raise OSError("injected failure")

    monkeypatch.setattr(controls.os, operation, fail)
    with pytest.raises(OSError):
        controls.write_runtime_state(running=True, manual_paused=False, capture_paused=False, control_revision=2, home=tmp_path)
    assert path.read_bytes() == original
    assert not list(path.parent.glob("*.pending"))


def test_saved_outcomes_distinguish_five_seven_and_legacy_windows(tmp_path):
    paths = [controls.record_review_outcome(DAY, "tried", "same value", "local note", days=days, output_dir=tmp_path) for days in (5, 7, None)]
    assert len(set(paths)) == 1
    text = paths[0].read_text()
    entries = [json.loads(line[2:]) for line in text.splitlines() if line.startswith("- ")]
    assert [entry["window"]["calendar_days"] for entry in entries] == [5, 7, None]
    assert [entry["window"]["start"] for entry in entries] == ["2026-08-23", "2026-08-21", None]
    assert [entry["pack"] for entry in entries] == ["weekly_review_2026-08-23_2026-08-27_5d", "weekly_review_2026-08-21_2026-08-27_7d", None]
    assert text.count("# Weekly review outcomes") == 1


def test_deeply_nested_runtime_json_is_unknown_and_startup_stays_paused(tmp_path):
    root = controls.runtime_dir(tmp_path)
    root.mkdir(mode=0o700, parents=True)
    path = root / controls.STATE_NAME
    path.write_text("[" * 1500 + "]" * 1500)
    path.chmod(0o600)
    assert controls.read_runtime_state(tmp_path) is None
    assert controls.initial_manual_pause(tmp_path) is True


@pytest.mark.parametrize("fault", ["chmod", "directory_sync", "marker_remove", "staging_cleanup"])
def test_unfinished_runtime_publication_is_unverified_until_retry(tmp_path, monkeypatch, fault):
    path = controls.write_runtime_state(running=True, manual_paused=True, capture_paused=True, control_revision=0, home=tmp_path)
    marker = path.parent / controls.STATE_PENDING_NAME
    real_chmod, real_sync = controls.os.chmod, controls._fsync_dir
    real_unlink = type(path).unlink

    def chmod(target, *args, **kwargs):
        if fault == "chmod" and target == path:
            raise OSError("injected chmod failure")
        return real_chmod(target, *args, **kwargs)

    def sync(target):
        if fault == "directory_sync" and json.loads(path.read_text())["manual_paused"] is False:
            raise OSError("injected directory sync failure")
        return real_sync(target)

    def unlink(target, *args, **kwargs):
        if (fault == "marker_remove" and target == marker) or (
            fault == "staging_cleanup" and target.name.startswith(f".{controls.STATE_NAME}.")
        ):
            raise OSError("injected cleanup failure")
        return real_unlink(target, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(controls.os, "chmod", chmod)
        patch.setattr(controls, "_fsync_dir", sync)
        patch.setattr(type(path), "unlink", unlink)
        with pytest.raises(OSError):
            controls.write_runtime_state(running=True, manual_paused=False, capture_paused=False, control_revision=1, home=tmp_path)
    assert marker.exists()
    assert marker.stat().st_mode & 0o777 == 0o600
    assert controls.read_runtime_state(tmp_path) is None
    assert controls.initial_manual_pause(tmp_path) is True
    controls.write_runtime_state(running=True, manual_paused=False, capture_paused=False, control_revision=1, home=tmp_path)
    assert not marker.exists()
    assert controls.read_runtime_state(tmp_path)["manual_paused"] is False
    assert not list(path.parent.glob("*.pending"))


@pytest.mark.parametrize("kind", ["file", "broken_link", "fifo"])
def test_pending_runtime_marker_without_state_fails_closed(tmp_path, kind):
    root = controls.runtime_dir(tmp_path)
    root.mkdir(mode=0o700, parents=True)
    marker = root / controls.STATE_PENDING_NAME
    if kind == "file":
        marker.touch(mode=0o600)
    elif kind == "broken_link":
        marker.symlink_to(root / "absent")
    else:
        os.mkfifo(marker, 0o600)
    assert controls.read_runtime_state(tmp_path) is None
    assert controls.initial_manual_pause(tmp_path) is True


def test_failed_resume_after_replace_cannot_be_acknowledged(reset_logger_state, monkeypatch):
    reset_logger_state()
    il._set_pause(manual=True)
    assert il._publish_runtime_state(running=True)
    path = controls.runtime_dir() / controls.STATE_NAME
    real_sync = controls._fsync_dir
    def fail_after_replace(root):
        if json.loads(path.read_text())["manual_paused"] is False:
            raise OSError("injected post-replace sync failure")
        return real_sync(root)
    def signal_control(_pid, signum):
        il._request_manual_control(signum)
        il._apply_pending_manual_control()
    monkeypatch.setattr(controls, "_fsync_dir", fail_after_replace)
    monkeypatch.setattr(controls, "process_state", lambda _home=None: controls.ProcessState(True, os.getpid()))
    monkeypatch.setattr(controls.os, "kill", signal_control)
    with pytest.raises(controls.OperatorError) as failed:
        controls.set_manual_pause(False, timeout=0.01)
    assert failed.value.code == "control_unconfirmed"
    assert il._pause_manual and il.is_paused()
    assert controls.read_runtime_state() is None
    monkeypatch.setattr(controls, "_fsync_dir", real_sync)
    il._manual_state_retry_at = 0
    il._apply_pending_manual_control()
    assert not il._pause_manual
    assert controls.read_runtime_state()["manual_paused"] is False


def test_outcome_fifo_without_reader_returns_without_blocking(tmp_path):
    fifo = tmp_path / controls.OUTCOMES_NAME
    os.mkfifo(fifo, 0o600)
    code = "from datetime import date; from pathlib import Path; from operator_controls import record_review_outcome; record_review_outcome(date(2026,8,27),'tried','','',days=5,output_dir=Path(__import__('sys').argv[1]))"
    result = subprocess.run([sys.executable, "-c", code, str(tmp_path)], timeout=5, capture_output=True)
    assert result.returncode != 0
    assert stat.S_ISFIFO(fifo.lstat().st_mode)


def test_storage_reports_review_bytes_incomplete_folders_and_nested_roots(tmp_path):
    log_dir = tmp_path / "logs"
    _commit_ready_day(log_dir, DAY)
    output_dir = log_dir / "private_review"
    output_dir.mkdir(mode=0o700)
    incomplete = output_dir / "weekly_review_2026-08-23_2026-08-27_5d"
    incomplete.mkdir(mode=0o700)
    path = incomplete / "part.md"
    path.write_bytes(b"abc")
    path.chmod(0o600)
    report = controls.storage_report(log_dir, output_dir=output_dir)
    assert report["review_packs"] == 0
    assert report["incomplete_review_packs"] == 1
    assert report["private_review_bytes"] == 3
    assert report["total_log_and_review_bytes"] == report["total_private_log_bytes"]
