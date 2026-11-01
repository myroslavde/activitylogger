"""Ops smoke checks: codesign DR and Launch Agent install ProgramArguments."""

from __future__ import annotations

import os
import plistlib
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
APP = REPO / "dist" / "ActivityLoggerNative.app"
INSTALL = REPO / "scripts" / "install_launch_agent.sh"
VERIFY = REPO / "scripts" / "lib" / "require_certificate_leaf.sh"
RENDER = REPO / "scripts" / "render_launch_agent.py"
PIN = REPO / ".codesign" / "leaf.sha1"


def test_source_bundle_and_readme_versions_match():
    source = (REPO / "interleaved_logger.py").read_text(encoding="utf-8")
    spec = (REPO / "ActivityLoggerNative.spec").read_text(encoding="utf-8")
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    source_version = re.search(r'^__version__ = "([0-9.]+)"$', source, re.MULTILINE)
    short_version = re.search(
        r"'CFBundleShortVersionString': '([0-9.]+)'", spec
    )
    bundle_version = re.search(r"'CFBundleVersion': '([0-9.]+)'", spec)
    readme_version = re.search(r"\*\*Version:\*\* ([0-9.]+)", readme)

    assert source_version is not None
    assert short_version is not None
    assert bundle_version is not None
    assert readme_version is not None
    assert {
        source_version.group(1),
        short_version.group(1),
        bundle_version.group(1),
        readme_version.group(1),
    } == {"4.7.0"}


def test_codesign_is_strict_and_pinned():
    if not APP.is_dir() or not PIN.is_file():
        pytest.skip("canonical signed app is not provisioned")
    result = subprocess.run(
        [str(VERIFY), str(APP)],
        check=False,
        capture_output=True,
        text=True,
    )
    out = (result.stdout or "") + (result.stderr or "")
    if os.environ.get("CODEX_SANDBOX") and "CSSMERR_TP_NOT_TRUSTED" in out:
        pytest.skip("macOS trust evaluation is unavailable inside the Codex sandbox")
    assert result.returncode == 0, out
    assert "identifier=com.mk.activitylogger.native" in out, out
    assert f"certificate_leaf_sha1={PIN.read_text().strip().lower()}" in out, out


def test_launch_agent_program_args_render_in_clean_checkout(tmp_path):
    dest_dir = tmp_path / "LaunchAgents"
    dest_dir.mkdir()
    out_plist = dest_dir / "com.mk.activitylogger.plist"
    subprocess.run(
        [
            sys.executable,
            str(RENDER),
            str(REPO / "com.mk.activitylogger.plist.template"),
            str(out_plist),
            str(REPO),
        ],
        check=True,
        cwd=str(tmp_path),
    )
    with out_plist.open("rb") as fh:
        data = plistlib.load(fh)
    args = data["ProgramArguments"]
    assert args[0] == "/bin/bash"
    assert len(args) == 2
    assert args[1].endswith("start_logger.sh")
    joined = " ".join(args).lower()
    assert "python" not in joined
    assert "interleaved_logger.py" not in joined
    assert out_plist.stat().st_mode & 0o777 == 0o600
    assert data["KeepAlive"] is True
    assert data["Umask"] == 0o77


def test_install_launch_agent_requires_verified_app(tmp_path):
    fake_repo = tmp_path / "repo"
    fake_repo.mkdir()
    out_plist = tmp_path / "agent.plist"
    env = os.environ.copy()
    env["ACTIVITYLOGGER_REPO"] = str(fake_repo)
    env["ACTIVITYLOGGER_PLIST_OUT"] = str(out_plist)
    result = subprocess.run(
        ["bash", str(INSTALL)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode != 0
    assert not out_plist.exists()


def test_plist_renderer_handles_xml_metacharacters(tmp_path):
    repo = tmp_path / "repo & <private>"
    repo.mkdir()
    destination = tmp_path / "agent.plist"
    subprocess.run(
        [
            "/usr/bin/python3",
            str(RENDER),
            str(REPO / "com.mk.activitylogger.plist.template"),
            str(destination),
            str(repo),
        ],
        check=True,
    )
    with destination.open("rb") as fh:
        data = plistlib.load(fh)
    assert data["WorkingDirectory"] == str(repo.resolve())
    assert data["ProgramArguments"][1] == str(repo.resolve() / "start_logger.sh")
    assert destination.stat().st_mode & 0o777 == 0o600


def test_build_contract_is_python_311_locked_and_staged():
    rebuild = (REPO / "scripts" / "rebuild_and_restart.sh").read_text()
    lifecycle = (REPO / "scripts" / "lib" / "exact_process_lifecycle.sh").read_text()
    signing = (REPO / "scripts" / "sign_app.sh").read_text()
    spec = (REPO / "ActivityLoggerNative.spec").read_text()
    requirements = (REPO / "requirements.txt").read_text()
    assert (REPO / ".python-version").read_text().strip() == "3.11.9"
    assert "$REPO/.venv/bin/pyinstaller" in rebuild
    assert 'EXPECTED_PYTHON="$(<"$REPO/.python-version")"' in rebuild
    assert "platform.python_version()" in rebuild
    assert ".build-stage." in rebuild
    assert "--distpath" in rebuild
    assert "exact_process_lifecycle.sh" in rebuild
    assert "pid=,command=" in lifecycle
    assert "-o command=" in lifecycle
    assert "comm=" not in lifecycle
    assert "--options runtime" not in signing
    assert "--force --deep" not in signing
    assert "Hardened Runtime is not enabled" not in (
        REPO / "scripts" / "lib" / "require_certificate_leaf.sh"
    ).read_text()
    assert "exclude_binaries=True" in spec
    assert "COLLECT(" in spec
    assert "create_identity" not in signing
    assert "openssl req" not in signing
    assert "--hash=sha256:" in requirements
    assert "requests==2.33.0" in requirements
    assert "pytest==9.0.3" in requirements
    assert "ruff==0.16.1" in requirements
    assert "pip-audit==2.10.1" in requirements


def test_launch_wrapper_records_privacy_neutral_pid_and_open_exit_status():
    wrapper = (REPO / "start_logger.sh").read_text(encoding="utf-8")
    assert "wrapper_pid=%s" in wrapper
    assert "open -W exited" in wrapper
    assert 'exit "$OPEN_STATUS"' in wrapper
    assert "exec /usr/bin/open" not in wrapper


def _validate_launch_plist(
    plist: Path, wrapper: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; validate_launch_agent_plist "$2" com.mk.activitylogger "$3"',
            "bash",
            str(REPO / "scripts" / "lib" / "exact_process_lifecycle.sh"),
            str(plist),
            str(wrapper),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_launch_plist_validation_rejects_mode_symlink_and_wrong_wrapper(tmp_path):
    wrapper = tmp_path / "repo with spaces" / "start_logger.sh"
    plist = tmp_path / "agent.plist"
    valid = {
        "Label": "com.mk.activitylogger",
        "ProgramArguments": ["/bin/bash", str(wrapper)],
        "RunAtLoad": True,
        "KeepAlive": True,
        "Umask": 0o77,
    }
    with plist.open("wb") as fh:
        plistlib.dump(valid, fh)
    plist.chmod(0o600)
    assert _validate_launch_plist(plist, wrapper).returncode == 0

    plist.chmod(0o644)
    assert _validate_launch_plist(plist, wrapper).returncode != 0
    plist.chmod(0o600)
    assert _validate_launch_plist(plist, tmp_path / "wrong.sh").returncode != 0

    for stale_policy in (
        {**valid, "KeepAlive": {"SuccessfulExit": False}},
        {key: value for key, value in valid.items() if key != "Umask"},
        {**valid, "Umask": 0o22},
        {**valid, "RunAtLoad": False},
    ):
        with plist.open("wb") as fh:
            plistlib.dump(stale_policy, fh)
        assert _validate_launch_plist(plist, wrapper).returncode != 0

    link = tmp_path / "agent-link.plist"
    link.symlink_to(plist)
    assert _validate_launch_plist(link, wrapper).returncode != 0


def _write_executable(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def test_rebuild_restores_previous_app_when_post_promotion_verify_fails(tmp_path):
    repo = tmp_path / "repo"
    scripts = repo / "scripts"
    libs = scripts / "lib"
    libs.mkdir(parents=True)
    shutil.copyfile(REPO / "scripts" / "rebuild_and_restart.sh", scripts / "rebuild_and_restart.sh")
    (scripts / "rebuild_and_restart.sh").chmod(0o755)
    shutil.copyfile(
        REPO / "scripts" / "lib" / "exact_process_lifecycle.sh",
        libs / "exact_process_lifecycle.sh",
    )
    (repo / ".python-version").write_text("3.11.9\n", encoding="utf-8")
    (repo / "ActivityLoggerNative.spec").write_text("# fake\n", encoding="utf-8")

    _write_executable(
        libs / "resolve_repo_root.sh",
        '#!/bin/bash\nresolve_repo_root() { REPO="$ACTIVITYLOGGER_REPO"; export REPO; }\n',
    )
    _write_executable(
        libs / "require_certificate_leaf.sh",
        "#!/bin/bash\n"
        "verify_activitylogger_app() {\n"
        '  local count_file="$REPO/verify-count" count=0\n'
        '  [[ ! -f "$count_file" ]] || count="$(<"$count_file")"\n'
        "  count=$((count + 1))\n"
        '  printf "%s\\n" "$count" > "$count_file"\n'
        '  [[ "$count" -lt 2 ]]\n'
        "}\n"
        "verify_activitylogger_rollback_app() {\n"
        "  return 0\n"
        "}\n",
    )
    _write_executable(scripts / "sign_app.sh", "#!/bin/bash\nexit 0\n")
    _write_executable(
        repo / ".venv" / "bin" / "python",
        "#!/bin/bash\nprintf '3.11.9\\n'\n",
    )
    _write_executable(
        repo / ".venv" / "bin" / "pyinstaller",
        "#!/bin/bash\n"
        "while [[ $# -gt 0 ]]; do\n"
        '  if [[ "$1" == "--distpath" ]]; then shift; dist="$1"; fi\n'
        "  shift\n"
        "done\n"
        'mkdir -p "$dist/ActivityLoggerNative.app"\n'
        'printf "new\\n" > "$dist/ActivityLoggerNative.app/marker"\n',
    )
    old_app = repo / "dist" / "ActivityLoggerNative.app"
    old_app.mkdir(parents=True)
    (old_app / "marker").write_text("old\n", encoding="utf-8")

    env = os.environ.copy()
    env["ACTIVITYLOGGER_REPO"] = str(repo)
    env["ACTIVITYLOGGER_SKIP_RESTART"] = "1"
    result = subprocess.run(
        ["bash", str(scripts / "rebuild_and_restart.sh")],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode != 0
    assert (old_app / "marker").read_text(encoding="utf-8") == "old\n"
    assert not list((repo / "dist").glob(".ActivityLoggerNative.app.previous.*"))
    assert not list(repo.glob(".build-stage.*"))


def _prepare_lifecycle_repo(tmp_path: Path, scenario: str) -> tuple[Path, dict[str, str]]:
    repo = tmp_path / "repo with spaces"
    scripts = repo / "scripts"
    libs = scripts / "lib"
    libs.mkdir(parents=True)
    fake_launchctl = tmp_path / "launchctl"
    fake_sleep = tmp_path / "sleep"
    fake_ps = tmp_path / "ps"
    fake_kill = tmp_path / "kill"
    rebuild_text = (REPO / "scripts" / "rebuild_and_restart.sh").read_text(encoding="utf-8")
    rebuild = scripts / "rebuild_and_restart.sh"
    rebuild.write_text(rebuild_text, encoding="utf-8")
    rebuild.chmod(0o755)
    restart = scripts / "restart_logger.sh"
    restart.write_text(
        (REPO / "scripts" / "restart_logger.sh").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    restart.chmod(0o755)
    lifecycle_text = (
        REPO / "scripts" / "lib" / "exact_process_lifecycle.sh"
    ).read_text(encoding="utf-8")
    lifecycle_text = lifecycle_text.replace("/bin/launchctl", str(fake_launchctl))
    lifecycle_text = lifecycle_text.replace("/bin/sleep", str(fake_sleep))
    lifecycle_text = lifecycle_text.replace("/bin/ps", str(fake_ps))
    lifecycle_text = lifecycle_text.replace("/bin/kill", str(fake_kill))
    _write_executable(libs / "exact_process_lifecycle.sh", lifecycle_text)
    (repo / ".python-version").write_text("3.11.9\n", encoding="utf-8")
    (repo / "ActivityLoggerNative.spec").write_text("# fake\n", encoding="utf-8")

    _write_executable(
        libs / "resolve_repo_root.sh",
        '#!/bin/bash\nresolve_repo_root() { REPO="$ACTIVITYLOGGER_REPO"; export REPO; }\n',
    )
    _write_executable(
        libs / "require_certificate_leaf.sh",
        "#!/bin/bash\n"
        "verify_activitylogger_app() {\n"
        '  printf "current %s\\n" "$1" >> "$REPO/verify-log"\n'
        "  return 0\n"
        "}\n"
        "verify_activitylogger_rollback_app() {\n"
        '  printf "rollback %s\\n" "$1" >> "$REPO/verify-log"\n'
        '  [[ "${ACTIVITYLOGGER_LIFECYCLE_SCENARIO:-}" != "invalid-rollback" ]]\n'
        "}\n",
    )
    _write_executable(
        scripts / "sign_app.sh",
        "#!/bin/bash\n"
        'printf "%s\\n" "${ACTIVITYLOGGER_APP:-}" >> "$ACTIVITYLOGGER_REPO/sign-log"\n',
    )
    _write_executable(
        repo / ".venv" / "bin" / "python",
        "#!/bin/bash\nprintf '3.11.9\\n'\n",
    )
    _write_executable(
        repo / ".venv" / "bin" / "pyinstaller",
        "#!/bin/bash\n"
        "while [[ $# -gt 0 ]]; do\n"
        '  if [[ "$1" == "--distpath" ]]; then shift; dist="$1"; fi\n'
        "  shift\n"
        "done\n"
        'mkdir -p "$dist/ActivityLoggerNative.app"\n'
        'printf "new\\n" > "$dist/ActivityLoggerNative.app/marker"\n',
    )
    _write_executable(
        fake_launchctl,
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        'state="$ACTIVITYLOGGER_REPO/process-state"\n'
        'agent_state="$ACTIVITYLOGGER_REPO/launch-agent-state"\n'
        'executable="$ACTIVITYLOGGER_REPO/dist/ActivityLoggerNative.app/Contents/MacOS/ActivityLoggerNative"\n'
        'if [[ "$1" == "bootout" ]]; then\n'
        '  [[ "$(<"$agent_state")" == "loaded" ]] || exit 3\n'
        '  printf "unloaded\\n" > "$agent_state"\n'
        '  printf "bootout\\n" >> "$ACTIVITYLOGGER_REPO/lifecycle-log"\n'
        'elif [[ "$1" == "bootstrap" ]]; then\n'
        '  [[ "$(<"$agent_state")" == "unloaded" ]] || exit 4\n'
        '  printf "loaded\\n" > "$agent_state"\n'
        '  count_file="$ACTIVITYLOGGER_REPO/bootstrap-count"\n'
        '  count=0; [[ ! -f "$count_file" ]] || count="$(<"$count_file")"\n'
        '  count=$((count + 1)); printf "%s\\n" "$count" > "$count_file"\n'
        '  printf "0\\n" > "$ACTIVITYLOGGER_REPO/post-bootstrap-print-count"\n'
        '  printf "bootstrap %s\\n" "$count" >> "$ACTIVITYLOGGER_REPO/lifecycle-log"\n'
        '  if [[ "$ACTIVITYLOGGER_LIFECYCLE_SCENARIO:$count" == "config-bootstrap-failure:1" ]]; then\n'
        '    printf "unloaded\\n" > "$agent_state"\n'
        '    exit 5\n'
        '  fi\n'
        '  case "$ACTIVITYLOGGER_LIFECYCLE_SCENARIO:$count" in\n'
        '    stubborn-success:1) printf "201|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    stale-then-rollback:1) printf "101|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    stale-then-rollback:2) printf "301|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    no-preexisting:1) printf "401|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    late-old:1) printf "103|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    late-old:2) printf "501|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    keepalive-race:1) printf "701|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    config-success:1) printf "201|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    config-pid-reuse:1) printf "101|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    config-pid-reuse:2) printf "202|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    config-bootstrap-failure:2) printf "211|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    config-health-failure:1) printf "221|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    config-health-failure:2) printf "222|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    config-revalidation-failure:1) printf "201|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    slow-wrapper:1) ;;\n'
        '    *) exit 2 ;;\n'
        '  esac\n'
        'elif [[ "$1" == "print" ]]; then\n'
        '  [[ "$(<"$agent_state")" == "loaded" ]] || exit 3\n'
        '  if [[ "$ACTIVITYLOGGER_LIFECYCLE_SCENARIO" == "slow-wrapper" && -f "$ACTIVITYLOGGER_REPO/bootstrap-count" ]]; then\n'
        '    poll_file="$ACTIVITYLOGGER_REPO/post-bootstrap-print-count"\n'
        '    poll="$(<"$poll_file")"; poll=$((poll + 1)); printf "%s\\n" "$poll" > "$poll_file"\n'
        '    if [[ "$poll" -eq 60 ]]; then printf "601|%s|term\\n" "$executable" >> "$state"; fi\n'
        '  fi\n'
        '  if [[ "$ACTIVITYLOGGER_LIFECYCLE_SCENARIO" == "config-health-failure" && "$(<"$ACTIVITYLOGGER_REPO/bootstrap-count")" == "1" ]]; then\n'
        "    printf 'state = waiting\\n'\n"
        '    exit 0\n'
        '  fi\n'
        "  printf 'state = running\\n'\n"
        "else\n"
        "  exit 2\n"
        "fi\n",
    )
    _write_executable(
        fake_sleep,
        "#!/bin/bash\n"
        'printf "sleep\\n" >> "$ACTIVITYLOGGER_REPO/sleep-log"\n',
    )
    _write_executable(
        fake_ps,
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        'state="$ACTIVITYLOGGER_REPO/process-state"\n'
        'if [[ "$1" == "-axo" && "$2" == "pid=,command=" ]]; then\n'
        '  count_file="$ACTIVITYLOGGER_REPO/ps-snapshot-count"\n'
        '  count=0; [[ ! -f "$count_file" ]] || count="$(<"$count_file")"\n'
        '  count=$((count + 1)); printf "%s\\n" "$count" > "$count_file"\n'
        '  executable="$ACTIVITYLOGGER_REPO/dist/ActivityLoggerNative.app/Contents/MacOS/ActivityLoggerNative"\n'
        '  case "$ACTIVITYLOGGER_LIFECYCLE_SCENARIO:$count" in\n'
        '    late-old:2) printf "103|%s|term\\n" "$executable" >> "$state" ;;\n'
        '    pre-snapshot-failure:1) exit 1 ;;\n'
        '    config-snapshot-failure:1) exit 1 ;;\n'
        '    config-revalidation-failure:2) exit 1 ;;\n'
        '  esac\n'
        "  while IFS='|' read -r pid command behavior; do\n"
        '    [[ -z "$pid" ]] || printf " %s %s\\n" "$pid" "$command"\n'
        '  done < "$state"\n'
        'elif [[ "$1" == "-p" && "$3" == "-o" && "$4" == "command=" ]]; then\n'
        '  wanted="$2"\n'
        '  if [[ "$ACTIVITYLOGGER_LIFECYCLE_SCENARIO" == "config-revalidation-failure" && "$wanted" == "101" ]]; then exit 1; fi\n'
        "  while IFS='|' read -r pid command behavior; do\n"
        '    if [[ "$pid" == "$wanted" ]]; then printf "%s\\n" "$command"; exit 0; fi\n'
        '  done < "$state"\n'
        "  exit 1\n"
        "else\n"
        "  exit 2\n"
        "fi\n",
    )
    _write_executable(
        fake_kill,
        "#!/bin/bash\n"
        "set -euo pipefail\n"
        'signal="$1"; wanted="$2"; state="$ACTIVITYLOGGER_REPO/process-state"\n'
        'temporary="$state.tmp"\n'
        ': > "$temporary"\n'
        "while IFS='|' read -r pid command behavior; do\n"
        '  if [[ "$pid" != "$wanted" ]]; then\n'
        '    printf "%s|%s|%s\\n" "$pid" "$command" "$behavior" >> "$temporary"\n'
        "    continue\n"
        "  fi\n"
        '  printf "%s %s %s\\n" "$signal" "$pid" "$command" >> "$ACTIVITYLOGGER_REPO/kill-log"\n'
        '  printf "kill %s %s\\n" "$signal" "$pid" >> "$ACTIVITYLOGGER_REPO/lifecycle-log"\n'
        '  if [[ "$signal" == "-TERM" && "$behavior" == "stubborn" ]]; then\n'
        '    printf "%s|%s|%s\\n" "$pid" "$command" "$behavior" >> "$temporary"\n'
        "  fi\n"
        'done < "$state"\n'
        '/bin/mv "$temporary" "$state"\n'
        'if [[ "$ACTIVITYLOGGER_LIFECYCLE_SCENARIO" == "keepalive-race" && "$signal" == "-TERM" && "$(<"$ACTIVITYLOGGER_REPO/launch-agent-state")" == "loaded" ]]; then\n'
        '  printf "777|%s|term\\n" "$ACTIVITYLOGGER_REPO/dist/ActivityLoggerNative.app/Contents/MacOS/ActivityLoggerNative" >> "$state"\n'
        'fi\n',
    )

    old_app = repo / "dist" / "ActivityLoggerNative.app"
    old_app.mkdir(parents=True)
    (old_app / "marker").write_text("old\n", encoding="utf-8")
    executable = old_app / "Contents" / "MacOS" / "ActivityLoggerNative"
    process_state = repo / "process-state"
    if scenario == "stubborn-success":
        process_state.write_text(
            f"101|{executable}|stubborn\n"
            f"102|{tmp_path / 'unrelated' / 'ActivityLoggerNative'}|stubborn\n",
            encoding="utf-8",
        )
    elif scenario == "stale-then-rollback":
        process_state.write_text(f"101|{executable}|term\n", encoding="utf-8")
    elif scenario == "no-preexisting":
        process_state.write_text("", encoding="utf-8")
    elif scenario == "late-old":
        process_state.write_text(f"101|{executable}|term\n", encoding="utf-8")
    elif scenario == "keepalive-race":
        process_state.write_text(f"101|{executable}|term\n", encoding="utf-8")
    elif scenario == "slow-wrapper":
        process_state.write_text("", encoding="utf-8")
    elif scenario == "pre-snapshot-failure":
        process_state.write_text("", encoding="utf-8")
    elif scenario == "invalid-rollback":
        process_state.write_text("", encoding="utf-8")
    elif scenario == "config-success":
        process_state.write_text(
            f"101|{executable}|term\n"
            f"102|{tmp_path / 'unrelated' / 'ActivityLoggerNative'}|stubborn\n",
            encoding="utf-8",
        )
    elif scenario in {
        "config-bootstrap-failure",
        "config-health-failure",
        "config-pid-reuse",
        "config-revalidation-failure",
        "config-snapshot-failure",
    }:
        process_state.write_text(f"101|{executable}|term\n", encoding="utf-8")
    else:  # pragma: no cover - helper contract
        raise AssertionError(f"unknown lifecycle scenario: {scenario}")

    env = os.environ.copy()
    launch_plist = repo / "LaunchAgents" / "com.mk.activitylogger.plist"
    launch_plist.parent.mkdir()
    with launch_plist.open("wb") as fh:
        plistlib.dump(
            {
                "Label": "com.mk.activitylogger",
                "ProgramArguments": ["/bin/bash", str(repo / "start_logger.sh")],
                "RunAtLoad": True,
                "KeepAlive": True,
                "Umask": 0o77,
            },
            fh,
        )
    launch_plist.chmod(0o600)
    (repo / "launch-agent-state").write_text("loaded\n", encoding="utf-8")
    env["ACTIVITYLOGGER_REPO"] = str(repo)
    env["ACTIVITYLOGGER_LIFECYCLE_SCENARIO"] = scenario
    env["ACTIVITYLOGGER_LAUNCH_PLIST"] = str(launch_plist)
    return repo, env


def _run_lifecycle_rebuild(repo: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(repo / "scripts" / "rebuild_and_restart.sh")],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def _run_config_restart(repo: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(repo / "scripts" / "restart_logger.sh")],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )


def test_operator_restart_scripts_share_exact_process_lifecycle():
    lifecycle = (REPO / "scripts" / "lib" / "exact_process_lifecycle.sh").read_text()
    rebuild = (REPO / "scripts" / "rebuild_and_restart.sh").read_text()
    restart = (REPO / "scripts" / "restart_logger.sh").read_text()
    install = (REPO / "scripts" / "install_launch_agent.sh").read_text()

    assert "/bin/launchctl bootout" in lifecycle
    assert "/bin/launchctl bootstrap" in lifecycle
    assert "kickstart -k" not in lifecycle
    assert "exact_process_lifecycle.sh" in rebuild
    assert "exact_process_lifecycle.sh" in restart
    assert "restart_exact_app_via_launch_agent" in restart
    assert "scripts/restart_logger.sh" in install
    for operator in (REPO / "scripts").glob("*.sh"):
        assert "/bin/launchctl kickstart -k" not in operator.read_text()


def test_config_restart_kills_only_exact_old_path_and_proves_fresh_pid(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "config-success")
    result = _run_config_restart(repo, env)

    assert result.returncode == 0, result.stdout + result.stderr
    kill_log = (repo / "kill-log").read_text(encoding="utf-8")
    assert "-TERM 101 " in kill_log
    assert " 102 " not in kill_log
    lifecycle = (repo / "lifecycle-log").read_text(encoding="utf-8").splitlines()
    assert lifecycle.index("bootout") < lifecycle.index("kill -TERM 101")
    assert lifecycle.index("kill -TERM 101") < lifecycle.index("bootstrap 1")
    state = (repo / "process-state").read_text(encoding="utf-8")
    assert "101|" not in state
    assert "102|" in state
    assert "201|" in state
    assert "fresh verified process" in result.stdout


def test_config_restart_rejects_reused_old_pid(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "config-pid-reuse")
    result = _run_config_restart(repo, env)

    assert result.returncode != 0
    assert "stable fresh process state" in result.stderr
    assert (repo / "bootstrap-count").read_text(encoding="utf-8").strip() == "2"
    assert (repo / "launch-agent-state").read_text(encoding="utf-8").strip() == "loaded"
    state = (repo / "process-state").read_text(encoding="utf-8")
    assert "101|" not in state
    assert "202|" in state
    assert "fresh verified process" not in result.stdout


def test_config_restart_bootstrap_failure_recovers_unchanged_service(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "config-bootstrap-failure")
    result = _run_config_restart(repo, env)

    assert result.returncode != 0
    assert (repo / "bootstrap-count").read_text(encoding="utf-8").strip() == "2"
    assert (repo / "launch-agent-state").read_text(encoding="utf-8").strip() == "loaded"
    state = (repo / "process-state").read_text(encoding="utf-8")
    assert "211|" in state
    assert "stable fresh process state" in result.stderr


def test_config_restart_health_failure_quiesces_and_recovers_service(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "config-health-failure")
    result = _run_config_restart(repo, env)

    assert result.returncode != 0
    assert (repo / "bootstrap-count").read_text(encoding="utf-8").strip() == "2"
    assert (repo / "launch-agent-state").read_text(encoding="utf-8").strip() == "loaded"
    lifecycle = (repo / "lifecycle-log").read_text(encoding="utf-8").splitlines()
    assert lifecycle.count("bootout") == 2
    assert lifecycle.index("kill -TERM 221") < lifecycle.index("bootstrap 2")
    state = (repo / "process-state").read_text(encoding="utf-8")
    assert "221|" not in state
    assert "222|" in state
    assert "stable fresh process state" in result.stderr


def test_config_restart_snapshot_failure_leaves_old_process_untouched(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "config-snapshot-failure")
    result = _run_config_restart(repo, env)

    assert result.returncode != 0
    assert "could not capture the existing" in result.stderr
    assert not (repo / "kill-log").exists()
    assert not (repo / "bootstrap-count").exists()
    state = (repo / "process-state").read_text(encoding="utf-8")
    assert "101|" in state


def test_config_restart_revalidation_failure_leaves_old_process_untouched(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "config-revalidation-failure")
    result = _run_config_restart(repo, env)

    assert result.returncode != 0
    assert "post-bootout ActivityLogger process set" in result.stderr
    assert not (repo / "kill-log").exists()
    assert (repo / "bootstrap-count").read_text(encoding="utf-8").strip() == "1"
    assert (repo / "launch-agent-state").read_text(encoding="utf-8").strip() == "loaded"
    state = (repo / "process-state").read_text(encoding="utf-8")
    assert "101|" in state


def test_rebuild_kills_only_exact_stale_path_and_escalates(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "stubborn-success")
    result = _run_lifecycle_rebuild(repo, env)

    assert result.returncode == 0, result.stdout + result.stderr
    kill_log = (repo / "kill-log").read_text(encoding="utf-8")
    assert "-TERM 101 " in kill_log
    assert "-KILL 101 " in kill_log
    assert " 102 " not in kill_log
    state = (repo / "process-state").read_text(encoding="utf-8")
    assert "101|" not in state
    assert "102|" in state
    assert "201|" in state


def test_running_wrapper_with_only_stale_pid_rolls_back_to_fresh_pid(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "stale-then-rollback")
    result = _run_lifecycle_rebuild(repo, env)

    assert result.returncode != 0
    old_app = repo / "dist" / "ActivityLoggerNative.app"
    assert (old_app / "marker").read_text(encoding="utf-8") == "old\n"
    assert (repo / "bootstrap-count").read_text(encoding="utf-8").strip() == "2"
    assert "stable fresh process state" in result.stderr
    assert "fresh verified process" in result.stderr
    verify_log = (repo / "verify-log").read_text(encoding="utf-8").splitlines()
    assert [line.split()[0] for line in verify_log] == [
        "current",
        "rollback",
        "current",
        "rollback",
    ]
    signed_paths = (repo / "sign-log").read_text(encoding="utf-8").splitlines()
    assert len(signed_paths) == 1
    assert ".build-stage." in signed_paths[0]
    assert signed_paths[0] != str(old_app)
    state = (repo / "process-state").read_text(encoding="utf-8")
    assert "101|" not in state
    assert "301|" in state
    assert not list((repo / "dist").glob(".ActivityLoggerNative.app.previous.*"))


def test_rebuild_without_preexisting_pid_accepts_fresh_exact_process(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "no-preexisting")
    result = _run_lifecycle_rebuild(repo, env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert not (repo / "kill-log").exists()
    state = (repo / "process-state").read_text(encoding="utf-8")
    assert "401|" in state


def test_rebuild_waits_for_slow_wrapper_then_takes_fresh_stability_sample(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "slow-wrapper")
    result = _run_lifecycle_rebuild(repo, env)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "601|" in (repo / "process-state").read_text(encoding="utf-8")
    polls = int(
        (repo / "post-bootstrap-print-count").read_text(encoding="utf-8").strip()
    )
    assert polls >= 61


def test_rebuild_boots_out_before_term_so_keepalive_cannot_race(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "keepalive-race")
    result = _run_lifecycle_rebuild(repo, env)

    assert result.returncode == 0, result.stdout + result.stderr
    lifecycle = (repo / "lifecycle-log").read_text(encoding="utf-8").splitlines()
    assert lifecycle.index("bootout") < lifecycle.index("kill -TERM 101")
    state = (repo / "process-state").read_text(encoding="utf-8")
    assert "777|" not in state
    assert "701|" in state


def test_rebuild_terminates_exact_old_pid_created_after_initial_snapshot(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "late-old")
    result = _run_lifecycle_rebuild(repo, env)

    assert result.returncode != 0
    kill_log = (repo / "kill-log").read_text(encoding="utf-8")
    assert "-TERM 101 " in kill_log
    assert "-TERM 103 " in kill_log
    assert (repo / "bootstrap-count").read_text(encoding="utf-8").strip() == "2"
    lifecycle = (repo / "lifecycle-log").read_text(encoding="utf-8").splitlines()
    assert lifecycle.index("kill -TERM 103") < lifecycle.index("bootstrap 1")
    assert "stable fresh process state" in result.stderr
    assert "fresh verified process" in result.stderr
    state = (repo / "process-state").read_text(encoding="utf-8")
    assert "101|" not in state
    assert "103|" not in state
    assert "501|" in state


def test_rebuild_fails_closed_when_pre_promotion_snapshot_fails(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "pre-snapshot-failure")
    result = _run_lifecycle_rebuild(repo, env)

    assert result.returncode != 0
    assert "could not capture the existing" in result.stderr
    old_app = repo / "dist" / "ActivityLoggerNative.app"
    assert (old_app / "marker").read_text(encoding="utf-8") == "old\n"
    assert not (repo / "bootstrap-count").exists()


def test_rebuild_rejects_invalid_rollback_app_before_promotion(tmp_path):
    repo, env = _prepare_lifecycle_repo(tmp_path, "invalid-rollback")
    old_app = repo / "dist" / "ActivityLoggerNative.app"
    result = _run_lifecycle_rebuild(repo, env)

    assert result.returncode != 0
    assert (old_app / "marker").read_text(encoding="utf-8") == "old\n"
    assert not list((repo / "dist").glob(".ActivityLoggerNative.app.previous.*"))
    assert not (repo / "bootstrap-count").exists()
    verify_log = (repo / "verify-log").read_text(encoding="utf-8").splitlines()
    assert [line.split()[0] for line in verify_log] == ["current", "rollback"]


def test_bundle_declares_apple_events_purpose_and_entitlement():
    spec = (REPO / "ActivityLoggerNative.spec").read_text()
    entitlements = plistlib.loads(
        (REPO / "ActivityLoggerNative.entitlements").read_bytes()
    )
    assert "NSAppleEventsUsageDescription" in spec
    assert entitlements["com.apple.security.automation.apple-events"] is True


def test_setup_uses_dedicated_keychain_and_nonextractable_import():
    setup = (REPO / "scripts" / "setup_signing_identity.sh").read_text()
    signing = (REPO / "scripts" / "sign_app.sh").read_text()
    assert "activitylogger-signing.keychain-db" in setup
    assert "security import" in setup
    assert " -x " in setup
    assert 'create-keychain -P "$keychain"' in setup
    assert 'unlock-keychain -u "$keychain"' in setup
    assert 'import "$p12" -k "$keychain" -f pkcs12 -x' in setup
    assert "--create-ephemeral-ci" in setup
    assert "--rotate-identity" in setup
    assert 'deployed_app_fingerprint "$deployed_app"' in setup
    assert 'require_identity_continuity "$deployed_fingerprint" "$fingerprint" "$rotate"' in setup
    assert 'unlock-keychain -u "$KEYCHAIN"' in signing
    assert "activitylogger-local-codesign" not in setup
    assert "create-keychain" not in signing
    assert "openssl req" not in signing

    workflow = (REPO / ".github" / "workflows" / "ci.yml").read_text()
    assert "runs-on: macos-15" in workflow
    assert "ACTIVITYLOGGER_KEYCHAIN_PASSWORD" not in workflow
    assert "ACTIVITYLOGGER_P12_PASS" not in workflow


def test_signing_identity_continuity_requires_explicit_rotation():
    setup = REPO / "scripts" / "setup_signing_identity.sh"
    old = "a" * 40
    new = "b" * 40
    mismatch = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; require_identity_continuity "$2" "$3" 0',
            "bash",
            str(setup),
            old,
            new,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert mismatch.returncode != 0
    assert "does not match deployed app leaf" in mismatch.stderr

    rotated = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; require_identity_continuity "$2" "$3" 1',
            "bash",
            str(setup),
            old,
            new,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert rotated.returncode == 0
    assert "TCC grants will not follow" in rotated.stderr


def test_signing_cleanup_removes_only_a_pin_created_by_this_invocation(tmp_path):
    setup = REPO / "scripts" / "setup_signing_identity.sh"
    pin = tmp_path / "leaf.sha1"
    pin.write_text("pre-existing\n", encoding="utf-8")
    preserved = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; cleanup_created_pin 1 0 "$2"',
            "bash",
            str(setup),
            str(pin),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert preserved.returncode == 0
    assert pin.read_text(encoding="utf-8") == "pre-existing\n"

    created = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; cleanup_created_pin 1 1 "$2"',
            "bash",
            str(setup),
            str(pin),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert created.returncode == 0
    assert not pin.exists()

    setup_text = setup.read_text(encoding="utf-8")
    assert '/bin/ln "$pin_temporary" "$pin_file"' in setup_text
    assert 'cleanup_created_pin "$status" "$pin_created" "$pin_file"' in setup_text
    assert "trap - EXIT" in setup_text


@pytest.mark.skipif(sys.platform != "darwin", reason="codesign is macOS-only")
def test_verifier_rejects_ad_hoc_signature(tmp_path):
    app = tmp_path / "AdHoc.app"
    executable = app / "Contents" / "MacOS" / "AdHoc"
    executable.parent.mkdir(parents=True)
    shutil.copyfile("/usr/bin/true", executable)
    executable.chmod(0o755)
    plist_path = app / "Contents" / "Info.plist"
    with plist_path.open("wb") as fh:
        plistlib.dump(
            {
                "CFBundleExecutable": "AdHoc",
                "CFBundleIdentifier": "com.mk.activitylogger.native",
                "CFBundlePackageType": "APPL",
            },
            fh,
        )
    subprocess.run(
        [
            "codesign",
            "--force",
            "--sign",
            "-",
            "--options",
            "runtime",
            "--identifier",
            "com.mk.activitylogger.native",
            str(app),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    env = os.environ.copy()
    env["ACTIVITYLOGGER_REPO"] = str(REPO)
    env["ACTIVITYLOGGER_CERT_SHA1"] = "0" * 40
    result = subprocess.run(
        [str(VERIFY), str(app)],
        check=False,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.returncode != 0
    output = result.stdout + result.stderr
    assert "pinned identity" in output


def _run_shell_ensure_log_dir(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; ensure_log_dir "$2"',
            "bash",
            str(REPO / "scripts" / "lib" / "ensure_log_dir.sh"),
            str(path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )


def test_log_directory_helper_creates_private_directory_without_rewriting_files(tmp_path):
    log_dir = tmp_path / "logs"
    assert _run_shell_ensure_log_dir(log_dir).returncode == 0
    log_file = log_dir / "capture.log"
    log_file.write_text("private")
    log_file.chmod(0o644)
    assert _run_shell_ensure_log_dir(log_dir).returncode == 0
    assert log_dir.stat().st_mode & 0o777 == 0o700
    assert log_file.stat().st_mode & 0o777 == 0o644


def test_log_directory_helper_rejects_shared_directory_file_and_symlink(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir(mode=0o755)
    shared.chmod(0o755)
    assert _run_shell_ensure_log_dir(shared).returncode != 0
    assert shared.stat().st_mode & 0o777 == 0o755

    leaf = tmp_path / "leaf"
    leaf.write_text("not a directory", encoding="utf-8")
    assert _run_shell_ensure_log_dir(leaf).returncode != 0

    link = tmp_path / "link"
    link.symlink_to(shared, target_is_directory=True)
    assert _run_shell_ensure_log_dir(link).returncode != 0
