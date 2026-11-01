# ActivityLogger for macOS

ActivityLogger is a private work journal for one person using a Mac. It records local work context and activity so you can remember what you worked on, see where your attention moved, find repeated steps, and spot small ways to work more efficiently.

It can prepare a focused review of 5 or 7 completed calendar days. ActivityLogger creates the review files, but it does not analyze them, upload them, or act on their contents. You choose a tool you trust and decide what to do with the result.

**Version:** 4.7.0 | **Runtime:** `dist/ActivityLoggerNative.app` | **Operations:** [`docs/MACOS_TCC.md`](docs/MACOS_TCC.md)

> ActivityLogger records sensitive plaintext, including typed text and clipboard changes. Use it only on a Mac and user account that you control.

## What it helps you do

- Rebuild the story of a workday from app, window, and activity context.
- See recorded context changes and work spans across the day.
- Find repeated work, friction, and possible errors during a weekly review.
- Ask for up to five small improvement ideas and rank the top three by likely value and effort.
- Save whether you found an idea, tried a change, or took no action, with an optional value note.
- Keep the source data local. ActivityLogger uploads nothing, but on this Mac a separate tool uploads ready daily logs to NotebookLM (see [Uploads by context-aggregator](#uploads-by-context-aggregator)).

ActivityLogger is not an exact time tracker or a billing timesheet. A work span shows observed activity, not proven effort time. Gaps can mean idle time, a privacy pause, stopped capture, or missing capture.

## How it works

1. The background app writes observed activity to one private Markdown file for each local calendar day.
2. The Review Center checks logger health, recent safe writes, privacy state, private storage, and whether selected days are ready.
3. You create a review pack for exactly 5 or 7 consecutive completed calendar days. A day that is missing or not ready is not replaced with an older day.
4. You review the pack with a trusted tool, check its evidence and limits, then record the review outcome and an optional note.

The daily Markdown logs stay the source records. Weekly packs are views made for review. They can lose some click order and timing detail, so they do not replace the daily logs.

## What it records

| Data | Default | What it means |
|---|---:|---|
| Active app and window | On | Uses native macOS details first. If ActivityWatch is installed, ActivityLogger can also use its local window title. By default, it connects only to this Mac. |
| Typed characters and hotkeys | On | Keeps the local input trail needed to understand work context. |
| Clicks | On | Records click details when macOS Accessibility can provide them. |
| Changed Accessibility text | On | Reads text exposed by macOS Accessibility. This is not a screenshot or screen image. |
| Clipboard changes | On | Records changed clipboard text outside privacy pauses. |
| Browser URLs | Off | When enabled, safe mode removes user information and fragments and hides the full query string. |
| Trigger labels | Off | Can add a small reason label when a section closes. |
| Scroll capture | Off | Can group a short scroll burst into one bounded event. |

ActivityLogger does not capture screenshots, Screen Recording, audio, video, camera input, or mouse-move trails. Base capture does not need Screen Recording permission.

## Weekly Review Center

ActivityLogger runs in the background and has no normal Dock window. While it is running, open `dist/ActivityLoggerNative.app` in Finder to show the Review Center.

The window opens on **Daily status**. It shows capture state, pause reasons, the last safe write, storage and **Recovery help**. Use **Weekly review** for the three steps:

1. Choose the last day and select 5 or 7 consecutive completed calendar days. Select **Create review files**.
2. Select **Show review files in Finder**. Start with `REVIEW_PROMPT.md`. Review and redact private text before using any online tool.
3. After the review, choose **Found an idea to try**, **Tried a change**, or **No action**. You can also save a short value note, such as time saved each week.

A result draft stays tied to its selected dates. Save it or select **Clear draft** before changing the window. Each text field has a 4,000 character limit. **Show saved results** opens the private outcome file in Finder. New outcomes keep the exact start, end and day count.

Read the context quality and heartbeat gap warnings before trusting the result. Valid files can still have weak labels or missing activity.

The Review Center pauses capture while its window is visible. Switching tabs does not change this pause. Closing or minimizing it removes only this window pause. Manual pause or a secure app or field can keep capture paused.

The Review Center window and its status checks do not show captured text. The review files do contain private captured text.

## Daily privacy controls

Normal daily use is passive. Open **Daily status** to check status or turn manual pause on or off. Unknown runtime state is shown as unknown, not as active capture. The same local controls are available from Terminal:

```bash
.venv/bin/python scripts/activityloggerctl.py health
.venv/bin/python scripts/activityloggerctl.py storage
.venv/bin/python scripts/activityloggerctl.py pause
.venv/bin/python scripts/activityloggerctl.py resume
```

Help, pause and resume work even when the default log config is broken. Read [local recovery help](docs/V2_RECOVERY.md) for storage, readiness and config problems.

Manual pause stops every capture channel. It stays on after a restart. Resume clears only manual pause and never clears a secure-app or secure-field pause.

Apps matched by the secure-app list in the config and macOS secure text fields pause all capture. Unknown privacy state also pauses capture. Clipboard changes seen during a pause are consumed and are not written after resume.

## Private files and retention

The built-in daily log path is:

```text
~/scripts/activitylogger/logs/daily_log_YYYY-MM-DD.md
```

You can change the log directory in the local config. The signed app stores review packs, review outcomes, and private runtime state under:

```text
~/Library/Application Support/ActivityLogger/
```

If a write cannot be prepared safely, capture stops accepting new activity, keeps accepted records in memory and retries with a delay. Keep the app running while storage is blocked. After recovery it records a storage gap.

Private directories use mode `700`, and private files use mode `600`. These files are still sensitive plaintext. ActivityLogger does not redact them and does not delete them automatically. They stay until you archive or delete them. Keep FileVault enabled, avoid shared backups, and review every file before external use.

Browser URL capture is off by default. ActivityWatch enrichment is on by default and connects only to this Mac unless the operator turns on remote access. Remote ActivityWatch access and full URL capture require clear choices and produce privacy warnings.

## Uploads by context-aggregator

ActivityLogger itself uploads nothing. A separate local tool, context-aggregator, uploads the daily logs, including typed text and clipboard changes. Its LaunchAgent, `com.context-aggregator.activity-logs`, runs every 15 minutes and uploads each ready daily log to the Google NotebookLM notebook named Myro Logs. Before upload, that tool applies its own size limits and credential redaction. It blocks any day where credentials remain. The tool lives in `~/scripts/contextAggregator`, and ActivityLogger does not depend on it. Unload that LaunchAgent to stop the uploads.

## Existing installation and maintainer setup

This repository is built for a signed local installation that is already managed by its operator. It is not a clean download-and-run package. A new machine needs an approved signing identity and a checked first-install plan. Do not create or rotate a signing identity just to bypass a setup error.

The maintained build uses macOS on Apple silicon, exact Python 3.11.9 from [`.python-version`](.python-version), and the project-local `.venv`:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
.venv/bin/python -m pip check
.venv/bin/ruff check --select E4,E7,E9,F .
.venv/bin/python -m pip_audit --strict
.venv/bin/python -m pytest -q
```

`requirements.txt` is the locked macOS Apple silicon environment. Regenerate it only with `./scripts/compile_requirements.sh`.

For the one-time migration of an existing PKCS#12 identity, follow [`docs/MACOS_TCC.md`](docs/MACOS_TCC.md). The setup uses native macOS password prompts and checks the certificate against the deployed app. Normal builds never create or rotate an identity.

Create the optional local config with private permissions:

```bash
mkdir -p ~/.config/activitylogger
cp config.example.toml ~/.config/activitylogger/config.toml
chmod 700 ~/.config/activitylogger
chmod 600 ~/.config/activitylogger/config.toml
```

Config loads once when the app starts. For a config-only change, run:

```bash
./scripts/restart_logger.sh
```

After a source change, use the required signed build and restart:

```bash
./scripts/rebuild_and_restart.sh
```

Use `./scripts/install_launch_agent.sh` only to install or repair the existing Launch Agent, then run `./scripts/restart_logger.sh`. Grant `dist/ActivityLoggerNative.app` Accessibility and Input Monitoring. Optional browser URL capture may also ask for Automation permission for each browser you enable.

Do not run both a Login Item and the Launch Agent. Do not launch Python directly from launchd. The full signing, TCC, restart, rollback, and recovery guide is in [`docs/MACOS_TCC.md`](docs/MACOS_TCC.md).

## Advanced local tools

Create a weekly pack without opening the Review Center:

```bash
.venv/bin/python scripts/export_weekly_review.py --end YYYY-MM-DD --days 5
```

The command prints the full pack path. Weekly packs and outcomes use the user Application Support folder by default. One-day export tools use `private_analysis_review/` in the repository by default and print the full output path. Use `--output-dir` to choose another private folder.

Use `--days 7` for seven days. Every selected day must be complete, use the current v2 format, and pass its private integrity check.

Save a review outcome from Terminal with its exact window:

```bash
.venv/bin/python scripts/activityloggerctl.py review --week YYYY-MM-DD --days 5 --outcome tried --value-result "Saved 15 minutes each week"
```

`--week` is the last day, matching the pack end date. Omitting `--days` is supported for older notes whose exact window is unknown.

Check one day without printing captured text:

```bash
.venv/bin/python scripts/check_analysis_day.py --day YYYY-MM-DD
```

Create a smaller workload view for one completed day:

```bash
.venv/bin/python scripts/export_workload_v3_pilot.py --day YYYY-MM-DD
```

Create a reversible compact view for one day:

```bash
.venv/bin/python scripts/export_compact_analysis.py --day YYYY-MM-DD
```

For older log formats, `compact_markdown_log.py` can reduce repeated text and `historical_analysis.py` can create private review copies. They never change the source logs. Neither tool redacts private text.

## Documentation map

- [`docs/V2_RECOVERY.md`](docs/V2_RECOVERY.md): offline recovery for status, storage, day readiness and review files.
- [`docs/AUDIT_REMEDIATION_2026-09-05.md`](docs/AUDIT_REMEDIATION_2026-09-05.md): the 16 audit fixes and Option C validation.
- [`docs/MACOS_TCC.md`](docs/MACOS_TCC.md): production setup, signing, permissions, restart, rollback, and recovery.
- [`docs/specs/00-MASTER.md`](docs/specs/00-MASTER.md): current product, privacy, capture, and storage contracts.
- [`docs/specs/F2-config.md`](docs/specs/F2-config.md): every config key, default, and allowed range.
- [`docs/specs/IMPL-STATUS.md`](docs/specs/IMPL-STATUS.md): implementation and deployment evidence.
- [`docs/COMPREHENSIVE_REVIEW_2026-08-21.md`](docs/COMPREHENSIVE_REVIEW_2026-08-21.md): dated security and reliability review.

## Latest recorded verification

The 4.6.0 source passed 606 tests, Ruff critical checks, dependency consistency and the strict dependency audit with no known vulnerabilities. Separate code, UX and final integration reviews found no unresolved material issue in their reviewed scope. All 194 completed daily logs match their pre-change hashes.

The signed 4.6.0 app was deployed on 2026-09-05 with the unchanged signing identity and a fresh verified process. Both native tabs were checked live. Switching tabs keeps the privacy pause; closing or minimizing removes it. Fresh typed events reached the log within 14 seconds, with matching intent records and no invalid marker. Storage checks found no unsafe items or missing readiness proofs. See [the current verification record](docs/specs/IMPL-STATUS.md) for evidence and limits.

These results do not prove full capture on every future day. Check Daily status and the pack's quality notes before trusting a review result.
