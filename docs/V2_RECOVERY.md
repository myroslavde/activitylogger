# ActivityLogger local recovery

Use this guide when Daily status shows a problem. It is included in the signed app and works offline. Status never shows captured text. Source logs and review files do contain private text.

## Check before changing anything

1. Open ActivityLogger and select **Daily status**, then **Refresh**. Read the checked time, capture state, pause reasons, last safe write and storage problems.
2. Check whether the logger is running. Unknown status does not mean capture is active or manual pause is off. An old checked time means the window needs a refresh. Runtime state changes on events, so an old state write alone does not prove failure.
3. Keep all source logs, intent journals, ready proofs, invalid markers and pending files. Do not remove markers to make a check pass. Do not edit sources or create proof files by hand.

The Terminal commands below run from the repository folder using its exact Python environment. They show metadata, not captured text:

```bash
.venv/bin/python scripts/activityloggerctl.py health
.venv/bin/python scripts/activityloggerctl.py storage
.venv/bin/python scripts/check_analysis_day.py --day YYYY-MM-DD
```

## Capture is paused or unknown

- **Manual pause:** use the manual control to resume only when you want to. It does not clear any other pause.
- **Review window:** capture stays paused while either tab is visible, even when Finder has focus. Close or minimize the window to remove only this pause.
- **Secure app or field:** move to an ordinary app and field. Unknown privacy state also blocks capture.
- **Storage:** follow the storage steps below. Do not restart while accepted records are waiting in memory.
- **Unknown runtime state:** refresh after confirming the signed app is running. A private `.operator_state.pending` marker means its status write is unfinished. The next successful write clears it; startup keeps manual pause on if the marker remains. Do not remove it to force a confirmation. Do not assume an unconfirmed Resume succeeded. Manual Pause can be requested when the exact process is known.

Manual controls do not need the log config:

```bash
.venv/bin/python scripts/activityloggerctl.py pause
.venv/bin/python scripts/activityloggerctl.py resume
```

## Storage failed or is full

ActivityLogger stops taking new activity when it cannot safely prepare a write. It keeps already accepted records in memory and retries with a delay. After the write succeeds, it records a storage gap and can accept activity again. This prevents a growing queue, but it cannot recover work that happened during the gap.

Free space using unrelated disposable files or your normal archive process. Check that the selected log folder is owned by your user, uses mode `700`, and contains regular private files with mode `600`. Do not use symlinks, hard links or special files as logs. Check the exact item before changing permissions.

Keep the process running while storage is blocked. Restarting or shutting down can lose records that only remain in memory. An uncertain saved transaction is different: capture stops and the normal startup path attempts the same transaction once its files are safe. If recovery refuses, preserve all files for a targeted repair.

## A day is not ready

The current day is always active. Weekly review accepts exactly 5 or 7 completed calendar days starting on or after 2026-08-27. It does not replace a missing day with an older one.

- **Missing:** a required source or intent journal is absent. Choose a complete window or investigate the original capture gap.
- **Unready:** the sources or their ready proof could not be verified. Refresh after a healthy later write. On startup or a day change, the logger checks existing completed days and can publish missing proofs for valid days, including after days when the Mac was off.
- **Invalid:** an invalid marker exists. Preserve the marker, sources, intents and pending evidence. A maintainer must find and repair the exact cause before capture or export can be trusted.
- **Unsupported:** the date uses an older format. Use the historical tools described in the repository README. Do not pass a v2 log to the legacy compactor.

A ready proof checks file integrity. It does not prove good context labels, complete capture or hours worked. Read the context quality and heartbeat gap warnings before using a review result.

## Redacting a completed day

Never edit a source log by hand. A hand edit breaks the day's intent journal, so the day becomes `intent_mismatch` and is not ready. Use the redaction command instead. It works only on a completed v2 day, never on today, so it can run while the logger is running.

Dry run first. It prints counts only, never the literal text:

```bash
.venv/bin/python scripts/activityloggerctl.py redact --day YYYY-MM-DD --literal-file /absolute/private/literals.txt
```

Put one literal per line in the file and keep it `600`, so secrets stay out of shell history. `--literal TEXT` works for text that is not secret. Add `--apply` to write. The command backs up the day's log, intent journal and ready proof to `private_analysis_review/redaction_backups/<day>_<timestamp>/` (folder `700`, files `600`), replaces each literal with `[REDACTED]` inside record payloads only, and republishes the ready proof. It must print `reason_after=ready`.

If a hand edit already made a day `intent_mismatch`, repair it with `--reseal` and no literals. It recomputes the journal digests from the current log and keeps batch ids and counts. Dry run first, then add `--apply`. Keep the backups private, because they contain the original text.

If a dry run reports `proof_missing` or `proof_invalid` while the intent digests still match, `--reseal --apply` only republishes the ready proof. It does not rewrite the log or the journal.

What the command matches and how:

- Matching is per record payload only. A secret split across two records is not caught, so search the day for the secret after a run before you rely on it.
- A literal that appears in a window heading makes the command refuse, because headings are not payloads.
- Literals that overlap inside one payload are replaced once. For example `ab` and `abc` on `abc` give a single `[REDACTED]`.
- Existing `[REDACTED]` text is never matched, and a literal that is part of the marker (such as `RED`) is refused. Running the same command again is safe: the second dry run reports zero occurrences, and `--apply` then refuses and writes nothing.

If `--apply` reports an error after it started, the day may be partly written. The command prints `Backups are in <path>`, the backup folder for that run. Do not edit the files by hand. Run a dry run with `--reseal`. If it reports `intent_mismatch`, `--reseal --apply` rebuilds the journal from the current log and keeps any redaction already written. To return to the original text, a maintainer can copy the three backed-up files back over the day's files with mode `600`, then check the day again.

The logger never rewrites completed ready days. Still, avoid running `--apply` at exactly midnight, when the day rolls over and the logger may be publishing proofs for the day that just closed.

## Review files or results cannot be saved

Open **Weekly review** and check the selected start and end dates. A draft stays tied to that exact window. Save it or use **Clear draft** before changing dates. Each text field has a 4,000 character limit. A date that is active after a clock change cannot be saved until it is completed again.

If review files already exist, show that pack in Finder. A pack with a complete `INDEX.json` can be reopened without rereading source logs, so local redactions remain intact. If a folder is incomplete, preserve it for inspection. Archive that review folder explicitly before trying the same window again. The app does not overwrite or delete it for you.

Use **Show saved results** to find the private outcome file. New results store the exact window, day count and expected pack name. Older results with no known window keep that uncertainty.

## Config errors and restarts

Help and explicit log paths work even when the default config is broken:

```bash
.venv/bin/python scripts/check_analysis_day.py --help
.venv/bin/python scripts/check_analysis_day.py --log-dir /absolute/private/logs --day YYYY-MM-DD
.venv/bin/python scripts/activityloggerctl.py --log-dir /absolute/private/logs health
```

Correct the config before restarting. For a config-only change, use `./scripts/restart_logger.sh`. For source changes, use `./scripts/rebuild_and_restart.sh`. Both rely on the signed native app and the pinned identity. Do not run the logger directly with Python, rotate the identity, or ask for new privacy grants to bypass a failed build.

Before a restart, check for blocked storage, uncommitted records and pending transactions. The full maintainer guide is `docs/MACOS_TCC.md` in the repository.
