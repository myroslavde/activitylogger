# ActivityLogger agent and maintainer notes

## Canonical runtime

Production is `dist/ActivityLoggerNative.app` through `start_logger.sh` -> `open -W`. Never launch launchd directly into Python for pynput on modern macOS.

Full guide: [`docs/MACOS_TCC.md`](docs/MACOS_TCC.md)

## Canonical Python environment

Build and test with the exact `.python-version`, currently Python 3.11.9, in the project-local `.venv`. The build rejects every other interpreter and never falls back to a global PyInstaller.

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements.txt
.venv/bin/python -m pip check
.venv/bin/ruff check --select E4,E7,E9,F .
.venv/bin/python -m pip_audit --strict
.venv/bin/python -m pytest -q
```

Regenerate the macOS Apple silicon lock only through `./scripts/compile_requirements.sh`.

## Signing identity

Normal builds never create or rotate identities. Before the first canonical rebuild, provision the dedicated keychain while the deployed app remains available for leaf-continuity verification:

```bash
./scripts/setup_signing_identity.sh --import-p12 .codesign/identity.p12
```

Use native SecurityAgent prompts. The scripts reject password environment variables. Provisioning imports the private key as nonextractable, pins its certificate leaf SHA-1 fingerprint, and refuses a mismatch with the deployed app. `--rotate-identity` is an explicit TCC-breaking exception and warns that existing grants will not follow.

The 2026-08-21 signing import, rebuild, exact-process restart, and capture smoke test passed. The legacy PKCS#12 and any redundant login-keychain identity remain private with mode `600` pending an explicit operator archive or irreversible deletion decision. They are recovery assets, not runtime blockers.

## Operator config

```bash
mkdir -p ~/.config/activitylogger
cp config.example.toml ~/.config/activitylogger/config.toml
chmod 700 ~/.config/activitylogger
chmod 600 ~/.config/activitylogger/config.toml
```

Config is trusted local operator input and loads once. Unsafe ownership, links, permissions, malformed values, and out-of-range limits are rejected. Browser URL capture and remote ActivityWatch access are off by default.

- Config-only change: `./scripts/restart_logger.sh`
- Logger source change: `./scripts/rebuild_and_restart.sh`

Do not rebuild for a config-only edit.

## After code changes

Run the mandatory canonical build:

```bash
./scripts/rebuild_and_restart.sh
```

It builds a staged onedir app and signs every nested Mach-O plus the outer bundle with the pinned local identity and the sole Apple Events entitlement. Hardened Runtime is intentionally disabled for this self-signed no-Team-ID leaf. Verification requires exact nested and outer signatures, leaf and designated requirement, identifier, entitlement allowlist, symlink containment, and Mach-O load-path containment.

The build validates the installed Launch Agent, boots it out, quiesces exact-path processes, promotes atomically, bootstraps the agent, and requires a fresh stable exact-path process. Failed proof restores the unchanged prevalidated bundle and proves a fresh previous-app process. Never use name-only process termination, never leave an ad-hoc-signed app in `dist`, and do not ask for TCC re-grant after a successful rebuild with the unchanged pinned identity.

Smoke-check that typing updates `logs/daily_log_*.md` within about 30 seconds.

## Data handling

Logs are private plaintext retained indefinitely until the operator archives or deletes them. The Markdown compactor does not redact. Oversized sections pass through unchanged after a warning. Review and redact output before any external LLM use, prefer local processing, keep FileVault enabled, and do not add automatic deletion without an explicit product decision.

Starting on local day 2026-08-27, `logs/daily_log_YYYY-MM-DD.md` is the strict v2 analysis log and the legacy writer is disabled. The legacy compactor rejects analysis-format files. Historical conversion skips declared analysis-format canonical days. Preserve all older daily logs, shadow logs, intent journals, and rollout evidence.

<!-- graft:start -->
## Graft — repo context graph

This repo is indexed in `graft/`: small linked markdown nodes that explain each
system and carry exact file:line spans, kept in sync with the code through git.

For ANY task here — understanding how something works, finding where code lives,
or scoping a change — get context from the graph before grepping or opening
source files. Re-ask freely (it's cheap) and reuse literal identifiers you
already have (symbol, error string, file name) as the query. New to this repo?
Run `graft map` first — a token-budgeted orientation (dir clusters, hubs,
hotspots), no LLM, no key.

- Run `graft ask "<your question>" --source` → ranked nodes with the relevant
  code spans inlined (each hit's ≤8-line crux by default; `--full` for whole
  definitions when the crux isn't enough). Match the tool to the task shape:
  for understanding or editing, the top node IS the answer — cite its
  `covers:` file:line spans and edit straight from `--source`. For
  exhaustive tasks ("every occurrence / every caller of this pattern"), ranked
  results are top-N, not complete — run `graft grep "<literal>"` instead
  (exhaustive over indexed files, grouped by enclosing symbol), falling back
  to raw `grep -rn` only for unindexed files.
- `graft skeleton <file>` → every definition's signature + span, ~10× cheaper
  than reading the file; use it to skim an API surface.
- `graft callers <symbol>` gives precomputed, exact edges — who calls this.
  Add `--direction out` for what it calls, or `--depth N` to walk
  transitively for the full blast radius. For structural questions, skip
  ranking and use this directly.
- Or browse: `graft/INDEX.md` lists every node; follow the links.
- Monorepos and folders of multiple repos rank fairly across sub-projects —
  hits carry `[scope/]` labels naming which one they're from. Narrow with
  `graft ask "<task>" --in <scope>/` once you know where you're working.

If a returned span is truncated ("+N more lines"), open the file at that exact
range before finalizing. Only open source files when a node genuinely lacks a
needed detail, and then at the exact file:line the node points to — never
re-read whole files.

After big code changes, refresh the graph with `graft build` (deterministic,
no API key, $0).
<!-- graft:end -->
