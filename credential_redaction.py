"""Capture-time credential redaction (regex detection only).

Ported from contextAggregator governance.py: the regex constants and the
detection in credential_matches. No config, allowlist or keyword handling.
"""

from __future__ import annotations

import base64
import json
import re

_PEM_BEGIN = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_PEM_END = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----")
_AWS_ACCESS_KEY = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_GITHUB_TOKEN = re.compile(
    r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82,255})\b"
)
_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
# Lookahead form, so overlapping candidates are all seen (as in governance.py).
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])(?=([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)"
    r"(?![A-Za-z0-9_-]))"
)
_LABELLED_SECRET = re.compile(
    r"(?i)\b(password|client[_ -]?secret|refresh[_ -]?token|api[_ -]?key|"
    r"access[_ -]?token|bearer)\b[\"']?\s*[:=]\s*[\"']?([^\s,;\"']+)"
)
_PLACEHOLDER_VALUES = frozenset(
    {
        "changeme",
        "dummy",
        "example",
        "placeholder",
        "redacted",
        "secret",
        "test",
        "your_password",
        "your-secret",
    }
)
# ponytail: shortest possible match is an 11-char compact JWT, so shorter text skips the regexes.
_MIN_LEN = 11


def _plausible_jwt_header(encoded: str) -> bool:
    try:
        padding = "=" * (-len(encoded) % 4)
        header = json.loads(base64.urlsafe_b64decode(encoded + padding))
    except ValueError:
        return False
    return (
        isinstance(header, dict)
        and isinstance(header.get("alg"), str)
        and bool(header["alg"].strip())
        and header["alg"].lower() != "none"
    )


def _accepted_labelled_secret(value: str) -> bool:
    normalized = value.strip().lower()
    return (
        len(normalized) >= 12
        and normalized not in _PLACEHOLDER_VALUES
        and "redacted" not in normalized
    )


def _pem_spans(text: str) -> list[tuple[int, int, str]]:
    # Linear: a BEGIN with no END after it ends the scan, since later BEGINs have no END either.
    spans: list[tuple[int, int, str]] = []
    pos = 0
    while (begin := _PEM_BEGIN.search(text, pos)) is not None:
        end = _PEM_END.search(text, begin.end())
        if end is None:
            break
        spans.append((begin.start(), end.end(), "pem_private_key"))
        pos = end.end()
    return spans


def _spans(text: str) -> list[tuple[int, int, str]]:
    spans = _pem_spans(text)
    for pattern, family in (
        (_AWS_ACCESS_KEY, "aws_access_key"),
        (_GITHUB_TOKEN, "github_token"),
        (_SLACK_TOKEN, "slack_token"),
    ):
        spans.extend(
            (match.start(), match.end(), family) for match in pattern.finditer(text)
        )
    for match in _JWT.finditer(text):
        if _plausible_jwt_header(match.group(1)):
            spans.append((match.start(1), match.end(3), "jwt"))
    for match in _LABELLED_SECRET.finditer(text):
        if _accepted_labelled_secret(match.group(2)):
            spans.append((match.start(2), match.end(2), "labelled_secret"))
    return spans


def redact(text: str) -> str:
    """Replace each detected credential span with ``[REDACTED:<family>]``.

    Never raises: on any internal error returns ``[REDACTED:error]`` (fail closed).
    """
    try:
        if len(text) < _MIN_LEN:
            return text
        merged: list[list] = []
        for start, end, family in sorted(_spans(text)):
            if merged and start < merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end, family])
        parts: list[str] = []
        cursor = 0
        for start, end, family in merged:
            parts.append(text[cursor:start])
            parts.append(f"[REDACTED:{family}]")
            cursor = end
        parts.append(text[cursor:])
        return "".join(parts)
    except Exception:  # noqa: BLE001 - fail closed on any error, never return raw text
        return "[REDACTED:error]"
