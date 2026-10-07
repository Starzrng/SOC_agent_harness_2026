"""Harness-side guards: untrusted-evidence sanitising, call economy and report checks.

Everything the runtime returns is produced by the monitored environment and may be
attacker-controlled. The guards here never trust that content: they bound its size,
strip invisible characters, flag instruction-like text, decode obvious encodings for
the analyst, and keep the LLM from spending runtime calls on duplicates or ids that
never appeared in the evidence.
"""

import base64
import binascii
import contextlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

MAX_STRING_CHARS = 3_000
MAX_LIST_ITEMS = 300
MAX_FLAGS = 20
MAX_DECODED_CHARS = 1_500

# Invisible and bidi-control characters used to hide text from humans but not from models.
_HIDDEN_CHARS = re.compile("[­͏؜ᅟᅠ឴឵᠋-᠏​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ\U000e0000-\U000e007f]")

# Text that tries to address or steer the investigating model rather than describe activity.
_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (name, re.compile(pattern, re.IGNORECASE))
    for name, pattern in [
        (
            "override_instructions",
            r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|system|your)\b.{0,20}\b(instruction|prompt|rule|guideline|context)s?",
        ),
        (
            "role_reassignment",
            r"\byou are (now |no longer )?(an? |the )?(ai|assistant|agent|llm|language model|chatbot|analyst)\b",
        ),
        (
            "addressed_to_ai",
            r"\b(note|message|attention|instruction)s?\s+(to|for)\s+(the\s+)?(ai|llm|assistant|agent|model|analyst|investigator|soc)\b",
        ),
        (
            "fake_role_marker",
            r"(^|[\s\"'>\[])(system|assistant|developer)\s*[:>\]]\s|<\|?(im_start|im_end|system|endoftext)\|?>|</?(system|instructions?|prompt)>|\[/?INST\]",
        ),
        (
            "verdict_steering",
            r"\b(mark|classify|report|label|treat|close|submit|resolve)\b.{0,40}\b(benign|false[ -]?positive|legitimate|malicious|true[ -]?positive|not (a )?threat)\b",
        ),
        (
            "tool_steering",
            r"\b(finish_investigation|get_entity|get_relation|ir_artifacts|verdict\s*[:=])",
        ),
        (
            "authority_claim",
            r"\b(authori[sz]ed|approved|sanctioned|whitelisted|allow-?listed)\b.{0,30}\b(test|pentest|penetration|red[ -]?team|exercise|activity|by (it|soc|security))\b",
        ),
        (
            "suppress_response",
            r"\b(do not|don't|never|no need to)\b.{0,20}\b(isolate|escalate|report|flag|alert|investigate|block|rotate)\b",
        ),
        (
            "already_handled",
            r"\b(already|has been|was)\b.{0,15}\b(remediated|resolved|investigated|triaged|closed|cleared)\b",
        ),
        (
            "ru_override",
            r"(игнорир\w*|забудь\w*|не обращай\w*).{0,40}(инструкц\w*|правил\w*|указани\w*|промпт\w*)",
        ),
        (
            "ru_addressed_to_ai",
            r"(ии|ai|llm|нейросет\w*|ассистент\w*|аналитик\w*)\s*[:,]?\s*(отметь|пометь|считай|укажи|закрой|заверши)",
        ),
        (
            "ru_verdict_steering",
            r"(ложн\w* срабатыв\w*|легитимн\w*|безопасн\w*|вредонос\w*)\s*[-—:]?\s*(вердикт|отметь|пометь|закрой)",
        ),
    ]
]

_PS_ENCODED = re.compile(
    r"-(?:e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})",
    re.IGNORECASE,
)
_BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/=])")
_HEX_ID_LIKE = re.compile(r"^[0-9a-fA-F]+$")


@dataclass
class SanitizeReport:
    """Findings collected while sanitising one untrusted payload."""

    flags: list[dict[str, str]] = field(default_factory=list)
    decoded: list[dict[str, str]] = field(default_factory=list)
    hidden_chars_removed: int = 0
    truncated_strings: int = 0
    truncated_lists: int = 0

    def as_dict(self) -> dict[str, Any]:
        """Return a compact JSON-ready summary, omitting empty sections."""
        summary: dict[str, Any] = {}
        if self.flags:
            summary["security_flags"] = self.flags[:MAX_FLAGS]
        if self.decoded:
            summary["decoded_for_analyst"] = self.decoded[:MAX_FLAGS]
        if self.hidden_chars_removed:
            summary["hidden_unicode_chars_removed"] = self.hidden_chars_removed
        if self.truncated_strings or self.truncated_lists:
            summary["truncated"] = {
                "strings": self.truncated_strings,
                "lists": self.truncated_lists,
            }
        return summary


def sanitize_untrusted(value: Any) -> tuple[Any, SanitizeReport]:
    """Return a bounded, annotated copy of untrusted evidence.

    Args:
        value: JSON-like payload from the alert or a tool result.

    Returns:
        The sanitised payload and the findings that describe what was changed or flagged.
    """
    report = SanitizeReport()
    return _sanitize(value, "$", report), report


def _sanitize(value: Any, path: str, report: SanitizeReport) -> Any:
    if isinstance(value, str):
        return _sanitize_string(value, path, report)
    if isinstance(value, dict):
        return {
            _sanitize_string(str(key), f"{path}.<key>", report): _sanitize(
                nested, f"{path}.{key}", report
            )
            for key, nested in value.items()
        }
    if isinstance(value, list):
        items = [
            _sanitize(item, f"{path}[{index}]", report)
            for index, item in enumerate(value[:MAX_LIST_ITEMS])
        ]
        if len(value) > MAX_LIST_ITEMS:
            report.truncated_lists += 1
            items.append(f"[harness: {len(value) - MAX_LIST_ITEMS} more items omitted]")
        return items
    return value


def _sanitize_string(text: str, path: str, report: SanitizeReport) -> str:
    cleaned, removed = _HIDDEN_CHARS.subn("", text)
    if removed:
        report.hidden_chars_removed += removed
        _add_flag(report, "hidden_unicode", path, cleaned)
    cleaned = unicodedata.normalize("NFKC", cleaned)

    for name, pattern in _INJECTION_PATTERNS:
        match = pattern.search(cleaned)
        if match:
            _add_flag(report, name, path, _excerpt(cleaned, match.start(), match.end()))

    for decoded in _decode_embedded(cleaned):
        report.decoded.append({"path": path, "text": decoded})
        for name, pattern in _INJECTION_PATTERNS:
            match = pattern.search(decoded)
            if match:
                _add_flag(
                    report,
                    f"{name}_in_decoded",
                    path,
                    _excerpt(decoded, match.start(), match.end()),
                )

    if len(cleaned) > MAX_STRING_CHARS:
        report.truncated_strings += 1
        omitted = len(cleaned) - MAX_STRING_CHARS
        cleaned = (
            cleaned[: MAX_STRING_CHARS - 300]
            + f" [harness: {omitted} chars omitted] "
            + cleaned[-300:]
        )
    return cleaned


def _add_flag(report: SanitizeReport, kind: str, path: str, excerpt: str) -> None:
    if len(report.flags) >= MAX_FLAGS:
        return
    report.flags.append({"kind": kind, "path": path, "excerpt": excerpt[:240]})


def _excerpt(text: str, start: int, end: int) -> str:
    return text[max(0, start - 60) : min(len(text), end + 60)]


def _decode_embedded(text: str) -> list[str]:
    """Decode PowerShell -EncodedCommand payloads and long base64 blobs for the analyst."""
    results: list[str] = []
    seen: set[str] = set()
    candidates = [match.group(1) for match in _PS_ENCODED.finditer(text)]
    candidates += [match.group(1) for match in _BASE64_BLOB.finditer(text)]
    for blob in candidates:
        if blob in seen or _HEX_ID_LIKE.match(blob):
            continue
        seen.add(blob)
        decoded = _try_base64(blob)
        if decoded:
            results.append(_HIDDEN_CHARS.sub("", decoded)[:MAX_DECODED_CHARS])
    return results


def _try_base64(blob: str) -> str | None:
    padded = blob + "=" * (-len(blob) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    for encoding in ("utf-16-le", "utf-8"):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
        if text and printable / len(text) > 0.95:
            return text
    return None


def collect_strings(value: Any, sink: set[str]) -> None:
    """Add every string value and key found in a JSON-like payload to `sink`."""
    if isinstance(value, str):
        sink.add(value)
        # Ids sometimes arrive embedded in JSON-encoded strings.
        if value[:1] in "[{":
            with contextlib.suppress(json.JSONDecodeError, RecursionError):
                collect_strings(json.loads(value), sink)
    elif isinstance(value, dict):
        for key, nested in value.items():
            sink.add(str(key))
            collect_strings(nested, sink)
    elif isinstance(value, list):
        for nested in value:
            collect_strings(nested, sink)
    elif isinstance(value, int | float) and not isinstance(value, bool):
        sink.add(str(value))


def id_arguments(arguments: Any, prefix: str = "") -> list[tuple[str, str]]:
    """Return (argument path, value) pairs for arguments that reference graph ids."""
    found: list[tuple[str, str]] = []
    if isinstance(arguments, dict):
        for key, value in arguments.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            if isinstance(value, str) and (key == "id" or key.endswith("_id")):
                found.append((path, value))
            else:
                found.extend(id_arguments(value, path))
    elif isinstance(arguments, list):
        for index, value in enumerate(arguments):
            found.extend(id_arguments(value, f"{prefix}[{index}]"))
    return found


def canonical_call_key(tool_name: str, arguments: dict[str, Any]) -> str:
    """Build a stable key used to detect repeated identical calls."""
    return f"{tool_name}:{json.dumps(arguments, sort_keys=True, ensure_ascii=False)}"


def dedupe_artifacts(artifacts: list[Any]) -> list[Any]:
    """Drop exact duplicate artifact objects while keeping their order."""
    seen: set[str] = set()
    unique: list[Any] = []
    for artifact in artifacts:
        key = json.dumps(artifact, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            unique.append(artifact)
    return unique
