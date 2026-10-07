"""Local checks of a finish_investigation report against what the agent was shown.

Deterministic and conservative. Errors are certain defects: an id that never appeared, an
entity cited as a relation (or the reverse), a property name the cited entity does not
have, one entity listed with two kinds. Warnings are likely defects: an object that was
only referenced and never opened, an empty or truncated field, a kind that does not fit the
object's type, a benign conclusion drawn while a search still had unread pages or
before the alert window was read.

Nothing here judges the verdict or whether the report is complete: those calls stay with
the investigator. `errors == []` only means the local checks passed.

`filter_report` is separate from the checks: the harness applies it to the final report
without a review round, dropping item types that cost more than they earn (FILTERED_TYPES).
"""

from dataclasses import dataclass, field
from typing import Any

from bluesec1_agent.evidence import AD_OBJECT, ENTITY, RELATION, EvidenceIndex

PROCESS_TYPES = frozenset({"windows_process", "linux_process"})
FILE_TYPES = frozenset({"windows_file", "linux_file", "archive_file"})
USER_TYPES = frozenset({"windows_user", "linux_user"})
IDENTITY_TYPES = USER_TYPES | {"linux_group", "ad_object"}

# Kinds that name one kind of object: another shown entity type draws a warning.
KIND_TYPES: dict[str, frozenset[str]] = {
    "host_to_isolate": frozenset({"host"}),
    "identity_to_rotate": IDENTITY_TYPES,
    "identity_observed": IDENTITY_TYPES,
    "process_observed": PROCESS_TYPES,
    "registry_observed": frozenset({"registry_key"}),
    "ticket_observed": frozenset({"kerberos_ticket"}),
    "lnk_observed": frozenset({"lnk_shortcut"}),
    "mount_observed": frozenset({"mounted_volume", "smb_share"}),
}
# Kinds that never fit these entity types.
KIND_EXCLUDED_TYPES: dict[str, frozenset[str]] = {
    "file_to_delete": PROCESS_TYPES | USER_TYPES | {"host", "network_connection"},
    "file_observed": PROCESS_TYPES | USER_TYPES | {"host", "network_connection"},
    "network_block": PROCESS_TYPES | FILE_TYPES | USER_TYPES | {"registry_key"},
    "persistence_to_remove": PROCESS_TYPES | USER_TYPES | {"host", "network_connection"},
    "mailbox_action": PROCESS_TYPES | FILE_TYPES | {"host", "network_connection", "registry_key"},
}
# The catalog calls artifact_observed an escape hatch; these types have a specific kind.
SPECIFIC_FORENSIC_KIND = {
    "windows_process": "process_observed",
    "linux_process": "process_observed",
    "windows_file": "file_observed",
    "linux_file": "file_observed",
    "archive_file": "file_observed",
    "registry_key": "registry_observed",
    "kerberos_ticket": "ticket_observed",
    "lnk_shortcut": "lnk_observed",
    "mounted_volume": "mount_observed",
    "smb_share": "mount_observed",
    "windows_user": "identity_observed",
    "linux_user": "identity_observed",
}
FORENSIC_KINDS = frozenset(
    {
        "process_observed",
        "file_observed",
        "registry_observed",
        "identity_observed",
        "ticket_observed",
        "mount_observed",
        "lnk_observed",
        "artifact_observed",
    }
)
# A benign report longer than this usually lists everything touched instead of the chain.
LONG_BENIGN_REPORT = 15
# Report filter: object types that almost never count as key objects, while every cited item
# costs points. Response actions name the address, file, process or account instead of the
# connection record, script text or cmdlet call; relations are dropped for the same reason.
FILTERED_TYPES = frozenset(
    {"network_connection", "powershell_script", "powershell_cmdlet_invocation"}
)
FILTER_FLOOR = 3
_MAX_FIELD_NAMES_SHOWN = 30
_MAX_SEARCHES_SHOWN = 3


@dataclass
class Finding:
    """One problem found in the report; `item` is the 1-based position in its list."""

    code: str
    message: str
    item: int | None = None

    def render(self) -> str:
        """Short text for the agent."""
        return f"item {self.item}: {self.message}" if self.item is not None else self.message


@dataclass
class Review:
    """Outcome of the local report checks."""

    errors: list[Finding] = field(default_factory=list)
    warnings: list[Finding] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        """Whether nothing was found."""
        return not self.errors and not self.warnings


def cited_ids(body: dict[str, Any]) -> set[str]:
    """Ids cited by a report body."""
    ids: set[str] = set()
    for section in ("ir_artifacts", "legitimacy_evidence"):
        for item in body.get(section) or []:
            if isinstance(item, dict):
                ids.update(
                    item[key]
                    for key in ("entity_id", "relation_id")
                    if isinstance(item.get(key), str)
                )
    return ids


def review_report(body: dict[str, Any], index: EvidenceIndex, known: set[str]) -> Review:
    """Check a submission body (verdict, ir_artifacts / legitimacy_evidence, reasoning).

    Args:
        body: The report object (the catalog's `submission`, or a legacy top-level report).
        index: What the agent was shown during the task.
        known: Every string that appeared in the alert or a tool result.
    """
    review = Review()
    verdict = body.get("verdict")
    if verdict == "malicious":
        _review_malicious(body.get("ir_artifacts") or [], index, known, review)
    elif verdict == "benign":
        _review_benign(body.get("legitimacy_evidence") or [], index, known, review)
        unread = index.unread_searches()
        if unread:
            shown = "; ".join(_describe_search(entry) for entry in unread[:_MAX_SEARCHES_SHOWN])
            more = len(unread) - _MAX_SEARCHES_SHOWN
            review.warnings.append(
                Finding(
                    "unread_pages",
                    f"searches with unread pages: {shown}"
                    + (f" (+{more} more)" if more > 0 else "")
                    + ". A benign conclusion cannot rest on 'nothing else happened' there: read "
                    "on, run a narrower search that tests the claim, or drop that claim.",
                )
            )
        gaps = index.window_gaps()
        if gaps and index.trigger_span is not None:
            start, end = (stamp.isoformat() for stamp in index.trigger_span)
            shown = "; ".join(
                f"{gap['query']!r} pages read reach {gap['read_until']}, pages "
                f"{', '.join(str(page) for page in gap['unread_pages'])} unread"
                for gap in gaps[:_MAX_SEARCHES_SHOWN]
            )
            review.warnings.append(
                Finding(
                    "window_not_reached",
                    f"the alert window {start} to {end} was never read: {shown}. Search the "
                    "account or logon id with a time_window over the alert window before a "
                    "benign verdict; an unread alert window keeps the case open.",
                )
            )
    return review


def _check_id(
    object_id: Any,
    expected: str,
    item: int,
    index: EvidenceIndex,
    known: set[str],
    review: Review,
) -> bool:
    """Check one cited id; return True when it was shown in full (further checks apply)."""
    if not isinstance(object_id, str) or not object_id:
        return False
    if object_id not in known and object_id not in index.objects:
        review.errors.append(
            Finding("unknown_id", f"{object_id} never appeared in the alert or any result.", item)
        )
        return False
    actual = index.category(object_id)
    if actual == AD_OBJECT:
        review.warnings.append(Finding("ad_object", _ad_message(object_id, index), item))
        return False
    if actual is not None and actual != expected:
        review.errors.append(
            Finding(
                "wrong_anchor",
                f"{object_id} is a{'n' if actual == ENTITY else ''} {actual} id, but it is "
                f"cited as a{'n' if expected == ENTITY else ''} {expected}.",
                item,
            )
        )
        return False
    if object_id in index.objects:
        return True
    refs = index.references.get(object_id)
    if refs:
        review.warnings.append(
            Finding(
                "not_opened",
                f"{object_id} was never opened (seen only as {refs[0].describe()}): its type and "
                "properties are unverified. Open it, or drop it if the chain does not need it.",
                item,
            )
        )
    else:
        review.warnings.append(
            Finding(
                "text_only",
                f"{object_id} appears only inside evidence text, never as a graph object: it "
                "is not verified evidence.",
                item,
            )
        )
    return False


def _ad_message(object_id: str, index: EvidenceIndex) -> str:
    """Why an AD id in the report is uncertain, and what to cite instead."""
    if object_id in index.ad_objects:
        where = "an Active Directory object you read with get_ad_object_info"
    else:
        ref = index.references[object_id][0]
        where = f"an Active Directory object seen as {ref.describe()}"
    carriers = sorted(index.ad_links.get(object_id, set()))
    instead = (
        f"cite the graph entity that carries it ({', '.join(carriers[:3])}) with its fields"
        if carriers
        else "cite the graph entity that carries this ad_object_id"
    )
    return (
        f"{object_id} is {where}, not a graph entity; the catalog does not say AD ids are "
        f"accepted in this list. Its facts stay valid evidence: {instead} and keep the AD "
        "facts in reasoning, or keep the item knowingly. No need to read it again."
    )


def _describe_search(entry: dict[str, Any]) -> str:
    """Compact form of a search with unread pages, e.g. "'alice' scope=windows_process p3"."""
    parts = [repr(entry.get("query"))]
    scope = entry.get("scope")
    if isinstance(scope, dict) and scope.get("type"):
        parts.append(f"scope={scope['type']}")
    window = entry.get("time_window")
    if isinstance(window, dict):
        parts.append(f"time {window.get('from')}..{window.get('to')}")
    if entry.get("sort_order"):
        parts.append(f"sort={entry['sort_order']}")
    parts.append("unread page(s) " + ", ".join(str(page) for page in entry["unread_pages"]))
    return " ".join(parts)


def _review_malicious(
    items: list[Any], index: EvidenceIndex, known: set[str], review: Review
) -> None:
    if not items:
        review.warnings.append(Finding("empty", "The malicious report lists no ir_artifacts."))
        return
    kinds: dict[str, str] = {}
    for position, item in enumerate(items, 1):
        if not isinstance(item, dict):
            continue
        entity_id, kind = item.get("entity_id"), item.get("kind")
        if isinstance(entity_id, str) and isinstance(kind, str):
            previous = kinds.setdefault(entity_id, kind)
            if previous != kind:
                review.errors.append(
                    Finding(
                        "conflicting_kinds",
                        f"{entity_id} is listed as {previous} and as {kind}: keep one kind.",
                        position,
                    )
                )
                continue
        if not _check_id(entity_id, ENTITY, position, index, known, review):
            continue
        seen = index.objects[entity_id]
        problem = _kind_problem(str(kind), seen.type)
        if problem:
            review.warnings.append(Finding("kind_type", f"{entity_id}: {problem}", position))


def _kind_problem(kind: str, entity_type: str) -> str | None:
    allowed = KIND_TYPES.get(kind)
    if allowed is not None and entity_type not in allowed:
        return f"{kind} is for {' / '.join(sorted(allowed))}, but this is a {entity_type}."
    if entity_type in KIND_EXCLUDED_TYPES.get(kind, frozenset()):
        return f"{kind} does not fit a {entity_type}."
    if entity_type == "network_connection" and kind in FORENSIC_KINDS:
        return (
            "the catalog has no forensic kind for network connections: report a C2 or "
            "exfiltration connection as network_block, otherwise leave it out."
        )
    specific = SPECIFIC_FORENSIC_KIND.get(entity_type)
    if kind == "artifact_observed" and specific:
        return (
            f"artifact_observed is the escape hatch; a {entity_type} has its own kind ({specific})."
        )
    return None


def _review_benign(items: list[Any], index: EvidenceIndex, known: set[str], review: Review) -> None:
    if not items:
        review.warnings.append(Finding("empty", "The benign report cites no legitimacy_evidence."))
        return
    if len(items) > LONG_BENIGN_REPORT:
        review.warnings.append(
            Finding(
                "long_benign",
                f"{len(items)} evidence items: long benign reports tend to list everything "
                "touched. Keep the objects that prove the legitimate chain (trigger, its launcher "
                "or mechanism, account, counterpart), one representative per repeated pattern.",
            )
        )
    for position, item in enumerate(items, 1):
        if not isinstance(item, dict):
            continue
        is_relation = item.get("anchor") == "relation"
        object_id = item.get("relation_id") if is_relation else item.get("entity_id")
        expected = RELATION if is_relation else ENTITY
        if not _check_id(object_id, expected, position, index, known, review):
            continue
        seen = index.objects[object_id]
        fields = [name for name in item.get("property_fields") or [] if isinstance(name, str)]
        if is_relation:
            available = seen.relation_fields()
            unverified = [
                name
                for name in fields
                if name not in available and name.split(".")[-1] not in available
            ]
            if unverified:
                review.warnings.append(
                    Finding(
                        "relation_field",
                        f"{object_id}: {unverified} not seen on this relation "
                        f"(seen: {_names(available)}).",
                        position,
                    )
                )
            continue
        unknown = [name for name in fields if name not in seen.fields | seen.empty_fields]
        if unknown:
            review.errors.append(
                Finding(
                    "unknown_field",
                    f"{object_id} ({seen.type}) has no properties {unknown}; its non-empty "
                    f"properties are {_names(seen.fields)}.",
                    position,
                )
            )
        empty = [name for name in fields if name in seen.empty_fields]
        if empty:
            review.warnings.append(
                Finding("empty_field", f"{object_id}: {empty} empty on this object.", position)
            )
        truncated = [name for name in fields if name in seen.truncated_fields]
        if truncated:
            review.warnings.append(
                Finding(
                    "truncated_field",
                    f"{object_id}: {truncated} were shortened in your view; cite them only if the "
                    "part you read proves the point.",
                    position,
                )
            )


def repair_report(
    body: dict[str, Any], review: Review, index: EvidenceIndex
) -> tuple[dict[str, Any], list[str]]:
    """Apply the unambiguous fix for each remaining error; return the body and what changed.

    Unknown ids and malicious items that cite a relation are dropped; a benign anchor on
    the wrong category is switched when the id's category is known; unknown property names
    are dropped (and the item too when an entity has none left); a second kind for the same
    entity is dropped.
    """
    by_item: dict[int, list[Finding]] = {}
    for finding in review.errors:
        if finding.item is not None:
            by_item.setdefault(finding.item, []).append(finding)
    section = "ir_artifacts" if body.get("verdict") == "malicious" else "legitimacy_evidence"
    items = body.get(section)
    if not isinstance(items, list) or not by_item:
        return body, []

    kept: list[Any] = []
    notes: list[str] = []
    for position, item in enumerate(items, 1):
        findings = by_item.get(position)
        if not findings or not isinstance(item, dict):
            kept.append(item)
            continue
        codes = {finding.code for finding in findings}
        if codes & {"unknown_id", "conflicting_kinds"} or (
            "wrong_anchor" in codes and section == "ir_artifacts"
        ):
            notes.append(f"dropped item {position}: {findings[0].message}")
            continue
        fixed = dict(item)
        if "wrong_anchor" in codes:
            fixed = _switch_anchor(fixed, index)
            if fixed is None:
                notes.append(f"dropped item {position}: {findings[0].message}")
                continue
            notes.append(f"item {position}: anchor switched to {fixed['anchor']}")
        if "unknown_field" in codes and fixed.get("anchor") == "entity":
            seen = index.objects.get(str(fixed.get("entity_id")))
            names = seen.fields | seen.empty_fields if seen else set()
            valid = [name for name in fixed.get("property_fields") or [] if name in names]
            if not valid:
                notes.append(f"dropped item {position}: no valid property_fields left")
                continue
            fixed["property_fields"] = valid
            notes.append(f"item {position}: unknown property_fields dropped")
        kept.append(fixed)
    return {**body, section: kept}, notes


def filter_report(
    body: dict[str, Any], index: EvidenceIndex
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Drop cited relations and objects of FILTERED_TYPES before submission.

    A malicious report also loses processes that ran on the trigger's host outside the
    trigger's logon session: system-session targets and hosts of the attack (the process
    whose memory was read, a WMI or service host) are almost never key objects; a response
    acts on the attacker's own processes. Processes on other hosts stay.

    Alert trigger objects stay. At least FILTER_FLOOR items remain: when the filter would go
    below it, the candidates listed last are dropped first and the rest stay. Returns the
    body and one record (section, position, id, category, type) per dropped item.
    """
    triggers = [seen for seen in index.objects.values() if seen.shown_by == "alert"]
    trigger_sessions = {seen.logon_id for seen in triggers if seen.logon_id}
    trigger_hosts = {seen.host_id for seen in triggers if seen.host_id}
    trigger_hosts |= {seen.object_id for seen in triggers if seen.type == "host"}
    candidates: list[tuple[str, int, dict[str, Any]]] = []
    total = 0
    for section in ("ir_artifacts", "legitimacy_evidence"):
        items = body.get(section)
        if not isinstance(items, list):
            continue
        for position, item in enumerate(items, 1):
            total += 1
            if not isinstance(item, dict):
                continue
            object_id = str(item.get("entity_id") or item.get("relation_id") or "")
            seen = index.objects.get(object_id)
            if seen is not None and seen.shown_by == "alert":
                continue
            category = index.category(object_id)
            object_type = seen.type if seen is not None else None
            other_session = (
                section == "ir_artifacts"
                and seen is not None
                and object_type in PROCESS_TYPES
                and bool(trigger_sessions)
                and seen.logon_id is not None
                and seen.logon_id not in trigger_sessions
                and seen.host_id in trigger_hosts
            )
            if category == RELATION or object_type in FILTERED_TYPES or other_session:
                record = {
                    "section": section,
                    "position": position,
                    "id": object_id,
                    "category": category,
                    "type": object_type,
                }
                if other_session:
                    record["reason"] = "outside the trigger's logon session"
                candidates.append((section, position, record))
    allowed = max(0, total - FILTER_FLOOR)
    dropped = candidates[len(candidates) - allowed :] if allowed < len(candidates) else candidates
    if not dropped:
        return body, []
    gone = {(section, position) for section, position, _ in dropped}
    filtered = dict(body)
    for section in ("ir_artifacts", "legitimacy_evidence"):
        items = body.get(section)
        if isinstance(items, list):
            filtered[section] = [
                item for position, item in enumerate(items, 1) if (section, position) not in gone
            ]
    return filtered, [record for _, _, record in dropped]


def _switch_anchor(item: dict[str, Any], index: EvidenceIndex) -> dict[str, Any] | None:
    object_id = item.get("entity_id") or item.get("relation_id")
    seen = index.objects.get(str(object_id))
    fields = [name for name in item.get("property_fields") or [] if isinstance(name, str)]
    if index.category(str(object_id)) == RELATION:
        available = seen.relation_fields() if seen else set()
        switched: dict[str, Any] = {"anchor": "relation", "relation_id": object_id}
        valid = [name for name in fields if name in available]
        if valid:
            switched["property_fields"] = valid
        return switched
    if seen is None:
        return None
    valid = [name for name in fields if name in seen.fields | seen.empty_fields]
    if not valid:
        return None
    return {"anchor": "entity", "entity_id": object_id, "property_fields": valid}


def _names(names: set[str]) -> str:
    shown = sorted(names)[:_MAX_FIELD_NAMES_SHOWN]
    more = len(names) - len(shown)
    return ", ".join(shown) + (f" (+{more} more)" if more > 0 else "") if shown else "none"
