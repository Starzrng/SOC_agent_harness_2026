"""Per-task index of the graph objects the agent has actually been shown.

The runtime returns graph objects in fixed places only: the alert's `trigger_entities` and
`trigger_relations`, the top-level result of get_entity / get_relation, and the `results`
rows of search. Those positions are indexed and nothing else. Text inside properties is
evidence, not structure: an object described inside a property value (JSON-looking strings
included) never becomes an entry, so planted text cannot fake an inspected object.

An id is in one of three states: shown in full (type and properties visible), referenced
(seen as a relation endpoint, a relation id or a host id, but never opened), or merely
mentioned inside evidence text (the harness's known-values set, not this index).
"""

import ipaddress
import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from bluesec1_agent.guards import MAX_LIST_ITEMS, MAX_STRING_CHARS

ENTITY = "entity"
RELATION = "relation"
# Active Directory objects come from get_ad_object_info: a directory, not the event graph.
AD_OBJECT = "ad_object"
# Relation property namespaces besides `properties` (logon and handle-access details).
RELATION_NAMESPACES = ("logon_properties", "access_properties")
# Tools whose results are indexed and whose repeats are pure reads.
READ_TOOLS = frozenset({"search", "get_entity", "get_relation", "get_ad_object_info"})
CONNECTION_TYPE = "network_connection"
# Relations from a process to a connection it made or accepted.
CONNECTION_LINKS = frozenset({"connected_to", "accepted_connection_from"})
_INSIDE_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
)


def inside_address(value: Any) -> bool | None:
    """Whether an IP address is in a private or local range; None when it is not an address.

    Documentation ranges count as outside: scenarios use them for external hosts.
    """
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return any(address in network for network in _INSIDE_NETWORKS)
_MAX_REFERENCES_PER_ID = 20


def is_empty(value: Any) -> bool:
    """Whether a property value carries nothing (None, empty string, list or object)."""
    return value is None or value == "" or value == [] or value == {}


def drop_blank(value: Any) -> Any:
    """Copy of a JSON-like value without null, empty-list and empty-object fields.

    Graph objects carry many null properties; dropping them shortens the agent's context
    without hiding anything (an absent field reads as unknown, as null did). Empty strings,
    zeros and false are kept: they are values.
    """
    if isinstance(value, dict):
        kept = {key: drop_blank(nested) for key, nested in value.items()}
        return {key: nested for key, nested in kept.items() if nested not in (None, [], {})}
    if isinstance(value, list):
        return [drop_blank(nested) for nested in value]
    return value


def compact_result(tool: str, result: Any) -> Any:
    """The agent's view of a read result: graph objects without blank fields."""
    if tool == "search" and isinstance(result, dict):
        view = {key: value for key, value in result.items() if value is not None}
        if isinstance(result.get("results"), list):
            view["results"] = [drop_blank(row) for row in result["results"]]
        return view
    if tool in READ_TOOLS and isinstance(result, dict):
        return drop_blank(result)
    return result


def alert_body(alert: dict[str, Any]) -> dict[str, Any]:
    """The part of an observation that holds the trigger lists (live: `alert_text`)."""
    if isinstance(alert.get("trigger_entities"), list):
        return alert
    for value in alert.values():
        if isinstance(value, dict) and isinstance(value.get("trigger_entities"), list):
            return value
    return {}


# Anchor values copied into the harness block must look like plain identifiers: anything
# else (spaces, quotes, markup, long text) could carry planted instructions and is dropped.
_BARE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._$-]{0,63}")
_LOGON_ID = re.compile(r"(0x)?[0-9A-Fa-f]{1,16}")
_HOSTNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,252}")
_ISO_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})")
_SEARCH_MIN_CHARS = 5


def trigger_anchors(alert: dict[str, Any]) -> dict[str, Any]:
    """Search anchors taken from the trigger entities: user names, logon ids, hosts, time span.

    Only values that match strict identifier formats are kept, so the block adds no free
    text. A bare user name is given apart from DOMAIN\\name because a substring search on
    the full form matches process rows but not the account object.
    """
    users: list[dict[str, str]] = []
    logon_ids: list[str] = []
    hosts: list[str] = []
    times: list[str] = []
    for entity in alert_body(alert).get("trigger_entities") or []:
        if not isinstance(entity, dict):
            continue
        props = entity.get("properties") if isinstance(entity.get("properties"), dict) else {}
        user = props.get("user")
        if isinstance(user, str):
            name = user.split("\\")[-1]
            if _BARE_NAME.fullmatch(name) and name not in (u["name"] for u in users):
                entry = {"name": name}
                if len(name) < _SEARCH_MIN_CHARS and _BARE_NAME.fullmatch(user.replace("\\", "")):
                    entry["search_as"] = user  # too short for a substring search alone
                users.append(entry)
        logon = props.get("logon_id")
        if (
            isinstance(logon, str)
            and len(logon) >= _SEARCH_MIN_CHARS
            and _LOGON_ID.fullmatch(logon)
            and logon not in logon_ids
        ):
            logon_ids.append(logon)
        hostname = props.get("hostname")
        if isinstance(hostname, str) and _HOSTNAME.fullmatch(hostname) and hostname not in hosts:
            hosts.append(hostname)
        if entity.get("type") == "host":
            continue  # a host's timestamps span its whole history, not the trigger
        stamps = [*(entity.get("timestamps") or []), props.get("start_time"), props.get("end_time")]
        times.extend(t for t in stamps if isinstance(t, str) and _ISO_TIME.fullmatch(t))
    anchors: dict[str, Any] = {}
    if users:
        anchors["users"] = users
    if logon_ids:
        anchors["logon_ids"] = logon_ids
    if hosts:
        anchors["hosts"] = hosts
    if times:
        ordered = sorted(times, key=lambda t: datetime.fromisoformat(t.replace("Z", "+00:00")))
        anchors["trigger_time_span"] = {"from": ordered[0], "to": ordered[-1]}
    return anchors


_ROW_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?")
_DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
# Timestamps read per row at most (a row's `timestamps` list can be long).
_MAX_ROW_TIMES = 50
# Built-in identities whose "session" is the whole host (SYSTEM, LOCAL / NETWORK SERVICE and
# their logon ids): a session search on them is not the trigger's session.
_HOST_WIDE_IDENTITIES = frozenset({"system", "localsystem", "0x3e7", "0x3e4", "0x3e5"})


# Identities that exist on every Windows host (SYSTEM, the service identities, anonymous logon,
# the window-manager and font-driver accounts): nobody's role or restriction, so never the
# account that proves an action legitimate.
_BUILTIN_SID = re.compile(r"S-1-5-(18|19|20|7)|S-1-5-(90|96)-[0-9-]+", re.IGNORECASE)


def builtin_identity(properties: dict[str, Any]) -> bool:
    """Whether an account object's properties describe a built-in identity."""
    sid = properties.get("sid")
    if isinstance(sid, str) and _BUILTIN_SID.fullmatch(sid.strip()):
        return True
    if str(properties.get("account_type") or "").strip().lower() == "builtin":
        return True
    return str(properties.get("domain") or "").strip().lower() == "nt authority"


def _parse_time(value: Any, end_of_day: bool = False) -> datetime | None:
    """An ISO 8601 time (UTC when no offset is given) or a UTC calendar day, else None."""
    if not isinstance(value, str):
        return None
    try:
        if _ROW_TIME.fullmatch(value):
            stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        elif _DAY.fullmatch(value):
            stamp = datetime.fromisoformat(value + ("T23:59:59" if end_of_day else "T00:00:00"))
        else:
            return None
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=UTC)


def _row_times(row: Any) -> list[datetime]:
    """Timestamps of one search row; hosts are skipped (theirs span the whole history)."""
    if not isinstance(row, dict) or row.get("type") == "host":
        return []
    props = row.get("properties") if isinstance(row.get("properties"), dict) else {}
    stamps = row.get("timestamps") if isinstance(row.get("timestamps"), list) else []
    values = [
        *stamps[:_MAX_ROW_TIMES],
        row.get("timestamp"),
        props.get("start_time"),
        props.get("end_time"),
        props.get("timestamp"),
    ]
    return [stamp for stamp in map(_parse_time, values) if stamp is not None]


def _window_overlaps(window: Any, start: datetime, end: datetime) -> bool:
    """Whether a search's `time_window` overlaps the span [start, end]."""
    if not isinstance(window, dict):
        return False
    low, high = _parse_time(window.get("from")), _parse_time(window.get("to"), end_of_day=True)
    return low is not None and high is not None and low <= end and high >= start


def compact_alert(alert: dict[str, Any]) -> dict[str, Any]:
    """The agent's view of the alert: trigger objects without blank fields."""
    body = alert_body(alert)
    if not body:
        return alert
    compact_body = {
        key: [drop_blank(item) for item in value]
        if key in ("trigger_entities", "trigger_relations") and isinstance(value, list)
        else value
        for key, value in body.items()
    }
    if body is alert:
        return compact_body
    return {key: compact_body if value is body else value for key, value in alert.items()}


def _truncated(value: Any) -> bool:
    """Whether the sanitiser shortens this value in the agent's view."""
    if isinstance(value, str):
        return len(value) > MAX_STRING_CHARS
    return isinstance(value, list) and len(value) > MAX_LIST_ITEMS


@dataclass
class SeenObject:
    """A graph object the agent has been shown in full."""

    object_id: str
    category: str
    type: str
    shown_by: str
    fields: set[str] = field(default_factory=set)
    empty_fields: set[str] = field(default_factory=set)
    truncated_fields: set[str] = field(default_factory=set)
    namespace_fields: dict[str, set[str]] = field(default_factory=dict)
    source_id: str | None = None
    target_id: str | None = None
    # Where and in which logon session the object lives (processes): the report filter
    # compares them with the alert's trigger.
    host_id: str | None = None
    logon_id: str | None = None
    # An account object of a built-in identity (SYSTEM, anonymous logon, ...).
    builtin: bool = False
    # A network connection: its direction and the address at its far end.
    direction: str | None = None
    far_address: str | None = None

    def relation_fields(self) -> set[str]:
        """All property names of a relation, across its property namespaces."""
        names = self.fields | self.empty_fields
        for namespace in self.namespace_fields.values():
            names |= namespace
        return names


@dataclass
class SeenAdObject:
    """An Active Directory object read with get_ad_object_info."""

    object_id: str
    ad_kind: str | None
    type: str | None
    fields: set[str] = field(default_factory=set)
    empty_fields: set[str] = field(default_factory=set)


@dataclass
class SearchCoverage:
    """Pages read and pages announced for one normalised search."""

    arguments: dict[str, Any]
    read: set[int] = field(default_factory=set)
    announced: set[int] = field(default_factory=set)
    # Latest timestamp among the rows of the pages read.
    latest: datetime | None = None

    @property
    def unread(self) -> list[int]:
        """Announced pages not read yet, lowest first."""
        return sorted(self.announced - self.read)


@dataclass(frozen=True)
class Reference:
    """One place where an id that may never have been opened was seen."""

    category: str
    via: str
    role: str
    neighbor: str | None

    def describe(self) -> str:
        """Short human form, e.g. 'target of wrote_file from <id>'."""
        if self.via == "host_id":
            return f"host of {self.neighbor}"
        if self.category == AD_OBJECT:
            return f"{self.via} of AD object {self.neighbor}"
        if self.category == RELATION:
            return f"{self.role} relation of {self.neighbor}"
        other = "from" if self.role == "target" else "to"
        return f"{self.role} of {self.via} {other} {self.neighbor}"


class EndpointTypes:
    """Entity types seen at each end of each relation type, learned from shown objects.

    Shared by the tasks of a run: once a relation type's endpoint has been seen a few times,
    the type of an id known only as such an endpoint can be predicted before it is opened.
    Nothing is assumed about relation names; an unknown catalog simply predicts nothing.
    """

    MIN_SEEN = 2
    MIN_SHARE = 0.9

    def __init__(self) -> None:
        """Start with no knowledge."""
        self._types: dict[tuple[str, str], Counter[str]] = {}
        self._counted: set[tuple[str, str]] = set()

    def learn(self, index: "EvidenceIndex") -> None:
        """Count the endpoint types of every relation whose endpoint is shown in full."""
        for relation in index.objects.values():
            if relation.category != RELATION:
                continue
            for role, endpoint_id in (
                ("source", relation.source_id),
                ("target", relation.target_id),
            ):
                endpoint = index.objects.get(endpoint_id or "")
                if endpoint is None or endpoint.category != ENTITY:
                    continue
                if (relation.object_id, role) in self._counted:
                    continue
                self._counted.add((relation.object_id, role))
                self._types.setdefault((relation.type, role), Counter())[endpoint.type] += 1

    def predict(self, relation_type: str, role: str) -> str | None:
        """The entity type at that end of that relation type, when it has been consistent."""
        counts = self._types.get((relation_type, role))
        if not counts:
            return None
        entity_type, seen = counts.most_common(1)[0]
        total = sum(counts.values())
        return entity_type if total >= self.MIN_SEEN and seen / total >= self.MIN_SHARE else None


class EvidenceIndex:
    """What the agent has been shown during one task."""

    def __init__(self) -> None:
        """Start empty; fill with `record_alert` and `record_result`."""
        self.objects: dict[str, SeenObject] = {}
        self.references: dict[str, list[Reference]] = {}
        self.ad_objects: dict[str, SeenAdObject] = {}
        # AD object id -> graph entities whose `ad_object_id` property names it.
        self.ad_links: dict[str, set[str]] = {}
        self._searches: dict[str, SearchCoverage] = {}
        # The trigger's own first-to-last time span and the account / logon terms that
        # identify its session (from `trigger_anchors`).
        self.trigger_span: tuple[datetime, datetime] | None = None
        self.session_terms: list[str] = []

    def record_alert(self, alert: Any) -> int:
        """Index the alert's trigger objects; return how many were new."""
        if not isinstance(alert, dict):
            return 0
        anchors = trigger_anchors(alert)
        span = anchors.get("trigger_time_span")
        if span:
            start, end = _parse_time(span["from"]), _parse_time(span["to"])
            if start and end:
                self.trigger_span = (start, end)
        terms = [user["name"] for user in anchors.get("users", [])]
        terms += [user["search_as"] for user in anchors.get("users", []) if "search_as" in user]
        self.session_terms = [
            term.lower()
            for term in [*terms, *anchors.get("logon_ids", [])]
            if term.lower() not in _HOST_WIDE_IDENTITIES
        ]
        new = 0
        for raw in alert.get("trigger_entities") or []:
            new += self._record(raw, "alert", ENTITY)
        for raw in alert.get("trigger_relations") or []:
            new += self._record(raw, "alert", RELATION)
        return new

    def record_result(
        self,
        tool: str,
        arguments: dict[str, Any],
        result: Any,
        defaults: dict[str, Any] | None = None,
    ) -> int:
        """Index one runtime read result; return how many objects it showed for the first time.

        `defaults` are the tool's declared argument defaults, so a search spelled with or
        without them counts as the same search for page coverage.
        """
        if tool == "get_entity":
            return self._record(result, tool, ENTITY)
        if tool == "get_relation":
            return self._record(result, tool, RELATION)
        if tool == "get_ad_object_info":
            return self._record_ad(result)
        if tool != "search" or not isinstance(result, dict):
            return 0
        rows = result.get("results")
        new = sum(self._record(row, tool, None) for row in rows) if isinstance(rows, list) else 0
        coverage = self.search_coverage(arguments, defaults)
        page = arguments.get("page_id") or result.get("current_page_id") or 1
        if isinstance(page, int):
            coverage.read.add(page)
        next_page = result.get("next_page_id")
        if isinstance(next_page, int):
            coverage.announced.add(next_page)
        for row in rows if isinstance(rows, list) else []:
            for stamp in _row_times(row):
                if coverage.latest is None or stamp > coverage.latest:
                    coverage.latest = stamp
        return new

    def window_gaps(self) -> list[dict[str, Any]]:
        """Session searches that stopped before the trigger's time span.

        A search on the trigger's account or logon id, without a time window over the
        span, whose pages read all end before the span starts while more pages remain: the
        alert window itself was never read. Empty once any session search is windowed over
        the span, and when the alert gives no span or no session terms.
        """
        if self.trigger_span is None or not self.session_terms:
            return []
        start, end = self.trigger_span
        session = [
            coverage
            for coverage in self._searches.values()
            if any(
                term in str(coverage.arguments.get("query", "")).lower()
                for term in self.session_terms
            )
        ]
        if any(_window_overlaps(c.arguments.get("time_window"), start, end) for c in session):
            return []
        return [
            {
                "query": coverage.arguments.get("query"),
                "read_until": coverage.latest.isoformat(),
                "unread_pages": coverage.unread,
            }
            for coverage in session
            if coverage.unread and coverage.latest is not None and coverage.latest < start
        ]

    def search_coverage(
        self, arguments: dict[str, Any], defaults: dict[str, Any] | None = None
    ) -> SearchCoverage:
        """Coverage record of a search: same query and filters, defaults normalised away."""
        defaults = defaults or {}
        normalized = {
            key: value
            for key, value in arguments.items()
            if key not in ("reasoning", "page_id")
            and not (key in defaults and defaults[key] == value)
        }
        signature = json.dumps(normalized, sort_keys=True, ensure_ascii=False)
        return self._searches.setdefault(signature, SearchCoverage(normalized))

    def unread_searches(self) -> list[dict[str, Any]]:
        """Every search with announced but unread pages: its query, filters and those pages."""
        found = []
        for coverage in self._searches.values():
            if coverage.unread:
                entry = {key: value for key, value in coverage.arguments.items() if value}
                entry["unread_pages"] = coverage.unread
                found.append(entry)
        return found

    def unfetched_pages(self, limit: int = 3) -> list[dict[str, Any]]:
        """The first `limit` searches with unread pages (see `unread_searches`)."""
        return self.unread_searches()[:limit]

    def category(self, object_id: str) -> str | None:
        """Entity, relation or AD object, when the id was seen as one."""
        seen = self.objects.get(object_id)
        if seen is not None:
            return seen.category
        if object_id in self.ad_objects:
            return AD_OBJECT
        categories = {ref.category for ref in self.references.get(object_id, [])}
        return categories.pop() if len(categories) == 1 else None

    def connection_process(self, connection_id: str) -> str | None:
        """The process a shown relation ties to a connection, when exactly one is known."""
        sources = {
            seen.source_id
            for seen in self.objects.values()
            if seen.type in CONNECTION_LINKS and seen.target_id == connection_id and seen.source_id
        }
        return sources.pop() if len(sources) == 1 else None

    def far_host(self, connection_id: str) -> str | None:
        """The shown host at a connection's far end, by its host id or a host relation."""
        seen = self.objects.get(connection_id)
        if seen is None or seen.type != CONNECTION_TYPE:
            return None
        candidates = [seen.host_id] + [
            link.target_id
            for link in self.objects.values()
            if link.type == "connection_to_host" and link.source_id == connection_id
        ]
        for host_id in candidates:
            host = self.objects.get(host_id or "")
            if host is not None and host.type == "host":
                return host.object_id
        return None

    def sole_channel(self, connection_id: str, cited: set[str]) -> bool:
        """Whether a shown connection is the single channel of a cited process.

        True when the connection is the only one its process is known to have made or
        accepted, no other shown connection has the same far end, and the process is cited in
        the report or is an alert object. An outbound connection to a private address is left
        out: its far end is an internal host, which a response isolates rather than blocks.

        Why (scripts/connection_keys.py, training traces): such a connection was a key object
        in 57 of 64 certain cases, every other shown connection in 3 of 1829 — a series from
        one process or to one destination (beaconing, repeated transfers) is credited to the
        remote host, if at all. The organisers' reference task cites exactly this object as
        `network_block`.
        """
        seen = self.objects.get(connection_id)
        if seen is None or seen.type != CONNECTION_TYPE:
            return False
        process = self.connection_process(connection_id)
        if process is None:
            return False
        made = {
            link.target_id
            for link in self.objects.values()
            if link.type in CONNECTION_LINKS and link.source_id == process and link.target_id
        }
        if made != {connection_id}:
            return False
        shown = self.objects.get(process)
        if process not in cited and not (shown is not None and shown.shown_by == "alert"):
            return False
        if seen.direction == "outbound" and inside_address(seen.far_address):
            return False
        far_end = (seen.host_id, seen.far_address)
        return not any(
            other.object_id != connection_id
            and other.type == CONNECTION_TYPE
            and (
                (far_end[0] is not None and other.host_id == far_end[0])
                or (far_end[1] is not None and other.far_address == far_end[1])
            )
            for other in self.objects.values()
        )

    def unopened(self, around: set[str] | None = None, limit: int = 5) -> list[dict[str, str]]:
        """Entities referenced by what the agent saw but never opened.

        Endpoints of relations touching `around` come first, then other relation endpoints,
        then hosts known only from objects' host_id.
        """
        around = around or set()
        ranked: list[tuple[int, str, Reference]] = []
        for object_id, refs in self.references.items():
            if object_id in self.objects:
                continue
            entity_refs = [ref for ref in refs if ref.category == ENTITY]
            if not entity_refs:
                continue
            near = [ref for ref in entity_refs if ref.neighbor in around and ref.via != "host_id"]
            linked = [ref for ref in entity_refs if ref.via != "host_id"]
            if near:
                ranked.append((0, object_id, near[0]))
            elif linked:
                ranked.append((1, object_id, linked[0]))
            else:
                ranked.append((2, object_id, entity_refs[0]))
        ranked.sort(key=lambda row: row[0])
        return [
            {"id": object_id, "seen_as": ref.describe()} for _, object_id, ref in ranked[:limit]
        ]

    def unopened_relations(
        self, around: set[str] | None = None, limit: int = 6
    ) -> list[dict[str, str]]:
        """Relation ids listed in an object's relation_ids but never read.

        Only what is known is reported: the id, its direction and the object that listed it
        (type and other endpoint stay unknown until read). Relations of `around` come first.
        """
        around = around or set()
        ranked: list[tuple[int, dict[str, str]]] = []
        for object_id, refs in self.references.items():
            if object_id in self.objects:
                continue
            for ref in refs:
                if ref.category == RELATION and ref.neighbor:
                    entry = {"id": object_id, "direction": ref.role, "of": ref.neighbor}
                    ranked.append((0 if ref.neighbor in around else 1, entry))
                    break
        ranked.sort(key=lambda row: row[0])
        return [entry for _, entry in ranked[:limit]]

    def _record(self, raw: Any, source: str, category: str | None) -> int:
        if not isinstance(raw, dict):
            return 0
        object_id, object_type = raw.get("id"), raw.get("type")
        if not (isinstance(object_id, str) and object_id and isinstance(object_type, str)):
            return 0
        if category is None:
            kind = raw.get("kind")
            if kind in (ENTITY, RELATION):
                category = kind
            else:
                category = RELATION if "source_id" in raw or "target_id" in raw else ENTITY
        new = object_id not in self.objects
        seen = self.objects.get(object_id) or SeenObject(object_id, category, object_type, source)

        properties = raw.get("properties")
        if isinstance(properties, dict):
            for key, value in properties.items():
                name = str(key)
                (seen.empty_fields if is_empty(value) else seen.fields).add(name)
                if _truncated(value):
                    seen.truncated_fields.add(name)
            seen.empty_fields -= seen.fields
            ad_id = properties.get("ad_object_id")
            if isinstance(ad_id, str) and ad_id:
                self.ad_links.setdefault(ad_id, set()).add(object_id)
            logon_id = properties.get("logon_id")
            if isinstance(logon_id, str) and logon_id:
                seen.logon_id = logon_id
            if object_type.endswith("_user") and builtin_identity(properties):
                seen.builtin = True
            if object_type == CONNECTION_TYPE:
                direction = properties.get("direction")
                seen.direction = direction if isinstance(direction, str) else seen.direction
                far = properties.get("src_ip" if direction == "inbound" else "dst_ip")
                seen.far_address = str(far) if isinstance(far, (str, int)) else seen.far_address

        if category == RELATION:
            for namespace in RELATION_NAMESPACES:
                block = raw.get(namespace)
                if isinstance(block, dict):
                    seen.namespace_fields.setdefault(namespace, set()).update(
                        str(key) for key, value in block.items() if not is_empty(value)
                    )
            source_id, target_id = raw.get("source_id"), raw.get("target_id")
            seen.source_id = source_id if isinstance(source_id, str) else seen.source_id
            seen.target_id = target_id if isinstance(target_id, str) else seen.target_id
            if seen.source_id:
                self._reference(
                    seen.source_id, Reference(ENTITY, object_type, "source", seen.target_id)
                )
            if seen.target_id:
                self._reference(
                    seen.target_id, Reference(ENTITY, object_type, "target", seen.source_id)
                )

        host_id = raw.get("host_id")
        if isinstance(host_id, str) and host_id and host_id != object_id:
            seen.host_id = host_id
            self._reference(host_id, Reference(ENTITY, "host_id", "host", object_id))
        relation_ids = raw.get("relation_ids")
        if isinstance(relation_ids, dict):
            for direction, ids in relation_ids.items():
                for relation_id in ids if isinstance(ids, list) else []:
                    if isinstance(relation_id, str):
                        reference = Reference(RELATION, "relation_ids", str(direction), object_id)
                        self._reference(relation_id, reference)

        self.objects[object_id] = seen
        return int(new)

    def _record_ad(self, raw: Any) -> int:
        """Index an AD object: its own id, kind, type and top-level attributes.

        Resolved references (a list or object with its own `id` and `kind`, e.g. groups)
        are kept as AD references; nothing is parsed out of string values.
        """
        if not isinstance(raw, dict):
            return 0
        object_id = raw.get("id")
        if not isinstance(object_id, str) or not object_id:
            return 0
        new = object_id not in self.ad_objects
        kind, ad_type = raw.get("kind"), raw.get("type")
        seen = self.ad_objects.get(object_id) or SeenAdObject(
            object_id,
            kind if isinstance(kind, str) else None,
            ad_type if isinstance(ad_type, str) else None,
        )
        for key, value in raw.items():
            if key in ("id", "kind", "type"):
                continue
            (seen.empty_fields if is_empty(value) else seen.fields).add(str(key))
            nested = value if isinstance(value, list) else [value]
            for item in nested:
                if (
                    isinstance(item, dict)
                    and isinstance(item.get("id"), str)
                    and isinstance(item.get("kind"), str)
                ):
                    self._reference(item["id"], Reference(AD_OBJECT, str(key), "ad", object_id))
        seen.empty_fields -= seen.fields
        self.ad_objects[object_id] = seen
        return int(new)

    def _reference(self, object_id: str, reference: Reference) -> None:
        refs = self.references.setdefault(object_id, [])
        if reference not in refs and len(refs) < _MAX_REFERENCES_PER_ID:
            refs.append(reference)
