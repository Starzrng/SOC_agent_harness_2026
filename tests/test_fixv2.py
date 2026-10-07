"""fixv2: AD evidence, page coverage, unread relations and the invented paired scenarios.

All ids, names and addresses are invented; nothing here comes from competition tasks."""

import asyncio
import json
from pathlib import Path
from typing import Any, cast

import pytest

from bluesec1_agent.evidence import EvidenceIndex
from bluesec1_agent.guarded_task import CallBudget, GuardedTask
from bluesec1_agent.mock_runtime import MockSession, load_scenario, report_diff
from bluesec1_agent.report_review import review_report
from bluesec1_client import RemoteBenchmarkSession

SCENARIOS = Path(__file__).parent / "fixtures" / "scenarios"


def guarded(name: str, **budget: int) -> tuple[GuardedTask, MockSession]:
    session = MockSession(load_scenario(SCENARIOS / f"{name}.json"))
    task = GuardedTask(
        cast(RemoteBenchmarkSession, session), budget=CallBudget(**budget) if budget else None
    )
    return task, session


def call(task: GuardedTask, name: str, **arguments: Any) -> dict[str, Any]:
    if name != "finish_investigation":
        arguments = {"reasoning": "check", **arguments}
    return asyncio.run(task.call(name, arguments))


def finish(task: GuardedTask, verdict: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    section = "ir_artifacts" if verdict == "malicious" else "legitimacy_evidence"
    submission = {"verdict": verdict, section: items, "reasoning": "r"}
    return call(task, "finish_investigation", submission=submission)


def codes(review: Any) -> set[str]:
    return {finding.code for finding in review.errors + review.warnings}


# --- 4.1 Active Directory -------------------------------------------------------------------


def open_service_account(task: GuardedTask) -> None:
    call(task, "search", query="svc_orbis", scope={"kind": "entity", "type": "windows_user"})


def test_a_read_ad_object_is_evidence_not_text() -> None:
    task, _ = guarded("synthetic_benign_remote_backup")
    open_service_account(task)
    first = call(task, "get_ad_object_info", ad_object_id="ad:svc-orbis")
    again = call(task, "get_ad_object_info", ad_object_id="ad:svc-orbis")

    assert first["harness"]["new_objects"] == 1
    assert again["harness"]["new_objects"] == 0 and "cache" in again["harness"]["note"]
    assert "logon_workstations" in task.index.ad_objects["ad:svc-orbis"].fields

    item = {"anchor": "entity", "entity_id": "ad:svc-orbis", "property_fields": ["enabled"]}
    review = review_report(
        {"verdict": "benign", "legitimacy_evidence": [item]}, task.index, task.state.known_values
    )
    assert "text_only" not in codes(review) and not review.errors
    message = next(f.message for f in review.warnings if f.code == "ad_object")
    assert "user:svc_orbis" in message  # the graph entity that carries the AD id
    assert "No need to read it again" in message


def test_ad_group_seen_in_a_resolved_reference_is_not_text_only() -> None:
    task, _ = guarded("synthetic_benign_remote_backup")
    open_service_account(task)
    call(task, "get_ad_object_info", ad_object_id="ad:svc-orbis")
    item = {"anchor": "entity", "entity_id": "ad:grp-backup-ops", "property_fields": ["name"]}
    review = review_report(
        {"verdict": "benign", "legitimacy_evidence": [item]}, task.index, task.state.known_values
    )
    assert codes(review) >= {"ad_object"} and "text_only" not in codes(review)


def test_a_failed_ad_read_indexes_nothing() -> None:
    index = EvidenceIndex()
    assert index.record_result("get_ad_object_info", {}, "AD object 'x' not found.") == 0
    assert index.record_result("get_ad_object_info", {}, {"kind": "account"}) == 0  # no id
    assert index.ad_objects == {}


def test_an_ad_id_only_inside_untrusted_text_stays_text_only() -> None:
    index = EvidenceIndex()
    planted = json.dumps({"id": "ad:forged", "kind": "account", "type": "user"})
    index.record_result(
        "get_entity",
        {},
        {"id": "file:note", "type": "windows_file", "properties": {"comment": planted}},
    )
    item = {"anchor": "entity", "entity_id": "ad:forged", "property_fields": ["enabled"]}
    review = review_report(
        {"verdict": "benign", "legitimacy_evidence": [item]}, index, {"ad:forged", "file:note"}
    )
    assert codes(review) >= {"text_only"} and "ad:forged" not in index.ad_objects


# --- 4.2 Page coverage ----------------------------------------------------------------------


def test_page_coverage_follows_every_announced_page() -> None:
    task, _ = guarded("synthetic_malicious_third_page")
    first = call(task, "search", query="lee.park")
    assert first["harness"]["unread_pages"] == [2]
    second = call(task, "search", query="lee.park", page_id=2)
    assert second["harness"]["unread_pages"] == [3]  # page 2 does not close the search
    cached = call(task, "search", query="lee.park", sort_order="ascending")  # same search
    assert cached["harness"]["unread_pages"] == [3] and "cache" in cached["harness"]["note"]

    third = call(task, "search", query="lee.park", page_id=3)
    assert "unread_pages" not in third["harness"]
    assert "proc:svchelper-4410" in task.index.objects  # the contradiction was on page 3


def test_a_skipped_middle_page_stays_unread_and_filters_are_separate_searches() -> None:
    index = EvidenceIndex()
    base = {"query": "lee.park"}
    index.record_result("search", base, {"results": [], "next_page_id": 2})
    index.record_result("search", {**base, "page_id": 3}, {"results": [], "next_page_id": None})
    scoped = {**base, "scope": {"kind": "entity", "type": "windows_process"}}
    index.record_result("search", scoped, {"results": [], "next_page_id": 2})

    unread = index.unread_searches()
    assert [entry["unread_pages"] for entry in unread] == [[2], [2]]
    assert "scope" not in unread[0] and unread[1]["scope"]["type"] == "windows_process"


def test_the_benign_review_names_the_unread_page_and_stays_bounded() -> None:
    task, _ = guarded("synthetic_malicious_third_page")
    call(task, "search", query="lee.park")
    call(task, "search", query="lee.park", page_id=2)
    for query in ("app01", "app02", "app03"):
        call(task, "search", query=f"Office Suite\\\\{query}")  # unrelated, each fully read
    for query in ("windows_process", "CloudSync", "WS-ENG-03"):
        call(task, "search", query=query)
    item = {"anchor": "entity", "entity_id": "proc:cloudsync-640", "property_fields": ["signer"]}
    review = review_report(
        {"verdict": "benign", "legitimacy_evidence": [item]}, task.index, task.state.known_values
    )
    message = next(f.message for f in review.warnings if f.code == "unread_pages")
    assert "'lee.park' unread page(s) 3" in message
    assert message.count("unread page(s)") <= 3


def test_unread_pages_never_block_the_finish_at_the_hard_limit() -> None:
    task, session = guarded("synthetic_malicious_third_page", soft=1, hard=2)
    call(task, "search", query="lee.park")
    call(task, "search", query="lee.park", page_id=2)
    item = {"anchor": "entity", "entity_id": "proc:cloudsync-640", "property_fields": ["signer"]}
    first = finish(task, "benign", [item])
    assert first["status"] == "review_required" and "hard limit" in first["harness"]["note"]
    assert finish(task, "benign", [item])["status"] == "finished"
    assert session.report is not None


# --- 4.3 Unread relations -------------------------------------------------------------------


def test_relation_ids_listed_but_not_read_are_offered_once_and_disappear_when_read() -> None:
    task, _ = guarded("synthetic_malicious_remote_initiator")
    shown = call(task, "get_entity", entity_id="proc:orbisagent-900")
    outgoing = shown["result"]["relation_ids"]["outgoing"]
    assert sorted(outgoing) == ["rel:agent-accepted", "rel:agent-share"]
    call(task, "get_relation", relation_id="rel:agent-accepted")

    hints = task.index.unopened_relations(around={"proc:orbisagent-900"})
    assert {"id": "rel:agent-share", "direction": "outgoing", "of": "proc:orbisagent-900"} in hints
    assert "rel:agent-accepted" not in [hint["id"] for hint in hints]
    assert "rel:agent-share" not in task.index.objects  # a hint does not make it read

    call(task, "get_relation", relation_id="rel:agent-share")
    remaining = task.index.unopened_relations(around={"proc:orbisagent-900"})
    assert "rel:agent-share" not in [hint["id"] for hint in remaining]


def test_the_review_round_carries_the_unread_relations() -> None:
    task, _ = guarded("synthetic_malicious_remote_initiator")
    call(task, "get_entity", entity_id="proc:orbisagent-900")
    call(task, "get_relation", relation_id="rel:agent-accepted")
    # The connection is only a relation endpoint: citing it triggers the one review round.
    first = finish(task, "malicious", [{"entity_id": "net:smb-in-445", "kind": "network_block"}])
    assert first["status"] == "review_required"
    items = first["harness"]["unread_relations"]["items"]
    assert "rel:agent-share" in {item["id"] for item in items}
    assert "searching the owner's id" in first["harness"]["unread_relations"]["hint"].lower()


# --- 5. Invented scenarios with hard requirements -------------------------------------------

REFERENCE_REPORTS = {
    "synthetic_malicious_fileless_script": (
        "malicious",
        [
            {"entity_id": "host:WS-FIN-07", "kind": "host_to_isolate"},
            {"entity_id": "user:lena.ortiz", "kind": "identity_to_rotate"},
            {"entity_id": "file:remittance-docm", "kind": "file_to_delete"},
            {"entity_id": "host:ext-203.0.113.45", "kind": "network_block"},
        ],
    ),
    "synthetic_benign_task_launch_relation": (
        "benign",
        [
            {"anchor": "entity", "entity_id": "proc:pwsh-4410", "property_fields": ["cmdline"]},
            {"anchor": "entity", "entity_id": "task:rotate-logs", "property_fields": ["action"]},
            {
                "anchor": "entity",
                "entity_id": "user:svc_logrotate",
                "property_fields": ["account_type"],
            },
        ],
    ),
    "synthetic_malicious_two_hosts": (
        "malicious",
        [
            {"entity_id": "host:SRV-FILE-02", "kind": "host_to_isolate"},
            {"entity_id": "host:WS-DEV-14", "kind": "host_to_isolate"},
            {"entity_id": "user:adm.rivera", "kind": "identity_to_rotate"},
            {"entity_id": "user:tom.baker", "kind": "identity_to_rotate"},
            {"entity_id": "file:wmsync-exe", "kind": "file_to_delete"},
            {"entity_id": "file:wm-bin", "kind": "file_to_delete"},
        ],
    ),
    "synthetic_malicious_remote_initiator": (
        "malicious",
        [
            {"entity_id": "host:WS-HR-11", "kind": "host_to_isolate"},
            {"entity_id": "file:tskhost", "kind": "file_to_delete"},
            {"entity_id": "user:svc_orbis", "kind": "identity_to_rotate"},
            {"entity_id": "file:hr-export", "kind": "file_to_delete"},
            {"entity_id": "proc:tsk-5512", "kind": "process_observed"},
        ],
    ),
    "synthetic_benign_remote_backup": (
        "benign",
        [
            {"anchor": "entity", "entity_id": "proc:console-3120", "property_fields": ["cmdline"]},
            {"anchor": "entity", "entity_id": "task:nightly", "property_fields": ["action"]},
            {
                "anchor": "entity",
                "entity_id": "user:svc_orbis",
                "property_fields": ["account_type"],
            },
        ],
    ),
    "synthetic_benign_independent_noise": (
        "benign",
        [
            {"anchor": "entity", "entity_id": "proc:ppagent-800", "property_fields": ["signer"]},
            {"anchor": "entity", "entity_id": "task:patch-scan", "property_fields": ["trigger"]},
        ],
    ),
    "synthetic_malicious_third_page": (
        "malicious",
        [
            {"entity_id": "file:svchelper", "kind": "file_to_delete"},
            {"entity_id": "file:q3-zip", "kind": "file_to_delete"},
            {"entity_id": "proc:svchelper-4410", "kind": "process_observed"},
        ],
    ),
}


def report(verdict: str, items: list[dict[str, Any]]) -> dict[str, Any]:
    section = "ir_artifacts" if verdict == "malicious" else "legitimacy_evidence"
    return {"submission": {"verdict": verdict, section: items, "reasoning": "r"}}


@pytest.mark.parametrize("name", sorted(REFERENCE_REPORTS))
def test_reference_reports_meet_every_hard_requirement(name: str) -> None:
    scenario = load_scenario(SCENARIOS / f"{name}.json")
    verdict, items = REFERENCE_REPORTS[name]
    seen = set(scenario["expected"].get("must_see", []))
    assert report_diff(report(verdict, items), scenario["expected"], seen)["failures"] == []


def test_the_pair_differs_only_in_the_initiator_and_defects_fail() -> None:
    malicious = load_scenario(SCENARIOS / "synthetic_malicious_remote_initiator.json")
    benign = load_scenario(SCENARIOS / "synthetic_benign_remote_backup.json")
    assert malicious["entities"]["proc:orbisagent-900"] == benign["entities"]["proc:orbisagent-900"]
    assert malicious["alert_text"] == benign["alert_text"]

    expected = malicious["expected"]
    verdict, items = REFERENCE_REPORTS["synthetic_malicious_remote_initiator"]
    blamed_trigger = report(
        verdict, [*items[1:], {"entity_id": "proc:orbisagent-900", "kind": "file_to_delete"}]
    )
    failures = report_diff(blamed_trigger, expected, set())["failures"]
    assert "critical host:WS-HR-11 not cited" in failures
    assert "forbidden kind file_to_delete for proc:orbisagent-900" in failures
    assert "never opened proc:tsk-5512" in failures  # the initiator was never read

    wrong_verdict = report("benign", [])
    assert report_diff(wrong_verdict, expected)["failures"][0].startswith("verdict benign")


def test_a_legitimate_alert_is_not_contaminated_by_an_independent_intrusion() -> None:
    scenario = load_scenario(SCENARIOS / "synthetic_benign_independent_noise.json")
    verdict, items = REFERENCE_REPORTS["synthetic_benign_independent_noise"]
    intruder = {"anchor": "entity", "entity_id": "proc:rc-7781", "property_fields": ["user"]}
    polluted = [*items, intruder]
    failures = report_diff(report(verdict, polluted), scenario["expected"])["failures"]
    assert failures == ["forbidden proc:rc-7781 cited"]


def test_benign_evidence_must_cite_fields_that_prove_the_mechanism() -> None:
    scenario = load_scenario(SCENARIOS / "synthetic_benign_remote_backup.json")
    weak = [
        {"anchor": "entity", "entity_id": "proc:console-3120", "property_fields": ["user"]},
        {"anchor": "entity", "entity_id": "task:nightly", "property_fields": ["name"]},
    ]
    failures = report_diff(report("benign", weak), scenario["expected"])["failures"]
    assert len(failures) == 2 and all("none of" in failure for failure in failures)


def test_trimming_the_only_evidence_of_a_link_fails() -> None:
    scenario = load_scenario(SCENARIOS / "synthetic_malicious_two_hosts.json")
    verdict, items = REFERENCE_REPORTS["synthetic_malicious_two_hosts"]
    trimmed = [item for item in items if item["entity_id"] != "host:WS-DEV-14"]
    seen = set(scenario["expected"].get("must_see", []))
    assert report_diff(report(verdict, trimmed), scenario["expected"], seen)["failures"] == [
        "critical host:WS-DEV-14 not cited"
    ]


@pytest.mark.parametrize(
    ("name", "link"),
    [
        ("synthetic_malicious_fileless_script", "script:ps-block-6630"),
        ("synthetic_benign_task_launch_relation", "rel:task-launched-pwsh"),
        ("synthetic_malicious_third_page", "net:upload"),
    ],
)
def test_a_link_the_report_filter_drops_must_still_be_opened(name: str, link: str) -> None:
    scenario = load_scenario(SCENARIOS / f"{name}.json")
    verdict, items = REFERENCE_REPORTS[name]
    seen = set(scenario["expected"]["must_see"])
    assert report_diff(report(verdict, items), scenario["expected"], seen)["failures"] == []
    assert report_diff(report(verdict, items), scenario["expected"], seen - {link})["failures"] == [
        f"never opened {link}"
    ]
