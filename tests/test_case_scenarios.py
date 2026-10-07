"""The invented off-distribution scenarios (admin-vs-attacker twins, Linux) are well formed.

Every scenario file must be internally consistent, and each new case must be solvable through
the harness: a walk outwards from the trigger reaches every expected object and the reference
report passes the scenario's own requirements. All data is invented."""

import asyncio
import json
from pathlib import Path
from typing import Any, cast

import pytest

from bluesec1_agent.guarded_task import CallBudget, GuardedTask
from bluesec1_agent.mock_runtime import (
    MockSession,
    load_scenario,
    public_task_id,
    report_diff,
    scenario_for_task,
)
from bluesec1_client import RemoteBenchmarkSession

SCENARIOS = Path(__file__).parent / "fixtures" / "scenarios"
CASES = [
    "synthetic_benign_admin_account_onboarding",
    "synthetic_benign_admin_wmi_restart",
    "synthetic_benign_linux_config_sync",
    "synthetic_malicious_admin_account_backdoor",
    "synthetic_malicious_admin_wmi_trojan",
    "synthetic_malicious_linux_ssh_intrusion",
]


def call(task: GuardedTask, name: str, **arguments: Any) -> dict[str, Any]:
    if name != "finish_investigation":
        arguments = {"reasoning": "check", **arguments}
    return asyncio.run(task.call(name, arguments))


@pytest.mark.parametrize("path", sorted(SCENARIOS.glob("*.json")), ids=lambda path: path.stem)
def test_scenario_files_are_consistent(path: Path) -> None:
    scenario = load_scenario(path)
    entities, relations = scenario["entities"], scenario["relations"]
    assert scenario["name"] == path.stem
    for relation in relations.values():
        assert relation["source"] in entities and relation["target"] in entities
    assert set(scenario["alert_text"]["trigger_entities"]) <= set(entities)
    for entity in entities.values():
        if entity.get("ad_object_id"):
            assert entity["ad_object_id"] in scenario.get("ad_objects", {})
    expected = scenario["expected"]
    cited = [item["entity_id"] for item in expected["artifacts"]]
    cited += [need.get("entity_id") or need.get("relation_id") for need in expected["critical"]]
    cited += expected.get("must_see", []) + expected.get("forbidden_artifacts", [])
    assert set(cited) <= set(entities) | set(relations)


@pytest.mark.parametrize("path", sorted(SCENARIOS.glob("*.json")), ids=lambda path: path.stem)
def test_the_task_id_does_not_reveal_the_scenario(path: Path) -> None:
    # Scenario names carry the verdict; the investigator sees the task id and the alert.
    session = MockSession(load_scenario(path))
    assert session.task_id == public_task_id(path.stem)
    assert scenario_for_task(session.task_id) == path
    assert scenario_for_task(path.stem) == path  # traces recorded before the ids were opaque
    shown = (session.task_id + json.dumps(session.task.observation)).lower()
    assert path.stem.lower() not in shown and "synthetic" not in shown


@pytest.mark.parametrize("name", sorted(CASES))
def test_a_case_is_solvable_through_the_harness(name: str) -> None:
    scenario = load_scenario(SCENARIOS / f"{name}.json")
    expected = scenario["expected"]
    session = MockSession(scenario)
    task = GuardedTask(cast(RemoteBenchmarkSession, session), budget=CallBudget(soft=400, hard=500))
    assert task.alert_view()["harness"]["anchors"]["users"]
    # Walk outwards from the trigger: searching an object's id lists the relations around it.
    queue = list(scenario["alert_text"]["trigger_entities"])
    searched: set[str] = set()
    while queue:
        object_id = queue.pop(0)
        if object_id in searched:
            continue
        searched.add(object_id)
        page: int | None = 1
        while page:
            result = call(task, "search", query=object_id, page_id=page)
            assert result["status"] == "ok", result
            for row in result["result"]["results"]:
                queue += [row[key] for key in ("source_id", "target_id") if row.get(key)]
            page = result["result"].get("next_page_id")
    wanted = [item["entity_id"] for item in expected["artifacts"]] + expected["must_see"]
    assert set(wanted) <= set(task.index.objects) | searched
    for object_id in wanted:
        if object_id not in task.index.objects:
            assert call(task, "get_entity", entity_id=object_id)["status"] == "ok", object_id
    for ad_id in scenario["ad_objects"]:
        if ad_id in task.state.known_values:
            assert call(task, "get_ad_object_info", ad_object_id=ad_id)["status"] == "ok"

    if expected["verdict"] == "malicious":
        section = "ir_artifacts"
        items = [dict(item) for item in expected["artifacts"]]
    else:
        section = "legitimacy_evidence"
        fields = {need["entity_id"]: need["fields_any"][:2] for need in expected["critical"]}
        items = [
            {
                "anchor": "entity",
                "entity_id": item["entity_id"],
                "property_fields": fields.get(
                    item["entity_id"],
                    [key for key in scenario["entities"][item["entity_id"]] if key != "type"][:1],
                ),
            }
            for item in expected["artifacts"]
        ]
    submission = {"verdict": expected["verdict"], section: items, "reasoning": "reference"}
    result = call(task, "finish_investigation", submission=submission)
    if result["status"] == "review_required":
        assert "report_errors" not in result["harness"], result["harness"]
        result = call(task, "finish_investigation", submission=submission)
    assert result["status"] == "finished", json.dumps(result)[:400]
    seen = set(task.index.objects) | set(task.index.ad_objects)
    diff = report_diff(result["submitted_report"], expected, seen)
    assert diff["failures"] == [] and diff["missing"] == [] and diff["wrong_kind"] == []
