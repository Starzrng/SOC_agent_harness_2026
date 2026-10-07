import asyncio
import json
from pathlib import Path

import httpx
import pytest

from bluesec1_agent.guarded_task import GuardedTask
from bluesec1_agent.jev_shadow import (
    ATTACK_QUESTION,
    JevClient,
    JevError,
    evidence_state,
    load_task_evidence,
    shadow_task,
)
from bluesec1_agent.mock_runtime import (
    DEFAULT_SCENARIO_DIR,
    MockSession,
    load_scenario,
    public_task_id,
)
from bluesec1_agent.transcript import TranscriptWriter

API_KEY = "test-key-not-real"


def noul_transport(value: float, seen: list[httpx.Request] | None = None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if seen is not None:
            seen.append(request)
        questions = json.loads(request.content)["questions"]
        return httpx.Response(
            200,
            json={
                "model": "jev-test",
                "answers": {key: {"type": "noul", "noul": value} for key in questions},
                "usage": {"input_tokens": 100, "output_tokens": 5},
            },
        )

    return httpx.MockTransport(handler)


def test_client_sends_typed_request_and_parses_answers() -> None:
    seen: list[httpx.Request] = []

    async def scenario() -> dict:
        async with JevClient(API_KEY, transport=noul_transport(0.8, seen)) as client:
            return await client.evaluate({"alert": "x"}, {"q": ATTACK_QUESTION})

    payload = asyncio.run(scenario())
    assert payload["answers"]["q"]["noul"] == 0.8
    request = seen[0]
    assert request.url == "https://api.typesafe.ai/v1/systemone"
    assert request.headers["Authorization"] == f"Bearer {API_KEY}"
    body = json.loads(request.content)
    assert body == {
        "model": "jev-latest",
        "state": {"alert": "x"},
        "questions": {"q": ATTACK_QUESTION},
    }


@pytest.mark.parametrize(("status", "attempts"), [(529, 3), (429, 3), (422, 1), (401, 1)])
def test_client_retries_only_overload_and_never_leaks_the_key(status: int, attempts: int) -> None:
    calls: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(status, json={"detail": "nope"})

    async def scenario() -> None:
        async with JevClient(
            API_KEY, transport=httpx.MockTransport(handler), backoff_seconds=0
        ) as client:
            await client.evaluate("state", {"q": ATTACK_QUESTION})

    with pytest.raises(JevError) as excinfo:
        asyncio.run(scenario())
    assert len(calls) == attempts
    assert f"HTTP {status}" in str(excinfo.value)
    assert API_KEY not in str(excinfo.value)


def record_macro_trace(tmp_path: Path) -> Path:
    scenario = load_scenario(DEFAULT_SCENARIO_DIR / "synthetic_malicious_macro_dropper.json")

    async def investigate() -> None:
        session = MockSession(scenario)
        task = GuardedTask(session, transcript=TranscriptWriter(tmp_path, session.task_id))
        trigger = scenario["alert_text"]["trigger_entities"][0]
        read = {"entity_id": trigger, "reasoning": "trigger"}
        await task.call("get_entity", read)
        await task.call("get_entity", read)  # cached, not evidence
        await task.call(
            "get_relation", {"relation_id": "rel:powershell-wrote-exe", "reasoning": "drop"}
        )
        await task.call("get_entity", {"entity_id": "file:msupdate-svchost", "reasoning": "file"})
        await task.call(
            "finish_investigation",
            {
                "submission": {
                    "verdict": "malicious",
                    "ir_artifacts": [
                        {"entity_id": "file:msupdate-svchost", "kind": "file_to_delete"}
                    ],
                    "reasoning": "REPORT-REASONING-MARKER",
                }
            },
        )

    asyncio.run(investigate())
    return tmp_path / f"{public_task_id(scenario['name'])}.jsonl"


def test_trace_is_replayed_through_jev_without_the_report(tmp_path: Path) -> None:
    evidence = load_task_evidence(record_macro_trace(tmp_path))
    assert evidence is not None
    assert evidence.verdict == "malicious"
    assert [item["tool"] for item in evidence.items] == [
        "get_entity",
        "get_relation",
        "get_entity",
    ]
    assert evidence.items[0]["result"]["id"] == "proc:powershell-5120"  # decoded, no envelope
    assert evidence.result["quality_score"] is not None

    seen: list[httpx.Request] = []

    async def scenario() -> dict:
        async with JevClient(API_KEY, transport=noul_transport(0.9, seen)) as client:
            return await shadow_task(client, evidence)

    row = asyncio.run(scenario())
    assert row["p_attack"] == row["p_attack_alert_only"] == 0.9
    assert [item["source"] for item in row["injection"]] == [
        "alert",
        "get_entity",
        "get_relation",
        "get_entity",
    ]
    assert sum(item["regex_flags"] for item in row["injection"]) >= 1  # planted note
    assert row["input_tokens"] == 100 * len(seen) and not row["errors"]
    # Jev judges the evidence, never the agent's verdict or reasoning.
    assert not any(b"REPORT-REASONING-MARKER" in request.content for request in seen)


def test_errors_are_recorded_not_raised(tmp_path: Path) -> None:
    evidence = load_task_evidence(record_macro_trace(tmp_path))
    failing = httpx.MockTransport(lambda request: httpx.Response(422, json={}))

    async def scenario() -> dict:
        async with JevClient(API_KEY, transport=failing) as client:
            return await shadow_task(client, evidence)

    row = asyncio.run(scenario())
    assert row["p_attack"] is None
    assert len(row["errors"]) == 2 + len(row["injection"])


def test_evidence_state_keeps_call_order_and_cuts_to_size() -> None:
    items = [
        {
            "call": n,
            "tool": "get_entity",
            "arguments": {"entity_id": f"e{n}"},
            "result": "x" * 400,
            "error": None,
        }
        for n in range(10)
    ]
    state, omitted = evidence_state({"alert": "a"}, items, max_chars=2_000)
    assert omitted > 0
    assert len(state["evidence"]) == 10 - omitted
    assert [entry["arguments"]["entity_id"] for entry in state["evidence"]][0] == "e0"
    assert len(json.dumps(state)) <= 2_000
