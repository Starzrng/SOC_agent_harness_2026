import asyncio
import json
from pathlib import Path

from bluesec1_agent import mcp_server
from bluesec1_agent.guarded_task import build_spec, fit_to_schema
from bluesec1_agent.mcp_server import (
    OFFLINE_ARENA,
    BluesecService,
    IRArtifact,
    LegitimacyEvidence,
    build_report,
    mcp,
)
from bluesec1_agent.mock_runtime import (
    DEFAULT_SCENARIO_DIR,
    MOCK_TOOL_CATALOG,
    MockSession,
    load_scenario,
)
from bluesec1_agent.settings import RuntimeSettings
from bluesec1_client import RemoteRunNotFoundError, RemoteUnavailableError


def make_service() -> BluesecService:
    return BluesecService(
        settings_loader=lambda: RuntimeSettings(
            scenario_runtime_token="unused-offline", agent_transcript_dir=""
        )
    )


def test_offline_run_lifecycle_through_the_service() -> None:
    async def scenario() -> None:
        service = make_service()
        assert "error" in await service.lease_task()

        opened = await service.start_run(OFFLINE_ARENA)
        assert opened["run_id"].startswith("offline-")
        assert "error" in await service.start_run(OFFLINE_ARENA)

        leased = await service.lease_task()
        task_id = leased["task_id"]
        alert = service.get_alert(task_id)
        assert alert["harness"]["budget"]["runtime_calls_used"] == 0
        catalog = alert["tool_catalog"]
        assert {tool["name"] for tool in catalog["tools"]} >= {"get_entity", "search"}
        assert "host_to_isolate" in json.dumps(catalog)  # IR kinds survive the compact view
        full = service.get_alert(task_id, full_catalog=True)["tool_catalog"]
        assert {tool["name"] for tool in full} == {tool["name"] for tool in catalog["tools"]}

        trigger = alert["alert"]["alert_text"]["trigger_entities"][0]["id"]
        read = {"entity_id": trigger, "reasoning": "inspect the trigger"}
        first = await service.call(task_id, "get_entity", read)
        again = await service.call(task_id, "get_entity", read)
        guessed = await service.call(
            task_id, "get_entity", {"entity_id": "made-up-id", "reasoning": "guess"}
        )
        assert first["status"] == "ok"
        assert first["result"]["id"] == trigger and "relation_ids" in first["result"]
        assert "available_tools" not in json.dumps(first)  # no catalog echo per call
        assert "cache" in again["harness"]["note"]
        assert guessed["status"] == "rejected_locally"

        assert (await service.close_run())["error"] == "Tasks are still open."
        mixed = await service.finish(
            task_id, "benign", "test", [IRArtifact(entity_id=trigger, kind="process_observed")], []
        )
        assert mixed["status"] == "rejected_locally"
        finished = await service.finish(
            task_id,
            "benign",
            "test",
            [],
            [LegitimacyEvidence(anchor="entity", entity_id=trigger, property_fields=["signer"])],
        )
        assert finished["status"] == "finished"
        assert finished["submitted_report"]["submission"]["legitimacy_evidence"] == [
            {"anchor": "entity", "entity_id": trigger, "property_fields": ["signer"]}
        ]
        assert finished["task_result"]["tool_calls"] == 2

        status = service.status()
        assert status["totals"]["runtime_calls"] == 2
        assert status["totals"]["cache_hits"] == 1
        assert status["open_tasks"] == []

        while "task_id" in (leased := await service.lease_task()):
            await service.abort_task(leased["task_id"], "test")
        assert leased == {"queue_exhausted": True}
        assert (await service.close_run())["closed"] is True

    asyncio.run(scenario())


class LostRunClient:
    """A remote client whose run the runtime has already dropped."""

    async def start_task(self) -> None:
        raise RemoteRunNotFoundError("The remote run could not be found.")

    async def __aexit__(self, *exc_info: object) -> None:
        raise RemoteRunNotFoundError("The remote run could not be found.")


def test_a_run_dropped_by_the_runtime_can_be_closed_and_replaced() -> None:
    async def scenario() -> None:
        service = make_service()
        await service.start_run(OFFLINE_ARENA)
        service._client = LostRunClient()

        assert (await service.lease_task())["error"] == "run_lost"
        closed = await service.close_run()
        assert closed["closed"] is True and "dropped" in closed["note"]
        assert "run_id" in await service.start_run(OFFLINE_ARENA)

    asyncio.run(scenario())


def test_tasks_carry_their_investigator_variant() -> None:
    async def scenario() -> None:
        service = make_service()
        await service.start_run(OFFLINE_ARENA)
        task_id = (await service.lease_task())["task_id"]

        assert "error" in service.tag_task(task_id, "not a label!")
        assert "error" in service.tag_task("made-up-id", "B")
        assert "error" in service.tag_task(task_id, "B", soft_budget=30, hard_budget=20)
        tagged = service.tag_task(task_id, "B", soft_budget=16, hard_budget=22)
        assert tagged == {
            "task_id": task_id,
            "variant": "B",
            "budget": {"soft": 16, "hard": 22},
            "review": False,
            "anchors": True,
            "report_filter": True,
            "read_bump": False,
        }
        assert "16" in service.get_alert(task_id)["harness"]["budget"]["advice"]

        trigger = service.get_alert(task_id)["alert"]["alert_text"]["trigger_entities"][0]["id"]
        evidence = LegitimacyEvidence(
            anchor="entity", entity_id=trigger, property_fields=["signer"]
        )
        await service.finish(task_id, "benign", "test", [], [evidence])
        status = service.status()
        assert status["tasks"][0]["variant"] == "B"
        assert status["by_variant"]["B"]["tasks"] == 1
        assert "A" not in status["by_variant"]

    asyncio.run(scenario())


def test_mcp_tool_surface() -> None:
    names = {tool.name for tool in asyncio.run(mcp.list_tools())}
    assert names == {
        "start_run",
        "resume_run",
        "lease_task",
        "run_status",
        "tag_task",
        "abort_task",
        "finalize_draft",
        "close_run",
        "get_alert",
        "get_entity",
        "get_relation",
        "get_ad_object_info",
        "search",
        "call_runtime_tool",
        "get_draft",
        "finish_investigation",
    }


def test_report_follows_the_catalog_shape() -> None:
    live = next(spec for spec in MOCK_TOOL_CATALOG if spec["name"] == "finish_investigation")
    artifact = IRArtifact(entity_id="e1", kind="file_to_delete")
    evidence = LegitimacyEvidence(anchor="relation", relation_id="r1")

    assert build_report(live["parameters"], "malicious", "why", [artifact], []) == {
        "submission": {
            "verdict": "malicious",
            "ir_artifacts": [{"entity_id": "e1", "kind": "file_to_delete"}],
            "reasoning": "why",
        }
    }
    assert build_report(live["parameters"], "benign", "why", [], [evidence]) == {
        "submission": {
            "verdict": "benign",
            "legitimacy_evidence": [{"anchor": "relation", "relation_id": "r1"}],
            "reasoning": "why",
        }
    }
    assert isinstance(build_report(live["parameters"], "malicious", "w", [], [evidence]), str)

    legacy = {"properties": {"verdict": {}, "ir_artifacts": {}, "reasoning": {}}}
    assert build_report(legacy, "benign", "why", [artifact], []) == {
        "verdict": "benign",
        "ir_artifacts": [{"entity_id": "e1", "kind": "file_to_delete"}],
        "reasoning": "why",
    }


def test_dedicated_tool_arguments_fit_the_advertised_schema() -> None:
    strict = build_spec(
        {
            "name": "get_entity",
            "parameters": {
                "type": "object",
                "properties": {"entity_id": {"type": "string"}},
                "additionalProperties": False,
            },
        }
    )
    loose = build_spec({"name": "get_entity", "parameters": {"type": "object"}})
    arguments = {"entity_id": "e", "reasoning": "why"}

    assert strict is not None and loose is not None
    assert fit_to_schema(strict, arguments) == {"entity_id": "e"}
    assert fit_to_schema(loose, arguments) == arguments


def test_a_run_records_its_model_next_to_the_traces(tmp_path) -> None:
    async def scenario() -> None:
        service = BluesecService(
            settings_loader=lambda: RuntimeSettings(
                scenario_runtime_token="unused-offline", agent_transcript_dir=str(tmp_path)
            )
        )
        opened = await service.start_run(OFFLINE_ARENA, model_name="claude-sonnet-5", effort="max")
        info = json.loads((Path(opened["trace_dir"]) / "run.json").read_text())
        assert info["model_name"] == "claude-sonnet-5" and info["arena"] == OFFLINE_ARENA
        assert info["effort"] == "max"
        await service.close_run(force=True)

    asyncio.run(scenario())


def test_an_unreachable_runtime_is_retried_and_reported_with_its_details(monkeypatch) -> None:
    created: list[dict] = []

    class UnreachableClient:
        def __init__(self, **kwargs) -> None:
            created.append(kwargs)

        async def __aenter__(self) -> None:
            raise RemoteUnavailableError(
                "The remote runtime is temporarily unavailable.",
                retryable=True,
                reason="upstream_connect_error",
                request_id="req-1",
            )

    monkeypatch.setattr(mcp_server, "RemoteBenchmarkClient", UnreachableClient)

    async def scenario() -> None:
        service = make_service()
        failed = await service.start_run(model_name="claude-sonnet-5-5", effort="xhigh")
        assert "start_run again" in failed["error"]
        assert failed["detail"] == {
            "type": "RemoteUnavailableError",
            "message": "The remote runtime is temporarily unavailable.",
            "reason": "upstream_connect_error",
            "request_id": "req-1",
        }
        assert service.run_id is None and "error" in await service.lease_task()

    asyncio.run(scenario())
    policy = created[0]["retry_policy"]
    assert policy.max_attempts >= 5 and policy.initial_backoff_seconds >= 1
    assert created[0]["metadata"]["effort"] == "xhigh"


def test_review_mode_keeps_the_first_report_as_a_draft_for_the_reviewer() -> None:
    async def scenario() -> None:
        service = make_service()
        await service.start_run(OFFLINE_ARENA)
        task_id = (await service.lease_task())["task_id"]
        assert service.tag_task(task_id, "R", review=True)["review"] is True
        assert "error" in service.get_draft(task_id)  # nothing drafted yet

        trigger = service.get_alert(task_id)["alert"]["alert_text"]["trigger_entities"][0]["id"]
        read = {"entity_id": trigger, "reasoning": "inspect the trigger"}
        await service.call(task_id, "get_entity", read)
        evidence = LegitimacyEvidence(
            anchor="entity", entity_id=trigger, property_fields=["signer"]
        )
        drafted = await service.finish(task_id, "benign", "draft", [], [evidence])
        assert drafted["status"] == "draft_saved" and "drafted" in drafted["harness"]["note"]
        row = service.status()["tasks"][0]
        assert row["drafted"] is True and row["finished"] is False and row["runtime_calls"] == 1
        assert "error" in service.tag_task(task_id, "R")  # too late to change the mode

        view = service.get_draft(task_id)
        assert view["draft"]["verdict"] == "benign"
        assert [(r["call"], r["tool"]) for r in view["reads"]] == [(1, "get_entity")]
        assert "reasoning" not in view["reads"][0]["arguments"]
        assert view["reads"][0]["result"]["id"] == trigger
        # The reviewer repeats a read for free and submits its own report.
        again = await service.call(task_id, "get_entity", read)
        assert "cache" in again["harness"]["note"]
        final = await service.finish(task_id, "benign", "reviewed", [], [evidence])
        assert final["status"] == "finished"
        assert final["submitted_report"]["submission"]["reasoning"] == "reviewed"
        assert final["task_result"]["tool_calls"] == 2
        assert "error" in await service.finalize_draft(task_id)

    asyncio.run(scenario())


def test_the_orchestrator_can_submit_a_draft_unchanged() -> None:
    async def scenario() -> None:
        service = make_service()
        await service.start_run(OFFLINE_ARENA)
        task_id = (await service.lease_task())["task_id"]
        service.tag_task(task_id, "R", review=True)
        assert "error" in await service.finalize_draft(task_id)  # no draft yet

        trigger = service.get_alert(task_id)["alert"]["alert_text"]["trigger_entities"][0]["id"]
        evidence = LegitimacyEvidence(
            anchor="entity", entity_id=trigger, property_fields=["signer"]
        )
        await service.finish(task_id, "benign", "draft", [], [evidence])
        finalized = await service.finalize_draft(task_id)
        assert finalized["status"] == "finished" and "submitted_report" not in finalized
        assert service.status()["open_tasks"] == []

    asyncio.run(scenario())


def test_cached_repeats_stay_available_at_the_hard_limit() -> None:
    async def scenario() -> None:
        service = make_service()
        await service.start_run(OFFLINE_ARENA)
        task_id = (await service.lease_task())["task_id"]
        service.tag_task(task_id, "X", soft_budget=1, hard_budget=1)
        trigger = service.get_alert(task_id)["alert"]["alert_text"]["trigger_entities"][0]["id"]
        read = {"entity_id": trigger, "reasoning": "inspect the trigger"}
        assert (await service.call(task_id, "get_entity", read))["status"] == "ok"
        again = await service.call(task_id, "get_entity", read)
        assert "cache" in again["harness"]["note"]
        new = await service.call(task_id, "search", {"query": "other", "reasoning": "r"})
        assert new["status"] == "rejected_locally" and "exhausted" in new["harness"]["error"]

    asyncio.run(scenario())


def test_the_reviewer_gets_at_most_four_new_reads() -> None:
    async def scenario() -> None:
        service = make_service()
        await service.start_run(OFFLINE_ARENA)
        task_id = (await service.lease_task())["task_id"]
        service.tag_task(task_id, "R", review=True)
        trigger = service.get_alert(task_id)["alert"]["alert_text"]["trigger_entities"][0]["id"]
        first = {"query": "first-pass", "reasoning": "r"}
        await service.call(task_id, "search", first)
        evidence = LegitimacyEvidence(
            anchor="entity", entity_id=trigger, property_fields=["signer"]
        )
        await service.finish(task_id, "benign", "draft", [], [evidence])
        read = service.get_draft(task_id)["reads"][0]
        assert read["status"] == "ok" and read["tool"] == "search"

        for query in ("alpha1", "bravo2", "charlie3", "delta4"):
            answer = await service.call(task_id, "search", {"query": query, "reasoning": "r"})
            assert answer["status"] == "ok"
        assert answer["harness"]["budget"]["review_reads_left"] == 0
        capped = await service.call(task_id, "search", {"query": "echo5", "reasoning": "r"})
        assert capped["status"] == "rejected_locally" and "4 new" in capped["harness"]["error"]
        repeat = await service.call(task_id, "search", first)
        assert "cache" in repeat["harness"]["note"]
        final = await service.finish(task_id, "benign", "reviewed", [], [evidence])
        assert final["status"] == "finished" and final["task_result"]["tool_calls"] == 6

    asyncio.run(scenario())


def test_search_anchors_are_shown_unless_switched_off() -> None:
    async def scenario() -> None:
        service = make_service()
        await service.start_run(OFFLINE_ARENA)
        task_id = (await service.lease_task())["task_id"]
        anchors = service.get_alert(task_id)["harness"].get("anchors")
        if anchors is not None:  # mock triggers may carry no user, logon id or host
            assert "note" in anchors and "instructions" in anchors["note"]
        assert service.tag_task(task_id, "X", anchors=False)["anchors"] is False
        assert "anchors" not in service.get_alert(task_id)["harness"]

    asyncio.run(scenario())


class FakeAttachedClient:
    """Stands in for AttachedRemoteClient: serves the rebuilt tasks from the mock scenarios."""

    def __init__(self) -> None:
        self.closed = False

    async def __aenter__(self) -> "FakeAttachedClient":
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.closed = True

    def attach_task(self, task: object) -> MockSession:
        session = MockSession(load_scenario(DEFAULT_SCENARIO_DIR / f"{task.task_id}.json"))
        session.task = task  # the task as rebuilt from its trace
        return session

    async def start_task(self) -> None:
        return None


def traced_service(trace_dir: Path) -> BluesecService:
    return BluesecService(
        settings_loader=lambda: RuntimeSettings(
            scenario_runtime_token="unused-offline", agent_transcript_dir=str(trace_dir)
        )
    )


async def finish_benign(service: BluesecService, task_id: str) -> dict:
    trigger = service.get_alert(task_id)["alert"]["alert_text"]["trigger_entities"][0]["id"]
    evidence = LegitimacyEvidence(anchor="entity", entity_id=trigger, property_fields=["signer"])
    outcome = await service.finish(task_id, "benign", "test", [], [evidence])
    if outcome.get("status") == "review_required":
        outcome = await service.finish(task_id, "benign", "test", [], [evidence])
    return outcome


def test_a_run_survives_an_mcp_server_restart(tmp_path: Path, monkeypatch) -> None:
    fake = FakeAttachedClient()
    monkeypatch.setattr(mcp_server, "attached_client", lambda settings, info: fake)

    async def scenario() -> None:
        first = traced_service(tmp_path)
        run_id = (await first.start_run(OFFLINE_ARENA))["run_id"]
        done = (await first.lease_task())["task_id"]
        assert (await finish_benign(first, done))["status"] == "finished"
        open_id = (await first.lease_task())["task_id"]
        trigger = first.get_alert(open_id)["alert"]["alert_text"]["trigger_entities"][0]["id"]
        read = {"entity_id": trigger, "reasoning": "inspect the trigger"}
        assert (await first.call(open_id, "get_entity", read))["status"] == "ok"
        await first.shutdown()  # the server stops: nothing is closed
        run_dir = next(tmp_path.iterdir())
        info = json.loads((run_dir / "run.json").read_text())
        assert "closed_at" not in info
        offline = await traced_service(tmp_path).resume_run(run_id)
        assert "cannot resume" in offline["error"]
        info["arena"] = "default"  # pretend it was a runtime run
        (run_dir / "run.json").write_text(json.dumps(info))

        second = traced_service(tmp_path)
        resumed = await second.resume_run(run_id[:12])
        assert resumed["run_id"] == run_id and resumed["finished_tasks"] == 1
        assert resumed["open_tasks"] == [{"task_id": open_id, "runtime_calls": 1}]
        assert "error" in await second.resume_run(run_id)  # already attached
        status = second.status()
        assert status["totals"]["leased"] == 2 and status["totals"]["completed"] == 1
        assert second.get_alert(open_id)["harness"]["budget"]["runtime_calls_used"] == 1
        again = await second.call(open_id, "get_entity", read)
        assert "cache" in again["harness"]["note"]  # the earlier read is free
        assert (await finish_benign(second, open_id))["status"] == "finished"
        assert await second.lease_task() == {"queue_exhausted": True}

        await second.shutdown()
        assert not fake.closed  # a restart never closes the runtime run
        third = traced_service(tmp_path)
        await third.resume_run()  # latest run by default
        assert (await third.close_run())["closed"] is True
        assert fake.closed
        assert "closed_at" in json.loads((run_dir / "run.json").read_text())
        assert "was closed" in (await traced_service(tmp_path).resume_run(run_id))["error"]

        kinds = [
            json.loads(line)["kind"]
            for line in (run_dir / f"{open_id}.jsonl").read_text().splitlines()
        ]
        assert kinds.count("task") == 1 and kinds.count("resume") == 2

    asyncio.run(scenario())


def test_a_run_without_traces_is_attached_by_its_complete_id(tmp_path: Path, monkeypatch) -> None:
    fake = FakeAttachedClient()
    monkeypatch.setattr(mcp_server, "attached_client", lambda settings, info: fake)
    run_id = "0a1b2c3d-1111-2222-3333-444455556666"

    async def scenario() -> None:
        service = traced_service(tmp_path)
        assert "complete run id" in (await service.resume_run(run_id[:8]))["error"]
        attached = await service.resume_run(run_id, model_name="claude-sonnet-5-5", effort="xhigh")
        assert attached["run_id"] == run_id
        assert attached["finished_tasks"] == 0 and attached["open_tasks"] == []
        info = json.loads((Path(attached["trace_dir"]) / "run.json").read_text())
        assert info["attached_without_trace"] is True and info["effort"] == "xhigh"
        assert await service.lease_task() == {"queue_exhausted": True}
        assert (await service.close_run())["closed"] is True

    asyncio.run(scenario())
