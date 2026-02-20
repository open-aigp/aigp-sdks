"""Tests for the golden-path govern(agent).run(...) API."""

import pytest

from aigp import (
    AgentGPConfig,
    AgentGPStartupError,
    govern,
    CrewAIAdapter,
    LangGraphAdapter,
    AutoGenAdapter,
    OpenAIAdapter,
    VertexAdapter,
    BedrockAdapter,
)
from aigp.instrumentor import AIGPInstrumentor


def _mock_transport_factory():
    calls = {"count": 0}

    def _transport(method, path, body, headers, timeout_s):  # noqa: ARG001
        calls["count"] += 1
        if path == "/api/sdk/capabilities":
            return {
                "success": True,
                "data": {
                    "endpoints": ["/api/govern/step", "/api/traces/{trace_id}"],
                    "min_sdk_version": "1.0.0",
                },
                "error": None,
                "trace_id": "",
                "governance": {},
            }
        if path == "/api/govern/step":
            if body.get("dry_run"):
                return {
                    "success": True,
                    "data": {"missing": {"prompts": [], "policies": [], "tools": []}},
                    "error": None,
                    "trace_id": body.get("trace_id", ""),
                    "governance": {},
                }
            return {
                "success": True,
                "data": {
                    "allowed": True,
                    "trace_id": body.get("trace_id", ""),
                    "prompt": {
                        "name": body.get("prompt_name", ""),
                        "version": 3,
                        "content": "system prompt",
                        "allowed": True,
                    },
                    "policy": {
                        "name": body.get("policy_name", ""),
                        "version": 4,
                        "content": "policy text",
                        "allowed": True,
                    },
                    "tools": [{"name": "tool.search", "allowed": True}],
                    "governance_hash": "a" * 64,
                    "coverage": {"prompt": True, "policy": True, "tool": True},
                },
                "error": None,
                "trace_id": body.get("trace_id", ""),
                "governance": {"governance_hash": "a" * 64},
            }
        if path.startswith("/api/traces/"):
            trace_id = path.rsplit("/", 1)[-1]
            return {
                "success": True,
                "data": {"trace_id": trace_id, "events": [], "coverage": {}},
                "error": None,
                "trace_id": trace_id,
                "governance": {},
            }
        raise AssertionError(f"Unexpected path: {path}")

    return _transport, calls


def test_govern_run_full_pipeline():
    transport, calls = _mock_transport_factory()
    cfg = AgentGPConfig(
        base_url="https://agentgp.example",
        api_key="sk-test",
        agent_id="agent.demo",
        debug=True,
        required_prompts=["prompt.support-v1"],
        required_policies=["policy.content-filter"],
        required_tools=["tool.search"],
    )
    runner = govern(cfg, transport=transport)
    result = runner.run(
        {"question": "reset password"},
        prompt_name="prompt.support-v1",
        policy_name="policy.content-filter",
        tools=["tool.search"],
        execute=lambda ctx: {"answer": f"ok:{ctx['trace_id']}"},
    )
    assert result.allowed is True
    assert result.governance_hash == "a" * 64
    assert isinstance(result.output, dict)
    event_types = [e["event_type"] for e in runner.recorder.events]
    assert "AGENT_REGISTERED" in event_types
    assert "PROMPT_USED" in event_types
    assert "INJECT_SUCCESS" in event_types
    assert "TOOL_INVOKED" in event_types
    assert "INFERENCE_STARTED" in event_types
    assert "INFERENCE_COMPLETED" in event_types
    assert "GOVERNANCE_PROOF" in event_types
    assert calls["count"] >= 3


def test_startup_check_missing_required_fields():
    transport, _calls = _mock_transport_factory()
    cfg = AgentGPConfig(base_url="", api_key="", agent_id="")
    runner = govern(cfg, transport=transport)
    with pytest.raises(AgentGPStartupError):
        runner.startup_check()


def test_framework_adapters_share_same_run_api():
    transport, _calls = _mock_transport_factory()
    runner = govern(
        AgentGPConfig(
            base_url="https://agentgp.example",
            api_key="sk-test",
            agent_id="agent.demo",
        ),
        transport=transport,
    )
    adapters = [
        CrewAIAdapter(runner),
        LangGraphAdapter(runner),
        AutoGenAdapter(runner),
        OpenAIAdapter(runner),
        VertexAdapter(runner),
        BedrockAdapter(runner),
    ]
    for adapter in adapters:
        out = adapter.run(
            {"task": "demo"},
            prompt_name="prompt.support-v1",
            policy_name="policy.content-filter",
            tools=["tool.search"],
            execute=lambda ctx: {"integration": ctx["policy"]["name"]},
        )
        assert out.governance_hash == "a" * 64


def test_instrumentor_auto_causality_ref():
    captured = []
    instrumentor = AIGPInstrumentor(
        agent_id="agent.test",
        event_callback=lambda evt: captured.append(evt),
    )
    trace_id = "1" * 32
    e1 = instrumentor.emit("EVENT_ONE", content="a", trace_id=trace_id)
    e2 = instrumentor.emit("EVENT_TWO", content="b", trace_id=trace_id)
    assert e1["causality_ref"] == ""
    assert e2["causality_ref"] == e1["event_id"]


def test_instrumentor_explicit_causality_ref_wins():
    instrumentor = AIGPInstrumentor(agent_id="agent.test")
    trace_id = "2" * 32
    instrumentor.emit("EVENT_ONE", content="a", trace_id=trace_id)
    e2 = instrumentor.emit(
        "EVENT_TWO",
        content="b",
        trace_id=trace_id,
        causality_ref="event.manual-parent",
    )
    assert e2["causality_ref"] == "event.manual-parent"
