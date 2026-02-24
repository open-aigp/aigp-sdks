"""
Tests for aigp.decorators — the vendor-neutral AI Governance decorator framework.
"""

import asyncio
import pytest
from aigp.decorators import (
    GovernanceBackend,
    GovernanceResult,
    GovernanceError,
    GovernedActionContext,
    configure,
    aigp,
    aigp_action,
    a2a_traced,
    audit_action,
    get_backend,
    get_instrumentor,
)


# ── Fixtures ─────────────────────────────────────────────────────────


class MockBackend(GovernanceBackend):
    """A mock GovernanceBackend for testing."""

    def __init__(self, *, allowed=True, denial_reason=None, merkle_root="mock-merkle"):
        self._allowed = allowed
        self._denial_reason = denial_reason
        self._merkle_root = merkle_root
        self._inject_calls = []
        self._audit_calls = []
        self._activity_calls = []
        self._agent_id = "agent.test-bot"

    @property
    def agent_id(self) -> str:
        return self._agent_id

    def inject_governance(self, *, policies=None, prompts=None, tools=None, tool_input=None, trace_id=None):
        self._inject_calls.append({
            "policies": policies,
            "prompts": prompts,
            "tools": tools,
            "tool_input": tool_input,
        })
        resp = {
            "allowed": self._allowed,
            "denial_reason": self._denial_reason,
            "merkle_root": self._merkle_root,
            "policies": {},
            "prompts": {},
            "tools": {},
        }
        if policies:
            for name in policies:
                resp["policies"][name] = {"content": f"rendered-{name}"}
        if prompts:
            for name in prompts:
                resp["prompts"][name] = {"content": f"prompt-{name}"}
        return resp

    def log_activity(self, *, agent_id, trace_id, inputs, outputs, skill, success=True, response_time_ms=0):
        self._activity_calls.append({
            "agent_id": agent_id,
            "skill": skill,
            "success": success,
        })

    def audit(
        self,
        event_type,
        *,
        governance_hash,
        resource_type=None,
        details=None,
        sequence_number=None,
        causality_ref=None,
    ):
        self._audit_calls.append({
            "event_type": event_type,
            "governance_hash": governance_hash,
            "resource_type": resource_type,
            "details": details,
            "sequence_number": sequence_number,
            "causality_ref": causality_ref,
        })


@pytest.fixture(autouse=True)
def reset_globals():
    """Reset global state between tests."""
    import aigp.decorators as dec
    dec._global_backend = None
    dec._global_instrumentor = None
    dec._global_agent_id = ""
    yield
    dec._global_backend = None
    dec._global_instrumentor = None
    dec._global_agent_id = ""


# ── Test: imports ────────────────────────────────────────────────────


class TestImports:
    def test_import_from_aigp(self):
        from aigp import configure, aigp, GovernanceResult
        assert callable(configure)
        assert callable(aigp)
        assert GovernanceResult is not None

    def test_import_governance_error(self):
        from aigp import GovernanceError
        assert issubclass(GovernanceError, Exception)

    def test_import_governance_backend(self):
        from aigp import GovernanceBackend
        assert GovernanceBackend is not None

    def test_version(self):
        import aigp
        assert aigp.__version__ == "1.0.0"


# ── Test: GovernanceBackend Protocol ─────────────────────────────────


class TestGovernanceBackendProtocol:
    def test_is_runtime_checkable(self):
        """GovernanceBackend should be a @runtime_checkable Protocol."""
        from typing import runtime_checkable, Protocol
        assert issubclass(GovernanceBackend, Protocol)
        # MockBackend subclasses Protocol explicitly
        assert isinstance(MockBackend(), GovernanceBackend)

    def test_structural_typing_isinstance(self):
        """A class that implements the right methods should pass isinstance
        check WITHOUT subclassing GovernanceBackend (structural typing)."""

        class DuckBackend:
            """Does NOT subclass GovernanceBackend — pure duck typing."""

            def inject_governance(self, *, policies=None, prompts=None,
                                  tools=None, tool_input=None, trace_id=None):
                return {"allowed": True, "merkle_root": "duck"}

            def log_activity(self, *, agent_id, trace_id, inputs, outputs,
                             skill, success=True, response_time_ms=0):
                pass

            def audit(
                self,
                event_type,
                *,
                governance_hash,
                resource_type=None,
                details=None,
                sequence_number=None,
                causality_ref=None,
            ):
                pass

            @property
            def agent_id(self):
                return "agent.duck"

            def get_trace_id(self):
                return "trace-duck"

        duck = DuckBackend()
        assert isinstance(duck, GovernanceBackend)

    def test_structural_typing_works_with_configure(self):
        """A structurally-compatible backend should work with configure()."""

        class StructuralBackend:
            def inject_governance(self, *, policies=None, prompts=None,
                                  tools=None, tool_input=None, trace_id=None):
                return {
                    "allowed": True,
                    "merkle_root": "struct-merkle",
                    "policies": {k: {"content": f"rendered-{k}"} for k in (policies or {})},
                    "prompts": {},
                    "tools": {},
                }

            def log_activity(self, *, agent_id, trace_id, inputs, outputs,
                             skill, success=True, response_time_ms=0):
                pass

            def audit(
                self,
                event_type,
                *,
                governance_hash,
                resource_type=None,
                details=None,
                sequence_number=None,
                causality_ref=None,
            ):
                pass

            @property
            def agent_id(self):
                return "agent.structural"

            def get_trace_id(self):
                return "trace-structural"

        backend = StructuralBackend()
        configure(backend=backend, agent_id="agent.test")
        assert get_backend() is backend

        @aigp(policy="policy.test-struct")
        def my_func(data, governance=None):
            return governance.merkle_root

        result = my_func({"x": 1})
        assert result == "struct-merkle"


# ── Test: GovernanceResult ───────────────────────────────────────────


class TestGovernanceResult:
    def test_default_allowed(self):
        r = GovernanceResult()
        assert r.allowed is True
        assert r.denied is False
        assert r.denial_reason is None

    def test_denied(self):
        r = GovernanceResult(allowed=False, denial_reason="over limit")
        assert r.denied is True
        assert r.allowed is False
        assert r.denial_reason == "over limit"

    def test_get_rendered(self):
        r = GovernanceResult(policies={"policy.x": {"content": "hello"}})
        assert r.get_rendered("policy.x") == "hello"
        assert r.get_rendered("policy.missing") is None

    def test_get_prompt(self):
        r = GovernanceResult(prompts={"prompt.x": {"content": "hi"}})
        assert r.get_prompt("prompt.x") == "hi"
        assert r.get_prompt("prompt.missing") is None

    def test_is_tool_allowed_true(self):
        r = GovernanceResult(tools={"tool.x": {"allowed": True}})
        assert r.is_tool_allowed("tool.x") is True

    def test_is_tool_allowed_false(self):
        r = GovernanceResult(tools={"tool.x": {"allowed": False}})
        assert r.is_tool_allowed("tool.x") is False

    def test_is_tool_allowed_missing(self):
        r = GovernanceResult()
        assert r.is_tool_allowed("tool.missing") is True

    def test_from_backend_response(self):
        resp = {
            "allowed": True,
            "denial_reason": None,
            "merkle_root": "abc123",
            "policies": {"p": {"content": "x"}},
            "prompts": {},
            "tools": {},
        }
        r = GovernanceResult.from_backend_response(resp)
        assert r.allowed is True
        assert r.merkle_root == "abc123"
        assert r.get_rendered("p") == "x"

    def test_error_fallback(self):
        r = GovernanceResult.error_fallback()
        assert r.allowed is True
        assert r.denied is False
        assert "_aigp_error" in r.raw_response

    def test_from_backend_response_missing_allowed_warns(self, caplog):
        """Backend returns response without 'allowed' — should warn and default to True."""
        import logging
        with caplog.at_level(logging.WARNING, logger="aigp"):
            r = GovernanceResult.from_backend_response({"merkle_root": "abc"})
        assert r.allowed is True
        assert "missing 'allowed'" in caplog.text

    def test_from_backend_response_empty_dict_warns(self, caplog):
        """Backend returns empty dict — should warn and default to allowed."""
        import logging
        with caplog.at_level(logging.WARNING, logger="aigp"):
            r = GovernanceResult.from_backend_response({})
        assert r.allowed is True
        assert "missing 'allowed'" in caplog.text

    def test_from_backend_response_with_allowed_no_warning(self, caplog):
        """Backend returns proper response with 'allowed' — no warning."""
        import logging
        with caplog.at_level(logging.WARNING, logger="aigp"):
            r = GovernanceResult.from_backend_response({"allowed": False, "denial_reason": "denied"})
        assert r.denied is True
        assert "missing 'allowed'" not in caplog.text


# ── Test: GovernanceResponse TypedDict ────────────────────────────────


class TestGovernanceResponse:
    def test_governance_response_importable(self):
        """GovernanceResponse TypedDict is importable from aigp."""
        from aigp import GovernanceResponse
        assert GovernanceResponse is not None

    def test_governance_response_is_typeddict(self):
        """GovernanceResponse is a TypedDict subclass."""
        from aigp.decorators import GovernanceResponse
        assert hasattr(GovernanceResponse, "__annotations__")
        assert "allowed" in GovernanceResponse.__annotations__
        assert "merkle_root" in GovernanceResponse.__annotations__
        assert "policies" in GovernanceResponse.__annotations__
        assert "prompts" in GovernanceResponse.__annotations__
        assert "tools" in GovernanceResponse.__annotations__

    def test_governance_response_total_false(self):
        """GovernanceResponse uses total=False — all fields optional at runtime."""
        from aigp.decorators import GovernanceResponse
        # TypedDict with total=False allows empty dicts
        resp: GovernanceResponse = {"allowed": True}  # type: ignore
        assert resp["allowed"] is True


# ── Test: GovernanceError ────────────────────────────────────────────


class TestGovernanceError:
    def test_basic(self):
        r = GovernanceResult(allowed=False)
        err = GovernanceError("denied", result=r)
        assert str(err) == "denied"
        assert err.result is r

    def test_no_result(self):
        err = GovernanceError("oops")
        assert err.result is None


# ── Test: configure ──────────────────────────────────────────────────


class TestConfigure:
    def test_configure_with_backend(self):
        backend = MockBackend()
        configure(backend=backend, agent_id="agent.test")
        assert get_backend() is backend

    def test_configure_without_backend(self):
        configure(agent_id="agent.test")
        assert get_backend() is None

    def test_agent_id_from_backend(self):
        import aigp.decorators as dec
        backend = MockBackend()
        configure(backend=backend)
        assert dec._global_agent_id == "agent.test-bot"


# ── Test: @aigp decorator ───────────────────────────────────────────


class TestAigpDecorator:
    def test_allowed(self):
        backend = MockBackend(allowed=True, merkle_root="root-123")
        configure(backend=backend, agent_id="agent.test")

        @aigp(policy="policy.limits")
        def my_func(order, governance=None):
            return {"allowed": governance.allowed, "root": governance.merkle_root}

        result = my_func({"amount": 100})
        assert result["allowed"] is True
        assert result["root"] == "root-123"

    def test_denied(self):
        backend = MockBackend(allowed=False, denial_reason="over limit")
        configure(backend=backend, agent_id="agent.test")

        @aigp(policy="policy.limits")
        def my_func(order, governance=None):
            return {"denied": governance.denied, "reason": governance.denial_reason}

        result = my_func({"amount": 999999})
        assert result["denied"] is True
        assert result["reason"] == "over limit"

    def test_deny_raises(self):
        backend = MockBackend(allowed=False, denial_reason="blocked")
        configure(backend=backend, agent_id="agent.test")

        @aigp(policy="policy.limits", deny_raises=True)
        def my_func(order, governance=None):
            return "should not reach"

        with pytest.raises(GovernanceError) as exc_info:
            my_func({"amount": 999999})
        assert "blocked" in str(exc_info.value)
        assert exc_info.value.result is not None
        assert exc_info.value.result.denied is True

    def test_no_backend_allows(self):
        """No backend configured = fail-open with warning."""
        configure(agent_id="agent.test", strict_governance_hash=False)

        @aigp(policy="policy.limits")
        def my_func(order, governance=None):
            return governance.allowed

        result = my_func({"x": 1})
        assert result is True

    def test_multiple_policies(self):
        backend = MockBackend()
        configure(backend=backend, agent_id="agent.test")

        @aigp(policy=["policy.a", "policy.b"])
        def my_func(order, governance=None):
            return governance

        result = my_func({})
        assert result.allowed is True
        assert len(backend._inject_calls) == 1
        call = backend._inject_calls[0]
        assert "policy.a" in call["policies"]
        assert "policy.b" in call["policies"]

    def test_governance_vars(self):
        backend = MockBackend()
        configure(backend=backend, agent_id="agent.test")

        @aigp(policy="policy.limits")
        def my_func(order, governance=None):
            return governance.allowed

        my_func({"x": 1}, governance_vars={"max_amount": 5000})
        call = backend._inject_calls[0]
        assert call["policies"]["policy.limits"]["max_amount"] == 5000

    def test_with_prompt(self):
        backend = MockBackend()
        configure(backend=backend, agent_id="agent.test")

        @aigp(policy="policy.limits", prompt="prompt.instructions")
        def my_func(order, governance=None):
            return governance.get_prompt("prompt.instructions")

        result = my_func({})
        assert result == "prompt-prompt.instructions"

    def test_with_tool(self):
        backend = MockBackend()
        configure(backend=backend, agent_id="agent.test")

        @aigp(policy="policy.limits", tool="tool.stripe-api")
        def my_func(order, governance=None):
            return governance

        result = my_func({})
        call = backend._inject_calls[0]
        assert call["tools"] == ["tool.stripe-api"]

    def test_backend_error_fail_open(self):
        """Backend that throws = fail-open with warning."""

        class BrokenBackend(GovernanceBackend):
            def inject_governance(self, **kwargs):
                raise ConnectionError("cannot reach server")

        configure(backend=BrokenBackend(), agent_id="agent.test", strict_governance_hash=False)

        @aigp(policy="policy.limits")
        def my_func(order, governance=None):
            return governance.allowed

        result = my_func({})
        assert result is True

    def test_fail_closed_on_backend_error(self):
        """fail_closed=True on decorator raises GovernanceError on backend error."""

        class BrokenBackend(GovernanceBackend):
            def inject_governance(self, **kwargs):
                raise ConnectionError("cannot reach server")

        configure(backend=BrokenBackend(), agent_id="agent.test")

        @aigp(policy="policy.limits", fail_closed=True)
        def my_func(order, governance=None):
            return governance.allowed

        with pytest.raises(GovernanceError, match="fail_closed"):
            my_func({})

    def test_fail_closed_on_no_backend(self):
        """fail_closed=True raises GovernanceError when no backend configured."""
        configure(backend=None, agent_id="agent.test", fail_closed=True)

        @aigp(policy="policy.limits")
        def my_func(order, governance=None):
            return governance.allowed

        with pytest.raises(GovernanceError, match="fail_closed"):
            my_func({})

    def test_fail_closed_global_setting(self):
        """configure(fail_closed=True) applies to all @aigp decorators."""

        class BrokenBackend(GovernanceBackend):
            def inject_governance(self, **kwargs):
                raise ConnectionError("down")

        configure(backend=BrokenBackend(), agent_id="agent.test", fail_closed=True)

        @aigp(policy="policy.limits")
        def my_func(order, governance=None):
            return governance.allowed

        with pytest.raises(GovernanceError, match="fail_closed"):
            my_func({})

    def test_fail_closed_per_decorator_overrides_global(self):
        """Per-decorator fail_closed=False overrides global fail_closed=True."""

        class BrokenBackend(GovernanceBackend):
            def inject_governance(self, **kwargs):
                raise ConnectionError("down")

        configure(
            backend=BrokenBackend(),
            agent_id="agent.test",
            fail_closed=True,
            strict_governance_hash=False,
        )

        @aigp(policy="policy.limits", fail_closed=False)
        def my_func(order, governance=None):
            return governance.allowed

        # Should NOT raise — per-decorator override
        result = my_func({})
        assert result is True


# ── Test: @aigp async ────────────────────────────────────────────────


class TestAigpAsync:
    def test_async_allowed(self):
        backend = MockBackend(allowed=True)
        configure(backend=backend, agent_id="agent.test")

        @aigp(policy="policy.limits")
        async def my_func(order, governance=None):
            return governance.allowed

        result = asyncio.run(my_func({"x": 1}))
        assert result is True

    def test_async_deny_raises(self):
        backend = MockBackend(allowed=False, denial_reason="nope")
        configure(backend=backend, agent_id="agent.test")

        @aigp(policy="policy.limits", deny_raises=True)
        async def my_func(order, governance=None):
            return "unreachable"

        with pytest.raises(GovernanceError):
            asyncio.run(my_func({}))


# ── Test: aigp_action context manager ────────────────────────────────


class TestAigpAction:
    def test_basic(self):
        backend = MockBackend(allowed=True, merkle_root="cm-root")
        configure(backend=backend, agent_id="agent.test")

        with aigp_action(policy="policy.limits") as gov:
            assert gov.allowed is True
            assert gov.merkle_root == "cm-root"

    def test_denied(self):
        backend = MockBackend(allowed=False, denial_reason="blocked")
        configure(backend=backend, agent_id="agent.test")

        with aigp_action(policy="policy.limits") as gov:
            assert gov.denied is True
            assert gov.denial_reason == "blocked"

    def test_no_backend_allows(self):
        configure(agent_id="agent.test", strict_governance_hash=False)

        with aigp_action(policy="policy.limits") as gov:
            assert gov.allowed is True

    def test_audits_on_completion(self):
        backend = MockBackend()
        configure(backend=backend, agent_id="agent.test")

        with aigp_action(policy="policy.limits") as gov:
            pass

        assert len(backend._audit_calls) == 1
        assert backend._audit_calls[0]["event_type"] == "governed_action_complete"
        assert backend._audit_calls[0]["governance_hash"] != ""

    def test_audits_on_error(self):
        backend = MockBackend()
        configure(backend=backend, agent_id="agent.test")

        with pytest.raises(ValueError):
            with aigp_action(policy="policy.limits") as gov:
                raise ValueError("boom")

        assert len(backend._audit_calls) == 1
        assert backend._audit_calls[0]["event_type"] == "governed_action_error"
        assert backend._audit_calls[0]["governance_hash"] != ""


# ── Test: @a2a_traced ────────────────────────────────────────────────


class TestA2aTraced:
    def test_logs_activity(self):
        backend = MockBackend()
        configure(backend=backend, agent_id="agent.test")

        @a2a_traced(agent_id="agent.sentiment", skill="analyze")
        def run_sentiment(text):
            return {"score": 0.95}

        result = run_sentiment("great product!")
        assert result == {"score": 0.95}
        assert len(backend._activity_calls) == 1
        assert backend._activity_calls[0]["agent_id"] == "agent.sentiment"
        assert backend._activity_calls[0]["skill"] == "analyze"
        assert backend._activity_calls[0]["success"] is True

    def test_logs_on_error(self):
        backend = MockBackend()
        configure(backend=backend, agent_id="agent.test")

        @a2a_traced(agent_id="agent.bad", skill="fail")
        def bad_func(text):
            raise RuntimeError("oops")

        with pytest.raises(RuntimeError):
            bad_func("input")

        assert len(backend._activity_calls) == 1
        assert backend._activity_calls[0]["success"] is False

    def test_no_backend_no_crash(self):
        configure(agent_id="agent.test")

        @a2a_traced(agent_id="agent.other", skill="do_thing")
        def my_func(x):
            return x + 1

        assert my_func(1) == 2


# ── Test: @audit_action ──────────────────────────────────────────────


class TestAuditAction:
    def test_basic(self):
        backend = MockBackend()
        configure(backend=backend, agent_id="agent.test")

        @audit_action("data_access", resource_type="database")
        def fetch_data(user_id):
            return {"id": user_id}

        result = fetch_data("user-123")
        assert result == {"id": "user-123"}
        assert len(backend._audit_calls) == 1
        assert backend._audit_calls[0]["event_type"] == "data_access"
        assert backend._audit_calls[0]["governance_hash"] != ""
        details = backend._audit_calls[0]["details"]
        assert details["function"] == "fetch_data"
        assert details["success"] is True
        assert details["resource_type"] == "database"

    def test_includes_args(self):
        backend = MockBackend()
        configure(backend=backend, agent_id="agent.test")

        @audit_action("data_access", include_args=True)
        def fetch_data(user_id):
            return {"id": user_id}

        fetch_data("user-123")
        details = backend._audit_calls[0]["details"]
        assert "args" in details

    def test_includes_result(self):
        backend = MockBackend()
        configure(backend=backend, agent_id="agent.test")

        @audit_action("data_access", include_result=True)
        def fetch_data(user_id):
            return {"id": user_id}

        fetch_data("user-123")
        details = backend._audit_calls[0]["details"]
        assert "result" in details

    def test_logs_error(self):
        backend = MockBackend()
        configure(backend=backend, agent_id="agent.test")

        @audit_action("data_access")
        def bad_func():
            raise ValueError("boom")

        with pytest.raises(ValueError):
            bad_func()

        assert len(backend._audit_calls) == 1
        details = backend._audit_calls[0]["details"]
        assert details["success"] is False
        assert details["error"] == "boom"

    def test_no_backend_no_crash(self):
        configure(agent_id="agent.test")

        @audit_action("data_access")
        def my_func():
            return 42

        assert my_func() == 42


# ── Test: GovernedActionContext ───────────────────────────────────────


class TestGovernedActionContext:
    def test_properties(self):
        r = GovernanceResult(
            allowed=True,
            merkle_root="abc",
            policies={"p": {"content": "x"}},
            prompts={"q": {"content": "y"}},
            tools={"t": {"allowed": True}},
        )
        ctx = GovernedActionContext(r)
        assert ctx.allowed is True
        assert ctx.denied is False
        assert ctx.merkle_root == "abc"
        assert ctx.get_rendered("p") == "x"
        assert ctx.get_prompt("q") == "y"
        assert ctx.is_tool_allowed("t") is True

    def test_set_result(self):
        ctx = GovernedActionContext(GovernanceResult())
        ctx.set_result({"output": "data"})
        assert ctx._action_result == {"output": "data"}


# ── Test: Prompt Event Emission ─────────────────────────────────────


class TestEventEmission:
    """@aigp decorator must emit governance events via _emit()."""

    def test_prompt_delivered_emitted_on_allow(self):
        """When allowed, _emit() should be called with governance.prompt.delivered."""
        import aigp.decorators as dec

        emitted = []
        original = dec._emit

        def mock_emit(event_type, **kwargs):
            emitted.append({"event_type": event_type, **kwargs})

        dec._emit = mock_emit
        try:
            backend = MockBackend(allowed=True)
            configure(backend=backend, agent_id="agent.test")

            @aigp(prompt="prompt.banking-system")
            def my_func(data, governance=None):
                return governance.get_prompt("prompt.banking-system")

            result = my_func({})
            assert result == "prompt-prompt.banking-system"
            prompt_events = [e for e in emitted if e["event_type"] == "PROMPT_USED"]
            assert len(prompt_events) == 1
            assert prompt_events[0]["prompt_name"] == "prompt.banking-system"
        finally:
            dec._emit = original

    def test_prompt_denied_emitted_on_deny(self):
        """When denied, _emit() should be called with governance.prompt.denied."""
        import aigp.decorators as dec

        emitted = []
        original = dec._emit

        def mock_emit(event_type, **kwargs):
            emitted.append({"event_type": event_type, **kwargs})

        dec._emit = mock_emit
        try:
            backend = MockBackend(allowed=False, denial_reason="forbidden")
            configure(backend=backend, agent_id="agent.test")

            @aigp(prompt="prompt.banking-system")
            def my_func(data, governance=None):
                return governance.denied

            result = my_func({})
            assert result is True
            prompt_events = [e for e in emitted if e["event_type"] == "PROMPT_DENIED"]
            assert len(prompt_events) == 1
            assert prompt_events[0]["prompt_name"] == "prompt.banking-system"
            assert prompt_events[0]["denial_reason"] == "forbidden"
        finally:
            dec._emit = original

    def test_multiple_prompts_emitted(self):
        """Multiple prompts should each get their own event."""
        import aigp.decorators as dec

        emitted = []
        original = dec._emit

        def mock_emit(event_type, **kwargs):
            emitted.append({"event_type": event_type, **kwargs})

        dec._emit = mock_emit
        try:
            backend = MockBackend(allowed=True)
            configure(backend=backend, agent_id="agent.test")

            @aigp(prompt=["prompt.system", "prompt.context"])
            def my_func(data, governance=None):
                return True

            my_func({})
            prompt_events = [e for e in emitted if e["event_type"] == "PROMPT_USED"]
            assert len(prompt_events) == 2
            names = {e["prompt_name"] for e in prompt_events}
            assert "prompt.system" in names
            assert "prompt.context" in names
        finally:
            dec._emit = original

    def test_all_three_resources(self):
        """Policy + prompt + tool in one decorator, all events emitted."""
        import aigp.decorators as dec

        emitted = []
        original = dec._emit

        def mock_emit(event_type, **kwargs):
            emitted.append({"event_type": event_type, **kwargs})

        dec._emit = mock_emit
        try:
            backend = MockBackend(allowed=True)
            configure(backend=backend, agent_id="agent.test")

            @aigp(
                policy="policy.trading-limits",
                prompt="prompt.trading-system",
                tool="tool.stripe-api",
            )
            def process_trade(order, governance=None):
                return {
                    "policy": governance.get_rendered("policy.trading-limits"),
                    "prompt": governance.get_prompt("prompt.trading-system"),
                    "tool_ok": governance.is_tool_allowed("tool.stripe-api"),
                }

            result = process_trade({"amount": 100})
            assert result["policy"] == "rendered-policy.trading-limits"
            assert result["prompt"] == "prompt-prompt.trading-system"
            assert result["tool_ok"] is True

            policy_events = [e for e in emitted if e["event_type"] == "INJECT_SUCCESS"]
            prompt_events = [e for e in emitted if e["event_type"] == "PROMPT_USED"]
            tool_events = [e for e in emitted if e["event_type"] == "TOOL_INVOKED"]

            assert len(policy_events) == 1
            assert policy_events[0]["policy_name"] == "policy.trading-limits"
            assert len(prompt_events) == 1
            assert prompt_events[0]["prompt_name"] == "prompt.trading-system"
            assert len(tool_events) == 1
            assert tool_events[0]["annotations"]["tool_name"] == "tool.stripe-api"
        finally:
            dec._emit = original


# ── Test: Governance Hash Correctness ────────────────────────────────


class TestGovernanceHashCorrectness:
    """Decorator must pass actual policy content to emit(), not merkle_root."""

    def test_policy_delivered_gets_policy_content(self):
        """_emit() should receive the actual rendered content."""
        import aigp.decorators as dec

        emitted = []
        original = dec._emit

        def mock_emit(event_type, **kwargs):
            emitted.append({"event_type": event_type, **kwargs})

        dec._emit = mock_emit
        try:
            backend = MockBackend(allowed=True, merkle_root="should-NOT-see-this")
            configure(backend=backend, agent_id="agent.test")

            @aigp(policy="policy.limits")
            def my_func(data, governance=None):
                return True

            my_func({})
            policy_events = [e for e in emitted if e["event_type"] == "INJECT_SUCCESS"]
            assert len(policy_events) == 1
            # Content should be the rendered policy, NOT the merkle_root
            assert policy_events[0]["content"] == "rendered-policy.limits"
            assert policy_events[0]["content"] != "should-NOT-see-this"
        finally:
            dec._emit = original

    def test_policy_delivered_empty_content_when_no_policy_data(self):
        """When backend returns no policy content, should pass empty string."""
        import aigp.decorators as dec

        emitted = []
        original = dec._emit

        def mock_emit(event_type, **kwargs):
            emitted.append({"event_type": event_type, **kwargs})

        dec._emit = mock_emit
        try:
            class SparseBackend(MockBackend):
                def inject_governance(self, **kwargs):
                    return {"allowed": True, "merkle_root": "abc", "policies": {}, "prompts": {}, "tools": {}}

            configure(backend=SparseBackend(), agent_id="agent.test")

            @aigp(policy="policy.limits")
            def my_func(data, governance=None):
                return True

            my_func({})
            policy_events = [e for e in emitted if e["event_type"] == "INJECT_SUCCESS"]
            assert len(policy_events) == 1
            assert policy_events[0]["content"] == ""
        finally:
            dec._emit = original


# ── Test: aigp_action prompt events ─────────────────────────────────


class TestAigpActionPromptEvents:
    """aigp_action() context manager must also emit prompt events."""

    def test_aigp_action_emits_prompt_delivered(self):
        import aigp.decorators as dec

        emitted = []
        original = dec._emit

        def mock_emit(event_type, **kwargs):
            emitted.append({"event_type": event_type, **kwargs})

        dec._emit = mock_emit
        try:
            backend = MockBackend(allowed=True)
            configure(backend=backend, agent_id="agent.test")

            with aigp_action(prompt="prompt.system") as gov:
                assert gov.allowed is True

            prompt_events = [e for e in emitted if e["event_type"] == "PROMPT_USED"]
            assert len(prompt_events) == 1
            assert prompt_events[0]["prompt_name"] == "prompt.system"
        finally:
            dec._emit = original

    def test_aigp_action_emits_prompt_denied(self):
        import aigp.decorators as dec

        emitted = []
        original = dec._emit

        def mock_emit(event_type, **kwargs):
            emitted.append({"event_type": event_type, **kwargs})

        dec._emit = mock_emit
        try:
            backend = MockBackend(allowed=False, denial_reason="no access")
            configure(backend=backend, agent_id="agent.test")

            with aigp_action(prompt="prompt.system") as gov:
                assert gov.denied is True

            prompt_events = [e for e in emitted if e["event_type"] == "PROMPT_DENIED"]
            assert len(prompt_events) == 1
            assert prompt_events[0]["prompt_name"] == "prompt.system"
        finally:
            dec._emit = original
