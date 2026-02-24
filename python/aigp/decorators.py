"""
AIGP Decorator Framework — Building Blocks for Governance Platforms
====================================================================

This module provides a vendor-neutral decorator framework that governance
platforms can use to build a decorator-based developer experience on top
of AIGP instrumentation.

**This is NOT the primary AIGP API.** The primary API is ``AIGPInstrumentor``
(see ``aigp.instrumentor``). This module is for governance platform authors
who want to provide ``@aigp()`` style decorators that:

1. Call a ``GovernanceBackend`` to fetch governed resources
2. Use ``AIGPInstrumentor`` to emit AIGP events
3. Inject a ``GovernanceResult`` into the decorated function

Governance platforms implement the ``GovernanceBackend`` protocol, then
call ``configure()`` to wire it up. End-developer code then uses the
decorators without knowing anything about AIGP instrumentation.

Decorators:
  - @aigp: Full governance pipeline — fetch resources, emit events, inject result.
  - @a2a_traced: Auto-emit AIGP A2A_CALL events for multi-agent calls.
  - @audit_action: Auto-log function calls as AIGP audit events.

Context managers:
  - aigp_action: Inline governance for code blocks (same pipeline as @aigp).
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import hashlib
import inspect
import json
import logging
import time
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Generator,
    Optional,
    Protocol,
    TypedDict,
    TypeVar,
    runtime_checkable,
)

logger = logging.getLogger("aigp")

F = TypeVar("F", bound=Callable[..., Any])


# ── GovernanceResponse TypedDict ─────────────────────────────────────


class GovernanceResponse(TypedDict, total=False):
    """
    Typed contract for GovernanceBackend.inject_governance() return value.

    Backends MUST return a dict with at least ``allowed``. All other fields
    have sensible defaults when missing, but well-behaved backends should
    populate them for full AIGP compliance (Merkle proofs, audit events).

    Required:
        allowed: Whether the governed action is permitted.

    Optional:
        denial_reason: Human-readable reason when denied.
        merkle_root: Cryptographic proof hash covering all resources.
        policies: Per-policy rendered content and metadata.
        prompts: Per-prompt rendered content and metadata.
        tools: Per-tool enforcement result.
        governance: Governance metadata (hash, hash_type, resource_count).
        raw_response: Original backend response for debugging.
    """
    allowed: bool
    denial_reason: str | None
    merkle_root: str
    policies: dict[str, dict[str, Any]]
    prompts: dict[str, dict[str, Any]]
    tools: dict[str, dict[str, Any]]
    governance: dict[str, Any]
    raw_response: dict[str, Any]


# ── GovernanceBackend Protocol ────────────────────────────────────────


@runtime_checkable
class GovernanceBackend(Protocol):
    """
    Vendor-neutral protocol for AI Governance backends.

    Any governance server SDK can implement this
    protocol to plug into the @aigp decorator framework. The backend provides
    the governance pipeline (policy retrieval, enforcement, proof computation);
    AIGP handles event emission and the developer-facing API.

    Methods return simple dicts — no vendor-specific models required.

    Because this is a ``Protocol``, implementations do **not** need to
    subclass ``GovernanceBackend`` — structural compatibility is sufficient.
    However, explicit subclassing is also supported and encouraged for
    discoverability.
    """

    def inject_governance(
        self,
        *,
        policies: dict[str, dict[str, Any]] | None = None,
        prompts: list[str] | None = None,
        tools: list[str] | None = None,
        tool_input: dict[str, Any] | None = None,
        trace_id: str | None = None,
    ) -> GovernanceResponse:
        """
        Execute the governance pipeline for policies, prompts, and/or tools.

        The backend implementation decides what "governance" means (template
        rendering, rule enforcement, approval checks, etc.). AIGP only
        requires the response to conform to ``GovernanceResponse`` so it can
        compute proofs and emit events.

        All resource types support multiple items — the backend evaluates them
        atomically and returns a single Merkle root covering everything.

        Args:
            policies: Per-policy variable dicts for rendering/evaluation.
                Keys are policy SRNs (e.g., "policy.trading-limits"),
                values are variable dicts for that policy.
            prompts: List of prompt SRNs (e.g., ["prompt.trading-v3"]).
            tools: List of tool SRNs (e.g., ["tool.stripe-api"]).
            tool_input: Input data for tool governance evaluation.
            trace_id: Optional trace ID for correlation.

        Returns:
            GovernanceResponse dict. ``allowed`` is required; all other
            fields are optional but recommended for full AIGP compliance.
        """
        ...

    def log_activity(
        self,
        *,
        agent_id: str,
        trace_id: str,
        inputs: dict[str, Any],
        outputs: dict[str, Any],
        skill: str,
        success: bool = True,
        response_time_ms: int = 0,
    ) -> None:
        """Log an activity event (A2A call, action, etc.)."""
        ...

    def audit(
        self,
        event_type: str,
        *,
        governance_hash: str,
        resource_type: str | None = None,
        details: dict[str, Any] | None = None,
        sequence_number: int | None = None,
        causality_ref: str | None = None,
    ) -> None:
        """Log a simple audit event."""
        ...

    @property
    def agent_id(self) -> str:
        """Agent identifier for this backend."""
        ...

    def get_trace_id(self) -> str:
        """Generate or return the current trace ID."""
        ...


# ── Governance Result Dataclass ───────────────────────────────────────


@dataclass
class GovernanceResult:
    """
    Vendor-neutral governance result from the @aigp decorator.

    Contains the backend's aggregate decision (allowed/denied), Merkle proof
    root covering all resources, and per-resource content/enforcement data
    for policies, prompts, and tools.

    Returned to decorated functions as the ``governance`` keyword argument.
    Provides a unified API regardless of which backend is in use.
    """

    allowed: bool = True
    denial_reason: str | None = None
    merkle_root: str = ""
    policies: dict[str, dict[str, Any]] = field(default_factory=dict)
    prompts: dict[str, dict[str, Any]] = field(default_factory=dict)
    tools: dict[str, dict[str, Any]] = field(default_factory=dict)
    raw_response: dict[str, Any] = field(default_factory=dict)

    @property
    def denied(self) -> bool:
        return not self.allowed

    def get_rendered(self, policy_name: str) -> str | None:
        """Get the rendered content for a specific policy."""
        p = self.policies.get(policy_name, {})
        return p.get("content")

    def get_prompt(self, prompt_name: str) -> str | None:
        """Get the rendered content for a specific prompt."""
        p = self.prompts.get(prompt_name, {})
        return p.get("content")

    def get_tool(self, tool_name: str) -> dict[str, Any] | None:
        """Get the enforcement result for a specific tool."""
        return self.tools.get(tool_name)

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a specific tool was allowed (True if not in result)."""
        t = self.tools.get(tool_name)
        if t is None:
            return True
        return t.get("allowed", True)

    @classmethod
    def from_backend_response(cls, resp: dict[str, Any]) -> GovernanceResult:
        """Create GovernanceResult from a GovernanceBackend.inject_governance() response.

        The response should conform to ``GovernanceResponse``. If ``allowed``
        is missing, logs a warning and defaults to True (fail-open).
        """
        if "allowed" not in resp:
            logger.warning(
                "GovernanceBackend.inject_governance() response missing 'allowed' "
                "field — defaulting to allowed=True. Backend should return a "
                "GovernanceResponse dict with at least {'allowed': bool}."
            )
        return cls(
            allowed=resp.get("allowed", True),
            denial_reason=resp.get("denial_reason"),
            merkle_root=resp.get("merkle_root", ""),
            policies=resp.get("policies", {}),
            prompts=resp.get("prompts", {}),
            tools=resp.get("tools", {}),
            raw_response=resp.get("raw_response", resp),
        )

    @classmethod
    def error_fallback(cls) -> GovernanceResult:
        """Create an allowed-but-unenforced result for fail-open scenarios."""
        return cls(
            allowed=True,
            raw_response={"_aigp_error": "backend_unavailable"},
        )


class GovernanceError(Exception):
    """Raised when governance enforcement denies an action (deny_raises=True)."""

    def __init__(self, message: str, result: GovernanceResult | None = None):
        super().__init__(message)
        self.result = result


# ── Global State ──────────────────────────────────────────────────────


_global_backend: GovernanceBackend | None = None
_global_instrumentor: Any = None
_global_agent_id: str = ""
_global_fail_closed: bool = False
_global_strict_governance_hash: bool = True


def configure(
    backend: GovernanceBackend | None = None,
    *,
    agent_id: str = "",
    agent_name: str = "",
    org_id: str = "",
    org_name: str = "",
    fail_closed: bool = False,
    strict_governance_hash: bool = True,
    event_callback: Callable[[dict[str, Any]], None] | None = None,
    openlineage_callback: Callable[[dict[str, Any]], None] | None = None,
) -> None:
    """
    Configure the AIGP decorator framework.

    Must be called once at startup before using @aigp or aigp_action().

    Args:
        backend: A GovernanceBackend implementation.
                 If None, decorators emit AIGP events only (no enforcement).
        agent_id: AGRN agent identifier (e.g., "agent.my-bot-v1").
        agent_name: Human-readable agent name.
        org_id: AGRN organization identifier.
        org_name: Human-readable organization name.
        fail_closed: If True, raise GovernanceError when the backend is
                     unavailable or not configured. Default is False (fail-open).
                     Can be overridden per-decorator with @aigp(fail_closed=True).
        strict_governance_hash: If True, fail fast when a governance hash is
                     missing. If False, decorator emissions become best-effort.
        event_callback: Callback invoked with each AIGP event dict.
        openlineage_callback: Callback for OpenLineage facets.
    """
    global _global_backend, _global_instrumentor, _global_agent_id, _global_fail_closed
    global _global_strict_governance_hash

    _global_backend = backend
    _global_agent_id = agent_id or (backend.agent_id if backend else "")
    _global_fail_closed = fail_closed
    _global_strict_governance_hash = strict_governance_hash

    # Auto-init AIGPInstrumentor
    try:
        from aigp.instrumentor import AIGPInstrumentor

        _global_instrumentor = AIGPInstrumentor(
            agent_id=_global_agent_id,
            agent_name=agent_name,
            org_id=org_id,
            org_name=org_name,
            strict_governance_hash=strict_governance_hash,
            event_callback=event_callback,
            openlineage_callback=openlineage_callback,
        )
    except Exception as exc:
        logger.debug("AIGP OTel instrumentor not available: %s", exc)
        _global_instrumentor = None


def get_backend() -> GovernanceBackend | None:
    """Return the configured governance backend, or None."""
    return _global_backend


def get_instrumentor() -> Any:
    """Return the AIGPInstrumentor, or None."""
    return _global_instrumentor


# ── AIGP Event Emission ──────────────────────────────────────────────


def _emit(event_type: str, **kwargs: Any) -> None:
    """Emit a governance event via the global instrumentor (if configured)."""
    if _global_instrumentor:
        try:
            _global_instrumentor.emit(event_type, **kwargs)
        except Exception:
            if _global_strict_governance_hash:
                raise


def _enforce_injected_governance_hash(result: GovernanceResult) -> None:
    """Fail fast when strict mode requires a governance hash from injection."""
    if not _global_strict_governance_hash:
        return
    if (result.merkle_root or "").strip():
        return
    raise GovernanceError(
        "Governance backend response missing required merkle_root/governance_hash in strict mode.",
        result=result,
    )


# ── @aigp — AI Governance Proof ───────────────────────────────────────


def aigp(
    policy: str | list[str] | None = None,
    *,
    policies: dict[str, dict[str, Any]] | None = None,
    prompt: str | list[str] | None = None,
    tool: str | list[str] | None = None,
    deny_raises: bool = False,
    fail_closed: bool | None = None,
) -> Callable[[F], F]:
    """
    AI Governance decorator — the core AIGP orchestration point.

    Orchestrates the full governance lifecycle for an agent function:

    1. **Fetch**: Calls ``backend.inject_governance()`` to retrieve governed
       policies, prompts, tool permissions, and enforcement decisions.
    2. **Proof**: The backend returns a single Merkle root proving what was
       delivered (all policies + prompts + tools in one atomic proof).
    3. **Events**: Emits AIGP events via ``instrumentor.emit()`` for compliance audit.

    The ``GovernanceResult`` is injected as the ``governance`` keyword argument.

    Args:
        policy: Policy SRN(s). Single string or list of SRNs.
            Use ``policies`` dict for per-policy variables.
        policies: Per-policy variable dicts (e.g.,
            ``{"policy.trading-limits": {"amount": 5000}}``).
            Merged with ``policy`` if both provided.
        prompt: Prompt SRN(s). Single string or list of SRNs.
        tool: Tool SRN(s). Single string or list of SRNs.
        deny_raises: If True, raise GovernanceError on denial.
        fail_closed: If True, raise GovernanceError when the backend is
            unavailable or not configured (instead of allowing the action).
            If None (default), uses the global ``configure(fail_closed=...)``
            setting. Set explicitly to override per-decorator.

    Examples:
        @aigp(policy="policy.trading-limits")
        def process_trade(order: dict, governance: GovernanceResult = None):
            if governance.denied:
                return {"error": governance.denial_reason}
            return execute(order)

        # Multiple resources — one atomic call, one Merkle proof:
        @aigp(
            policy=["policy.trading-limits", "policy.risk-controls"],
            prompt="prompt.trader-instructions-v3",
            tool="tool.bloomberg-api",
        )
        def complex_trade(order: dict, governance: GovernanceResult = None):
            instructions = governance.get_prompt("prompt.trader-instructions-v3")
            if not governance.is_tool_allowed("tool.bloomberg-api"):
                return {"error": "bloomberg API not permitted"}
            return execute(order, instructions)

        # Dynamic variables at call time:
        process_trade(order, governance_vars={"amount": 5000})
    """

    def decorator(func: F) -> F:
        is_async = inspect.iscoroutinefunction(func)

        # Normalize resource lists at decoration time
        _policy_list: list[str] = _to_list(policy)
        _prompt_list: list[str] = _to_list(prompt)
        _tool_list: list[str] = _to_list(tool)

        def _do_inject(
            extra_vars: dict[str, Any] | None = None,
            tool_input: dict[str, Any] | None = None,
        ) -> GovernanceResult:
            # Build policies dict: merge policy list + policies dict + extra_vars
            pv: dict[str, dict[str, Any]] = dict(policies or {})
            for p in _policy_list:
                if p not in pv:
                    pv[p] = {}
            if extra_vars:
                for key in pv:
                    pv[key] = {**pv[key], **extra_vars}

            # Resolve fail_closed: per-decorator overrides global
            _fc = fail_closed if fail_closed is not None else _global_fail_closed

            backend = get_backend()
            if backend is not None:
                try:
                    resp = backend.inject_governance(
                        policies=pv or None,
                        prompts=_prompt_list or None,
                        tools=_tool_list or None,
                        tool_input=tool_input,
                    )
                    result = GovernanceResult.from_backend_response(resp)
                except Exception as exc:
                    if _fc:
                        raise GovernanceError(
                            f"Governance backend unavailable (fail_closed=True): {exc}",
                            result=GovernanceResult.error_fallback(),
                        ) from exc
                    logger.warning(
                        "AIGP governance backend unavailable — allowing action "
                        "without enforcement. Error: %s", exc,
                    )
                    result = GovernanceResult.error_fallback()
            else:
                # No backend configured
                if _fc:
                    raise GovernanceError(
                        "Governance backend not configured (fail_closed=True). "
                        "Call aigp.configure(backend=...) first.",
                        result=GovernanceResult.error_fallback(),
                    )
                logger.warning(
                    "AIGP governance backend not configured — allowing action "
                    "without enforcement. Call aigp.configure(backend=...) first.",
                )
                result = GovernanceResult.error_fallback()

            _enforce_injected_governance_hash(result)

            # Emit AIGP events — policies
            for p in _policy_list:
                policy_data = result.policies.get(p, {})
                if result.allowed:
                    _emit(
                        "INJECT_SUCCESS",
                        event_category="inject",
                        governance_hash=result.merkle_root,
                        policy_name=p,
                        policy_version=policy_data.get("version", 0),
                        content=policy_data.get("content", ""),
                    )
                else:
                    _emit(
                        "INJECT_DENIED",
                        event_category="inject",
                        governance_hash=result.merkle_root,
                        policy_name=p,
                        denial_reason=result.denial_reason or "denied",
                    )

            # Emit AIGP events — prompts
            for pr in _prompt_list:
                prompt_data = result.prompts.get(pr, {})
                if result.allowed:
                    _emit(
                        "PROMPT_USED",
                        event_category="prompt",
                        governance_hash=result.merkle_root,
                        prompt_name=pr,
                        prompt_version=prompt_data.get("version", 0),
                        content=prompt_data.get("content", ""),
                    )
                else:
                    _emit(
                        "PROMPT_DENIED",
                        event_category="prompt",
                        governance_hash=result.merkle_root,
                        prompt_name=pr,
                        denial_reason=result.denial_reason or "denied",
                    )

            # Emit AIGP events — tools
            for t in _tool_list:
                if result.is_tool_allowed(t):
                    _emit(
                        "TOOL_INVOKED",
                        event_category="tool",
                        governance_hash=result.merkle_root,
                        content=json.dumps(tool_input or {}, sort_keys=True, default=str)[:512],
                        annotations={"tool_name": t},
                    )
                else:
                    tool_data = result.get_tool(t)
                    _emit(
                        "TOOL_DENIED",
                        event_category="tool",
                        governance_hash=result.merkle_root,
                        denial_reason=(tool_data or {}).get("message", "denied"),
                        annotations={"tool_name": t},
                    )

            return result

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            extra_vars = kwargs.pop("governance_vars", None)
            tool_input = kwargs.pop("tool_input", None)
            result = _do_inject(extra_vars, tool_input)
            if deny_raises and result.denied:
                raise GovernanceError(
                    f"Governance denied: {result.denial_reason}", result=result
                )
            kwargs["governance"] = result
            return await func(*args, **kwargs)

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            extra_vars = kwargs.pop("governance_vars", None)
            tool_input = kwargs.pop("tool_input", None)
            result = _do_inject(extra_vars, tool_input)
            if deny_raises and result.denied:
                raise GovernanceError(
                    f"Governance denied: {result.denial_reason}", result=result
                )
            kwargs["governance"] = result
            return func(*args, **kwargs)

        return async_wrapper if is_async else sync_wrapper  # type: ignore

    return decorator


# ── @a2a_traced — MAS Sub-Agent Tracing ───────────────────────────────


def a2a_traced(
    agent_id: str | None = None,
    skill: str | None = None,
    *,
    source_agent_id: str | None = None,
) -> Callable[[F], F]:
    """
    Auto-emit AIGP events for multi-agent sub-agent calls.

    Records input/output hashes, timing, and success/failure.
    When a GovernanceBackend is configured, also logs to the backend's audit stream.

    Args:
        agent_id: Target agent ID. If None, derives from function name.
        skill: Skill name. If None, uses function name.
        source_agent_id: Source agent ID.

    Example:
        @a2a_traced(agent_id="agent.sentiment-analyzer")
        def run_sentiment(text: str) -> dict:
            return analyze(text)
    """

    def decorator(func: F) -> F:
        is_async = inspect.iscoroutinefunction(func)
        target = agent_id or f"agent.{func.__name__}"
        skill_name = skill or func.__name__

        def _log_a2a(input_val: Any, result: Any, success: bool, elapsed_ms: int) -> None:
            # Emit AIGP A2A event
            _emit(
                "A2A_CALL",
                event_category="a2a",
                request_method="A2A",
                request_path=f"agent://{target}/{skill_name}",
                content=_hash_value(input_val),
            )

            # Log to backend audit if available
            try:
                backend = _global_backend
                if backend is None:
                    return
                backend.log_activity(
                    agent_id=target,
                    trace_id=backend.get_trace_id(),
                    inputs={"input_hash": _hash_value(input_val), "skill": skill_name},
                    outputs={
                        "output_hash": _hash_value(result) if result is not None else "",
                        "success": success,
                    },
                    skill=skill_name,
                    success=success,
                    response_time_ms=elapsed_ms,
                )
            except Exception:
                pass

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            input_val = args[0] if args else kwargs
            t0 = time.monotonic()
            try:
                result = await func(*args, **kwargs)
                _log_a2a(input_val, result, True, int((time.monotonic() - t0) * 1000))
                return result
            except Exception as e:
                _log_a2a(input_val, {"error": str(e)}, False, int((time.monotonic() - t0) * 1000))
                raise

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            input_val = args[0] if args else kwargs
            t0 = time.monotonic()
            try:
                result = func(*args, **kwargs)
                _log_a2a(input_val, result, True, int((time.monotonic() - t0) * 1000))
                return result
            except Exception as e:
                _log_a2a(input_val, {"error": str(e)}, False, int((time.monotonic() - t0) * 1000))
                raise

        return async_wrapper if is_async else sync_wrapper  # type: ignore

    return decorator


# ── @audit_action — Simple AIGP Audit Logging ─────────────────────────


def audit_action(
    event_type: str,
    *,
    resource_type: str | None = None,
    include_args: bool = False,
    include_result: bool = False,
) -> Callable[[F], F]:
    """
    Decorator to automatically log function calls as AIGP audit events.

    When a GovernanceBackend is configured, also logs to the backend.

    Args:
        event_type: Type of audit event.
        resource_type: Resource type for the audit event.
        include_args: Include function arguments in audit.
        include_result: Include function result in audit.

    Example:
        @audit_action("inference", resource_type="llm")
        def generate_response(prompt: str) -> str:
            return llm.generate(prompt)
    """

    def decorator(func: F) -> F:
        is_async = inspect.iscoroutinefunction(func)

        def _audit(details: dict[str, Any]) -> None:
            backend = get_backend()
            if backend is not None:
                try:
                    backend.audit(
                        event_type,
                        governance_hash=_hash_value(details),
                        details=details,
                    )
                except Exception:
                    if _global_strict_governance_hash:
                        raise

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            details: dict[str, Any] = {"function": func.__name__}
            if resource_type:
                details["resource_type"] = resource_type
            if include_args:
                details["args"] = _serialize_args(args, kwargs)
            t0 = time.monotonic()
            try:
                result = await func(*args, **kwargs)
                details["duration_ms"] = int((time.monotonic() - t0) * 1000)
                details["success"] = True
                if include_result:
                    details["result"] = _safe_repr(result)
                _audit(details)
                return result
            except Exception as e:
                details["success"] = False
                details["error"] = str(e)
                _audit(details)
                raise

        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            details: dict[str, Any] = {"function": func.__name__}
            if resource_type:
                details["resource_type"] = resource_type
            if include_args:
                details["args"] = _serialize_args(args, kwargs)
            t0 = time.monotonic()
            try:
                result = func(*args, **kwargs)
                details["duration_ms"] = int((time.monotonic() - t0) * 1000)
                details["success"] = True
                if include_result:
                    details["result"] = _safe_repr(result)
                _audit(details)
                return result
            except Exception as e:
                details["success"] = False
                details["error"] = str(e)
                _audit(details)
                raise

        return async_wrapper if is_async else sync_wrapper  # type: ignore

    return decorator


# ── aigp_action() — Inline AI Governance Context Manager ──────────────


class GovernedActionContext:
    """Context returned by aigp_action(). Provides governance result + proof."""

    def __init__(self, result: GovernanceResult):
        self.result = result
        self._action_result: Any = None

    @property
    def allowed(self) -> bool:
        return self.result.allowed

    @property
    def denied(self) -> bool:
        return self.result.denied

    @property
    def denial_reason(self) -> str | None:
        return self.result.denial_reason

    @property
    def merkle_root(self) -> str:
        return self.result.merkle_root

    def get_rendered(self, policy_name: str) -> str | None:
        return self.result.get_rendered(policy_name)

    def get_prompt(self, prompt_name: str) -> str | None:
        return self.result.get_prompt(prompt_name)

    def get_tool(self, tool_name: str) -> dict[str, Any] | None:
        return self.result.get_tool(tool_name)

    def is_tool_allowed(self, tool_name: str) -> bool:
        return self.result.is_tool_allowed(tool_name)

    def set_result(self, result: Any) -> None:
        self._action_result = result


@contextlib.contextmanager
def aigp_action(
    policy: str | list[str] | None = None,
    *,
    policies: dict[str, dict[str, Any]] | None = None,
    prompt: str | list[str] | None = None,
    tool: str | list[str] | None = None,
    tool_input: dict[str, Any] | None = None,
    fail_closed: bool | None = None,
) -> Generator[GovernedActionContext, None, None]:
    """
    Context manager for inline AI Governance (same pipeline as @aigp).

    Args:
        fail_closed: If True, raise GovernanceError when the backend is
            unavailable. If None, uses the global configure() setting.

    Example:
        with aigp_action(
            policy="policy.trading-limits",
            policies={"policy.trading-limits": {"amount": 5000}},
            tool="tool.bloomberg-api",
        ) as gov:
            if gov.denied:
                print(f"Blocked: {gov.denial_reason}")
            else:
                execute_trade(gov.get_rendered("policy.trading-limits"))
    """
    _policy_list = _to_list(policy)
    _prompt_list = _to_list(prompt)
    _tool_list = _to_list(tool)
    _fc = fail_closed if fail_closed is not None else _global_fail_closed

    # Build policies dict
    pv: dict[str, dict[str, Any]] = dict(policies or {})
    for p in _policy_list:
        if p not in pv:
            pv[p] = {}

    backend = get_backend()
    if backend is not None:
        try:
            resp = backend.inject_governance(
                policies=pv or None,
                prompts=_prompt_list or None,
                tools=_tool_list or None,
                tool_input=tool_input,
            )
            result = GovernanceResult.from_backend_response(resp)
        except Exception as exc:
            if _fc:
                raise GovernanceError(
                    f"Governance backend unavailable (fail_closed=True): {exc}",
                    result=GovernanceResult.error_fallback(),
                ) from exc
            logger.warning(
                "AIGP governance backend unavailable — allowing action "
                "without enforcement. Error: %s", exc,
            )
            result = GovernanceResult.error_fallback()
    else:
        if _fc:
            raise GovernanceError(
                "Governance backend not configured (fail_closed=True). "
                "Call aigp.configure(backend=...) first.",
                result=GovernanceResult.error_fallback(),
            )
        logger.warning(
            "AIGP governance backend not configured — allowing action "
            "without enforcement. Call aigp.configure(backend=...) first.",
        )
        result = GovernanceResult.error_fallback()

    _enforce_injected_governance_hash(result)

    # Emit AIGP events — policies
    for p in _policy_list:
        policy_data = result.policies.get(p, {})
        if result.allowed:
            _emit(
                "INJECT_SUCCESS",
                event_category="inject",
                governance_hash=result.merkle_root,
                policy_name=p,
                policy_version=policy_data.get("version", 0),
                content=policy_data.get("content", ""),
            )
        else:
            _emit(
                "INJECT_DENIED",
                event_category="inject",
                governance_hash=result.merkle_root,
                policy_name=p,
                denial_reason=result.denial_reason or "denied",
            )

    # Emit AIGP events — prompts
    for pr in _prompt_list:
        prompt_data = result.prompts.get(pr, {})
        if result.allowed:
            _emit(
                "PROMPT_USED",
                event_category="prompt",
                governance_hash=result.merkle_root,
                prompt_name=pr,
                prompt_version=prompt_data.get("version", 0),
                content=prompt_data.get("content", ""),
            )
        else:
            _emit(
                "PROMPT_DENIED",
                event_category="prompt",
                governance_hash=result.merkle_root,
                prompt_name=pr,
                denial_reason=result.denial_reason or "denied",
            )

    # Emit AIGP events — tools
    for t in _tool_list:
        if result.is_tool_allowed(t):
            _emit(
                "TOOL_INVOKED",
                event_category="tool",
                governance_hash=result.merkle_root,
                content=json.dumps(tool_input or {}, sort_keys=True, default=str)[:512],
                annotations={"tool_name": t},
            )
        else:
            tool_data = result.get_tool(t)
            _emit(
                "TOOL_DENIED",
                event_category="tool",
                governance_hash=result.merkle_root,
                denial_reason=(tool_data or {}).get("message", "denied"),
                annotations={"tool_name": t},
            )

    ctx = GovernedActionContext(result)
    t0 = time.monotonic()

    try:
        yield ctx
    except Exception as e:
        elapsed = int((time.monotonic() - t0) * 1000)
        if backend:
            try:
                backend.audit(
                    "governed_action_error",
                    governance_hash=result.merkle_root,
                    details={
                        "policies": _policy_list,
                        "prompts": _prompt_list,
                        "tools": _tool_list,
                        "error": str(e),
                        "duration_ms": elapsed,
                        "allowed": result.allowed,
                    },
                )
            except Exception:
                if _global_strict_governance_hash:
                    raise
        raise
    else:
        elapsed = int((time.monotonic() - t0) * 1000)
        if backend:
            try:
                backend.audit(
                    "governed_action_complete",
                    governance_hash=result.merkle_root,
                    details={
                        "policies": _policy_list,
                        "prompts": _prompt_list,
                        "tools": _tool_list,
                        "allowed": result.allowed,
                        "merkle_root": result.merkle_root,
                        "duration_ms": elapsed,
                    },
                )
            except Exception:
                if _global_strict_governance_hash:
                    raise


# ── Helpers ───────────────────────────────────────────────────────────


def _to_list(val: str | list[str] | None) -> list[str]:
    """Normalize a single string, list of strings, or None to a list."""
    if val is None:
        return []
    if isinstance(val, str):
        return [val]
    return list(val)


def _hash_value(val: Any) -> str:
    """SHA-256 hash of a value (string, bytes, or JSON-serializable)."""
    if isinstance(val, str):
        return hashlib.sha256(val.encode("utf-8")).hexdigest()
    if isinstance(val, bytes):
        return hashlib.sha256(val).hexdigest()
    return hashlib.sha256(
        json.dumps(val, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _serialize_args(args: tuple, kwargs: dict) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if args:
        result["positional"] = [_safe_repr(a) for a in args]
    if kwargs:
        result["keyword"] = {k: _safe_repr(v) for k, v in kwargs.items()}
    return result


def _safe_repr(obj: Any, max_length: int = 200) -> str:
    try:
        s = repr(obj)
        return s[:max_length - 3] + "..." if len(s) > max_length else s
    except Exception:
        return f"<{type(obj).__name__}>"
