"""
Golden path SDK for AgentGP-backed governance.

This module provides a strict, low-friction developer path:

    govern(agent).run(...)

The runner handles:
  register -> prompt pull -> policy inject -> tool enforcement -> audit proof
with automatic AIGP event emission and strict startup validation.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional, Protocol
from urllib import request, error

from aigp.events import compute_governance_hash
from aigp.instrumentor import AIGPInstrumentor

SDK_VERSION = "1.0.0"


class Transport(Protocol):
    """Callable transport used by AgentGPClient for HTTP requests."""

    def __call__(
        self,
        method: str,
        path: str,
        body: Optional[dict[str, Any]],
        headers: dict[str, str],
        timeout_s: float,
    ) -> dict[str, Any]:
        ...


class AgentGPClientError(RuntimeError):
    """Raised when AgentGP API calls fail or return invalid envelopes."""


class AgentGPStartupError(RuntimeError):
    """Raised by strict startup checks."""


@dataclass
class AgentGPConfig:
    """Single config object for govern(agent).run(...) orchestration."""

    base_url: str = ""
    api_key: str = ""
    agent_id: str = ""
    timeout_s: float = 10.0
    strict: bool = True
    fail_open: bool = False
    debug: bool = False
    governance_mode: str = "full"
    sdk_version: str = SDK_VERSION
    required_prompts: list[str] = field(default_factory=list)
    required_policies: list[str] = field(default_factory=list)
    required_tools: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.base_url:
            self.base_url = os.getenv("AGENTGP_BASE_URL", "").strip()
        if not self.api_key:
            self.api_key = os.getenv("AGENTGP_API_KEY", "").strip()
        if not self.agent_id:
            self.agent_id = os.getenv("AGENTGP_AGENT_ID", "").strip()
        self.base_url = self.base_url.rstrip("/")


@dataclass
class GovernRunResult:
    """Result of a governed execution step."""

    trace_id: str
    allowed: bool
    governance_hash: str
    output: Any = None
    denial_reason: str = ""
    policy_decision: dict[str, Any] = field(default_factory=dict)
    prompt: dict[str, Any] = field(default_factory=dict)
    tools: list[dict[str, Any]] = field(default_factory=list)
    coverage: dict[str, Any] = field(default_factory=dict)
    raw_response: dict[str, Any] = field(default_factory=dict)


@dataclass
class LocalRecorder:
    """In-memory debug recorder for raw request/response/event payloads."""

    enabled: bool = False
    requests: list[dict[str, Any]] = field(default_factory=list)
    responses: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)

    def record_request(self, payload: dict[str, Any]) -> None:
        if self.enabled:
            self.requests.append(payload)

    def record_response(self, payload: dict[str, Any]) -> None:
        if self.enabled:
            self.responses.append(payload)

    def record_event(self, payload: dict[str, Any]) -> None:
        if self.enabled:
            self.events.append(payload)


def _semver_tuple(version: str) -> tuple[int, int, int]:
    raw = (version or "").strip().split(".")
    items = [int(v) for v in raw[:3] if v.isdigit()]
    while len(items) < 3:
        items.append(0)
    return (items[0], items[1], items[2])


class AgentGPClient:
    """Minimal strict client for AgentGP golden-path endpoints."""

    def __init__(
        self,
        config: AgentGPConfig,
        *,
        recorder: Optional[LocalRecorder] = None,
        transport: Optional[Transport] = None,
    ):
        self.config = config
        self.recorder = recorder or LocalRecorder(enabled=False)
        self.transport = transport or self._http_transport

    def _http_transport(
        self,
        method: str,
        path: str,
        body: Optional[dict[str, Any]],
        headers: dict[str, str],
        timeout_s: float,
    ) -> dict[str, Any]:
        url = f"{self.config.base_url}{path}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
        req = request.Request(url=url, data=data, headers=headers, method=method)
        try:
            with request.urlopen(req, timeout=timeout_s) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {}
        except error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            raise AgentGPClientError(
                f"HTTP {exc.code} {path}: {body_text[:500]}"
            ) from exc
        except error.URLError as exc:
            raise AgentGPClientError(f"Request failed for {path}: {exc}") from exc

    @staticmethod
    def _normalize_envelope(payload: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise AgentGPClientError("AgentGP response must be a JSON object.")
        if "success" in payload and "data" in payload:
            envelope = {
                "success": bool(payload.get("success")),
                "data": payload.get("data"),
                "error": payload.get("error"),
                "trace_id": payload.get("trace_id", ""),
                "governance": payload.get("governance", {}),
            }
            return envelope
        # Backward-compatible coercion for legacy responses.
        return {
            "success": True,
            "data": payload,
            "error": None,
            "trace_id": payload.get("trace_id", ""),
            "governance": payload.get("governance", {}),
        }

    def _call(
        self,
        method: str,
        path: str,
        *,
        body: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
            "X-AIGP-SDK-Version": self.config.sdk_version,
        }
        request_snapshot = {
            "method": method,
            "path": path,
            "body": body or {},
        }
        self.recorder.record_request(request_snapshot)
        raw = self.transport(method, path, body, headers, self.config.timeout_s)
        envelope = self._normalize_envelope(raw)
        self.recorder.record_response({"path": path, "response": envelope})
        if not envelope["success"]:
            raise AgentGPClientError(
                f"AgentGP request failed for {path}: {envelope.get('error')}"
            )
        return envelope

    def capabilities(self) -> dict[str, Any]:
        return self._call("GET", "/api/sdk/capabilities")

    def govern_step(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._call("POST", "/api/govern/step", body=payload)

    def get_trace(self, trace_id: str) -> dict[str, Any]:
        return self._call("GET", f"/api/traces/{trace_id}")

    def startup_check(
        self,
        *,
        required_prompts: list[str],
        required_policies: list[str],
        required_tools: list[str],
    ) -> None:
        if not self.config.base_url:
            raise AgentGPStartupError("base_url is required.")
        if not self.config.api_key:
            raise AgentGPStartupError("api_key is required.")
        if not self.config.agent_id:
            raise AgentGPStartupError("agent_id is required.")

        caps_env = self.capabilities()
        caps = caps_env.get("data") or {}
        endpoints = set(caps.get("endpoints", []))
        required_endpoints = {"/api/govern/step", "/api/traces/{trace_id}"}
        missing_endpoints = sorted(required_endpoints - endpoints) if endpoints else []
        if missing_endpoints:
            raise AgentGPStartupError(
                f"Missing required endpoints: {', '.join(missing_endpoints)}"
            )

        minimum = caps.get("min_sdk_version", "")
        if minimum and _semver_tuple(self.config.sdk_version) < _semver_tuple(minimum):
            raise AgentGPStartupError(
                f"SDK {self.config.sdk_version} is below server minimum {minimum}."
            )

        if required_prompts or required_policies or required_tools:
            dry_run = self.govern_step(
                {
                    "agent_id": self.config.agent_id,
                    "trace_id": uuid.uuid4().hex,
                    "dry_run": True,
                    "required": {
                        "prompts": required_prompts,
                        "policies": required_policies,
                        "tools": required_tools,
                    },
                    "governance_mode": self.config.governance_mode,
                }
            )
            missing = (dry_run.get("data") or {}).get("missing", {})
            if any(missing.get(k) for k in ("prompts", "policies", "tools")):
                raise AgentGPStartupError(f"Missing governed resources: {missing}")


class GovernRunner:
    """Strict golden-path runner for governed agent execution."""

    def __init__(
        self,
        config: AgentGPConfig,
        *,
        transport: Optional[Transport] = None,
        recorder: Optional[LocalRecorder] = None,
        instrumentor: Optional[AIGPInstrumentor] = None,
    ):
        self.config = config
        self.recorder = recorder or LocalRecorder(enabled=config.debug)
        self.instrumentor = instrumentor or AIGPInstrumentor(
            agent_id=config.agent_id,
            strict_governance_hash=config.strict,
            event_callback=self.recorder.record_event if self.recorder.enabled else None,
        )
        self.client = AgentGPClient(
            config,
            recorder=self.recorder,
            transport=transport,
        )
        self._checked = False
        self._registered = False

    def startup_check(self) -> None:
        if self._checked:
            return
        self.client.startup_check(
            required_prompts=self.config.required_prompts,
            required_policies=self.config.required_policies,
            required_tools=self.config.required_tools,
        )
        self._checked = True
        if not self._registered:
            self.instrumentor.emit(
                "AGENT_REGISTERED",
                event_category="agent",
                content=self.config.agent_id,
            )
            self._registered = True

    def _require_hash(self, governance_hash: str) -> str:
        normalized = (governance_hash or "").strip()
        if normalized:
            return normalized
        if self.config.strict:
            raise AgentGPClientError(
                "governance_hash is required in strict mode."
            )
        return compute_governance_hash(
            f"fallback:{self.config.agent_id}:{uuid.uuid4().hex}"
        )

    def run(
        self,
        input_data: Any,
        *,
        execute: Optional[Callable[[dict[str, Any]], Any]] = None,
        prompt_name: str = "",
        prompt_variables: Optional[dict[str, Any]] = None,
        policy_name: str = "",
        policy_variables: Optional[dict[str, Any]] = None,
        tools: Optional[list[str]] = None,
        tool_input: Optional[dict[str, Any]] = None,
        governance_mode: str = "",
        metadata: Optional[dict[str, Any]] = None,
        trace_id: str = "",
        causality_ref: str = "",
    ) -> GovernRunResult:
        self.startup_check()
        resolved_trace_id = trace_id or uuid.uuid4().hex

        payload = {
            "agent_id": self.config.agent_id,
            "trace_id": resolved_trace_id,
            "input": input_data,
            "prompt_name": prompt_name,
            "prompt_variables": prompt_variables or {},
            "policy_name": policy_name,
            "policy_variables": policy_variables or {},
            "tools": tools or [],
            "tool_input": tool_input or {},
            "governance_mode": governance_mode or self.config.governance_mode,
            "metadata": metadata or {},
        }
        step_env = self.client.govern_step(payload)
        step_data = step_env.get("data") or {}
        response_governance = step_env.get("governance") or {}
        resolved_trace_id = step_env.get("trace_id") or step_data.get("trace_id") or resolved_trace_id

        policy_decision = step_data.get("policy") or {}
        prompt = step_data.get("prompt") or {}
        tool_decisions = step_data.get("tools") or []
        coverage = step_data.get("coverage") or {}

        allowed = bool(step_data.get("allowed", policy_decision.get("allowed", True)))
        denial_reason = (
            str(step_data.get("denial_reason", ""))
            or str(policy_decision.get("reason", ""))
        )
        governance_hash = self._require_hash(
            step_data.get("governance_hash")
            or response_governance.get("governance_hash", "")
        )

        prompt_allowed = bool(prompt.get("allowed", True))
        if prompt_name or prompt.get("name"):
            if prompt_allowed:
                self.instrumentor.emit(
                    "PROMPT_USED",
                    event_category="prompt",
                    trace_id=resolved_trace_id,
                    causality_ref=causality_ref,
                    prompt_name=prompt.get("name") or prompt_name,
                    prompt_version=int(prompt.get("version", 0) or 0),
                    governance_hash=governance_hash,
                    content=str(prompt.get("content", "")),
                )
            else:
                self.instrumentor.emit(
                    "PROMPT_DENIED",
                    event_category="prompt",
                    trace_id=resolved_trace_id,
                    causality_ref=causality_ref,
                    prompt_name=prompt.get("name") or prompt_name,
                    governance_hash=governance_hash,
                    denial_reason=str(prompt.get("reason", "denied")),
                )

        if policy_name or policy_decision.get("name"):
            if allowed:
                self.instrumentor.emit(
                    "INJECT_SUCCESS",
                    event_category="inject",
                    trace_id=resolved_trace_id,
                    policy_name=policy_decision.get("name") or policy_name,
                    policy_version=int(policy_decision.get("version", 0) or 0),
                    governance_hash=governance_hash,
                    content=str(policy_decision.get("content", "")),
                )
            else:
                self.instrumentor.emit(
                    "INJECT_DENIED",
                    event_category="inject",
                    trace_id=resolved_trace_id,
                    policy_name=policy_decision.get("name") or policy_name,
                    governance_hash=governance_hash,
                    denial_reason=denial_reason or "denied",
                )

        for tool_name in tools or []:
            decision = next(
                (item for item in tool_decisions if item.get("name") == tool_name),
                {"name": tool_name, "allowed": True},
            )
            if decision.get("allowed", True):
                self.instrumentor.emit(
                    "TOOL_INVOKED",
                    event_category="tool",
                    trace_id=resolved_trace_id,
                    governance_hash=governance_hash,
                    content=json.dumps(tool_input or {}, sort_keys=True, default=str)[:512],
                    annotations={"tool_name": tool_name},
                )
            else:
                self.instrumentor.emit(
                    "TOOL_DENIED",
                    event_category="tool",
                    trace_id=resolved_trace_id,
                    governance_hash=governance_hash,
                    denial_reason=str(decision.get("reason", "denied")),
                    annotations={"tool_name": tool_name},
                )

        output: Any = None
        if execute is not None and (allowed or self.config.fail_open):
            self.instrumentor.emit(
                "INFERENCE_STARTED",
                event_category="inference",
                trace_id=resolved_trace_id,
                governance_hash=governance_hash,
                content=json.dumps(input_data, sort_keys=True, default=str)[:512],
            )
            output = execute(
                {
                    "input": input_data,
                    "prompt": prompt,
                    "policy": policy_decision,
                    "tools": tool_decisions,
                    "governance_hash": governance_hash,
                    "trace_id": resolved_trace_id,
                }
            )
            self.instrumentor.emit(
                "INFERENCE_COMPLETED",
                event_category="inference",
                trace_id=resolved_trace_id,
                governance_hash=governance_hash,
                content=json.dumps(output, sort_keys=True, default=str)[:512],
            )
        elif not allowed and not self.config.fail_open:
            self.instrumentor.emit(
                "INFERENCE_BLOCKED",
                event_category="inference",
                trace_id=resolved_trace_id,
                governance_hash=governance_hash,
                denial_reason=denial_reason or "policy denied",
            )

        self.audit(
            "GOVERNANCE_PROOF",
            trace_id=resolved_trace_id,
            governance_hash=governance_hash,
            annotations={
                "coverage": coverage,
                "mode": payload["governance_mode"],
            },
        )

        return GovernRunResult(
            trace_id=resolved_trace_id,
            allowed=allowed,
            governance_hash=governance_hash,
            output=output,
            denial_reason=denial_reason,
            policy_decision=policy_decision,
            prompt=prompt,
            tools=tool_decisions,
            coverage=coverage,
            raw_response=step_env,
        )

    def audit(
        self,
        event_type: str,
        *,
        governance_hash: str,
        trace_id: str = "",
        annotations: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        normalized_hash = self._require_hash(governance_hash)
        return self.instrumentor.emit(
            event_type,
            event_category="audit",
            trace_id=trace_id or uuid.uuid4().hex,
            governance_hash=normalized_hash,
            annotations=annotations or {},
        )

    def trace(self, trace_id: str) -> dict[str, Any]:
        """Return normalized trace payload from canonical AgentGP endpoint."""
        return self.client.get_trace(trace_id)


def govern(
    agent: str | AgentGPConfig | GovernRunner,
    *,
    transport: Optional[Transport] = None,
    recorder: Optional[LocalRecorder] = None,
) -> GovernRunner:
    """Build a golden-path runner with the govern(agent).run(...) API."""
    if isinstance(agent, GovernRunner):
        return agent
    if isinstance(agent, str):
        config = AgentGPConfig(agent_id=agent)
    else:
        config = agent
    return GovernRunner(config, transport=transport, recorder=recorder)


class BaseGovernedAdapter:
    """Framework/provider adapter base with a uniform run() API surface."""

    integration: str = "generic"

    def __init__(self, runner: GovernRunner):
        self.runner = runner

    def run(
        self,
        input_data: Any,
        *,
        execute: Optional[Callable[[dict[str, Any]], Any]] = None,
        prompt_name: str = "",
        prompt_variables: Optional[dict[str, Any]] = None,
        policy_name: str = "",
        policy_variables: Optional[dict[str, Any]] = None,
        tools: Optional[list[str]] = None,
        tool_input: Optional[dict[str, Any]] = None,
        metadata: Optional[dict[str, Any]] = None,
        trace_id: str = "",
        causality_ref: str = "",
    ) -> GovernRunResult:
        merged_metadata = {"integration": self.integration, **(metadata or {})}
        return self.runner.run(
            input_data=input_data,
            execute=execute,
            prompt_name=prompt_name,
            prompt_variables=prompt_variables,
            policy_name=policy_name,
            policy_variables=policy_variables,
            tools=tools,
            tool_input=tool_input,
            metadata=merged_metadata,
            trace_id=trace_id,
            causality_ref=causality_ref,
        )


class LangGraphAdapter(BaseGovernedAdapter):
    integration = "langgraph"


class CrewAIAdapter(BaseGovernedAdapter):
    integration = "crewai"


class AutoGenAdapter(BaseGovernedAdapter):
    integration = "autogen"


class OpenAIAdapter(BaseGovernedAdapter):
    integration = "openai"


class VertexAdapter(BaseGovernedAdapter):
    integration = "vertex"


class BedrockAdapter(BaseGovernedAdapter):
    integration = "bedrock"


__all__ = [
    "AgentGPConfig",
    "AgentGPClientError",
    "AgentGPStartupError",
    "GovernRunResult",
    "LocalRecorder",
    "GovernRunner",
    "govern",
    "BaseGovernedAdapter",
    "LangGraphAdapter",
    "CrewAIAdapter",
    "AutoGenAdapter",
    "OpenAIAdapter",
    "VertexAdapter",
    "BedrockAdapter",
]
