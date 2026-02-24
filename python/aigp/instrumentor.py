"""
AIGP Instrumentor
=================

The core bridge between AIGP governance events and OpenTelemetry spans.
Handles dual-emit: every governance action produces both an AIGP event
(compliance store) and an OTel span event (observability backend).

AIGP standard event types use UPPER_SNAKE_CASE
(e.g., ``INJECT_SUCCESS``). This SDK also normalizes legacy dotted values
for compatibility. AIGP handles proof, transport, and OTel integration.

Usage:
    from aigp import AIGPInstrumentor

    instrumentor = AIGPInstrumentor(
        agent_id="agent.trading-bot-v2",
        agent_name="Trading Bot",
        org_id="org.finco",
    )

    # Emit any governance event you need:
    event = instrumentor.emit(
        event_type="INJECT_SUCCESS",
        event_category="inject",
        content="Max position: $10M...",
        annotations={"policy_name": "policy.trading-limits", "version": 4},
    )
"""

import logging
import uuid
from typing import Any, Callable, Optional

from opentelemetry import trace, baggage, context
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.trace import StatusCode, Span

from aigp.attributes import AIGPAttributes
from aigp.events import (
    create_aigp_event,
    compute_governance_hash,
    compute_merkle_governance_hash,
)
from aigp.baggage import AIGPBaggage
from aigp.tracestate import AIGPTraceState

logger = logging.getLogger(__name__)


class AIGPInstrumentor:
    """
    Bridges AIGP governance events with OpenTelemetry spans.

    Responsibilities:
    1. Sets AIGP Resource attributes (agent identity — constant per process).
    2. Creates AIGP events and simultaneously emits OTel span events.
    3. Manages Baggage propagation for agent-to-agent governance context.

    AIGP standard event types use UPPER_SNAKE_CASE. Governance platforms
    can also define custom event types. AIGP handles the proof, transport,
    and OTel bridge.
    """

    def __init__(
        self,
        agent_id: str,
        agent_name: str = "",
        org_id: str = "",
        org_name: str = "",
        tracer_name: str = "aigp",
        strict_governance_hash: bool = True,
        event_callback: Optional[Callable[[dict[str, Any]], None]] = None,
        openlineage_callback: Optional[Callable[[dict[str, Any]], None]] = None,
    ):
        """
        Initialize the AIGP instrumentor.

        Args:
            agent_id: AGRN agent identifier (e.g., "agent.trading-bot-v2").
            agent_name: Human-readable agent name.
            org_id: AGRN organization identifier (e.g., "org.finco").
            org_name: Human-readable organization name.
            tracer_name: OTel tracer name for AIGP spans.
            event_callback: Optional callback invoked with each AIGP event dict.
                           Use this to send AIGP events to your AI governance store
                           (message bus, HTTP endpoint, etc.).
            openlineage_callback: Optional callback invoked with an
                           AIGPGovernanceRunFacet dict for each governance event.
                           Use this to send governance facets to your lineage
                           backend (any OpenLineage-compatible store).
        """
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.org_id = org_id
        self.org_name = org_name
        self.tracer_name = tracer_name
        self.strict_governance_hash = strict_governance_hash
        self.event_callback = event_callback
        self.openlineage_callback = openlineage_callback

        self._tracer = trace.get_tracer(tracer_name, "1.0.0")

        # Causal ordering: auto-incrementing sequence per trace
        self._sequence_counters: dict[str, int] = {}
        self._last_event_ids: dict[str, str] = {}

    def _next_sequence(self, trace_id: str) -> int:
        """Increment and return the next sequence number for a given trace_id."""
        current = self._sequence_counters.get(trace_id, 0)
        current += 1
        self._sequence_counters[trace_id] = current
        return current

    def get_resource_attributes(self) -> dict[str, str]:
        """
        Return AIGP resource attributes for OTel Resource initialization.

        These should be set once at process startup:

            resource = Resource.create(instrumentor.get_resource_attributes())
            provider = TracerProvider(resource=resource)
        """
        attrs = {
            AIGPAttributes.AGENT_ID: self.agent_id,
        }
        if self.agent_name:
            attrs[AIGPAttributes.AGENT_NAME] = self.agent_name
        if self.org_id:
            attrs[AIGPAttributes.ORG_ID] = self.org_id
        if self.org_name:
            attrs[AIGPAttributes.ORG_NAME] = self.org_name
        return attrs

    def _get_span_context(self, span: Optional[Span] = None) -> dict[str, str]:
        """Extract OTel span context (trace_id, span_id, trace_flags) from current or given span."""
        if span is None:
            span = trace.get_current_span()

        ctx = span.get_span_context()
        if ctx is None or not ctx.is_valid:
            # Keep events spec-conformant even when no valid OTel span exists.
            return {
                "trace_id": uuid.uuid4().hex,
                "span_id": "",
                "trace_flags": "",
                "parent_span_id": "",
            }

        trace_id = format(ctx.trace_id, "032x")
        span_id = format(ctx.span_id, "016x")
        trace_flags = format(ctx.trace_flags, "02x")

        # Get parent span ID if available
        parent_span_id = ""
        if hasattr(span, "parent") and span.parent is not None:
            parent_span_id = format(span.parent.span_id, "016x")

        return {
            "trace_id": trace_id,
            "span_id": span_id,
            "trace_flags": trace_flags,
            "parent_span_id": parent_span_id,
        }

    def _emit_span_event(
        self,
        span: Span,
        event_name: str,
        aigp_event: dict[str, Any],
    ) -> None:
        """Emit an AIGP governance action as an OTel span event."""
        attrs: dict[str, Any] = {
            AIGPAttributes.EVENT_ID: aigp_event["event_id"],
            AIGPAttributes.EVENT_TYPE: aigp_event["event_type"],
            AIGPAttributes.EVENT_CATEGORY: aigp_event["event_category"],
        }

        # Governance proof
        if aigp_event.get("governance_hash"):
            attrs[AIGPAttributes.GOVERNANCE_HASH] = aigp_event["governance_hash"]
            attrs[AIGPAttributes.GOVERNANCE_HASH_TYPE] = aigp_event.get("hash_type", "sha256")

        # Data classification
        if aigp_event.get("data_classification"):
            attrs[AIGPAttributes.DATA_CLASSIFICATION] = aigp_event["data_classification"]

        # Policy (singular)
        if aigp_event.get("policy_name"):
            attrs[AIGPAttributes.POLICY_NAME] = aigp_event["policy_name"]
        if aigp_event.get("policy_version"):
            attrs[AIGPAttributes.POLICY_VERSION] = aigp_event["policy_version"]

        # Prompt (singular)
        if aigp_event.get("prompt_name"):
            attrs[AIGPAttributes.PROMPT_NAME] = aigp_event["prompt_name"]
        if aigp_event.get("prompt_version"):
            attrs[AIGPAttributes.PROMPT_VERSION] = aigp_event["prompt_version"]

        # Enforcement result (derived from event_type)
        event_type = aigp_event["event_type"]
        event_type_upper = event_type.upper()
        if "DENIED" in event_type_upper or "VIOLATION" in event_type_upper or "BLOCKED" in event_type_upper:
            attrs[AIGPAttributes.ENFORCEMENT_RESULT] = AIGPAttributes.ENFORCEMENT_DENIED
        else:
            attrs[AIGPAttributes.ENFORCEMENT_RESULT] = AIGPAttributes.ENFORCEMENT_ALLOWED

        # Denial/violation details
        if aigp_event.get("severity"):
            attrs[AIGPAttributes.SEVERITY] = aigp_event["severity"]
        if aigp_event.get("violation_type"):
            attrs[AIGPAttributes.VIOLATION_TYPE] = aigp_event["violation_type"]
        if aigp_event.get("denial_reason"):
            attrs[AIGPAttributes.DENIAL_REASON] = aigp_event["denial_reason"]

        # Merkle tree governance
        if aigp_event.get("governance_merkle_tree"):
            attrs[AIGPAttributes.MERKLE_LEAF_COUNT] = aigp_event["governance_merkle_tree"]["leaf_count"]

        # Proof integrity fields
        if aigp_event.get("event_signature"):
            attrs[AIGPAttributes.EVENT_SIGNATURE] = aigp_event["event_signature"]
        if aigp_event.get("signature_key_id"):
            attrs[AIGPAttributes.SIGNATURE_KEY_ID] = aigp_event["signature_key_id"]
        if aigp_event.get("sequence_number"):
            attrs[AIGPAttributes.SEQUENCE_NUMBER] = aigp_event["sequence_number"]
        if aigp_event.get("causality_ref"):
            attrs[AIGPAttributes.CAUSALITY_REF] = aigp_event["causality_ref"]

        span.add_event(event_name, attributes=attrs)

    def _dual_emit(
        self,
        event_name: str,
        aigp_event: dict[str, Any],
        span: Optional[Span] = None,
        causality_ref: str = "",
    ) -> dict[str, Any]:
        """
        Dual-emit: create AIGP event + OTel span event.

        1. Auto-sets sequence_number (monotonic per trace_id).
        2. Auto-sets causality_ref to prior event_id in trace (unless explicitly provided).
        3. Emits OTel span event (observability backend).
        4. Calls event_callback with AIGP event dict (compliance store).
        5. Returns the AIGP event dict.
        """
        if span is None:
            span = trace.get_current_span()

        # Auto-set causal ordering fields only if not explicitly provided.
        trace_id = aigp_event.get("trace_id", "")
        if trace_id:
            current_sequence = int(aigp_event.get("sequence_number", 0) or 0)
            if current_sequence < 1:
                aigp_event["sequence_number"] = self._next_sequence(trace_id)
            if causality_ref:
                aigp_event["causality_ref"] = causality_ref
            elif not aigp_event.get("causality_ref"):
                previous_event_id = self._last_event_ids.get(trace_id, "")
                if previous_event_id:
                    aigp_event["causality_ref"] = previous_event_id

        # Emit OTel span event
        self._emit_span_event(span, event_name, aigp_event)

        # Set span status for denials/violations
        event_type = aigp_event["event_type"]
        event_type_upper = event_type.upper()
        if "DENIED" in event_type_upper or "VIOLATION" in event_type_upper or "BLOCKED" in event_type_upper:
            severity = aigp_event.get("severity", "")
            if severity in ("critical", "high"):
                span.set_status(StatusCode.ERROR, f"AIGP: {event_type}")

        # Emit to AI governance store
        if self.event_callback:
            try:
                self.event_callback(aigp_event)
            except Exception as e:
                logger.error(f"AIGP event callback failed: {e}")

        # Emit to lineage backend (optional triple-emit)
        if self.openlineage_callback:
            try:
                from aigp.openlineage import build_governance_run_facet
                ol_facet = build_governance_run_facet(aigp_event)
                self.openlineage_callback(ol_facet)
            except Exception as e:
                logger.error(f"AIGP OpenLineage callback failed: {e}")

        if trace_id:
            self._last_event_ids[trace_id] = aigp_event["event_id"]

        return aigp_event

    # ===========================================================
    # Core API
    # ===========================================================

    def emit(
        self,
        event_type: str,
        event_category: str = "governance",
        *,
        governance_hash: str = "",
        content: str = "",
        data_classification: str = "",
        # Policy fields (optional — use if your event involves a policy)
        policy_name: str = "",
        policy_version: int = 0,
        policy_id: str = "",
        # Prompt fields (optional — use if your event involves a prompt)
        prompt_name: str = "",
        prompt_version: int = 0,
        prompt_id: str = "",
        # Governance fields
        hash_type: str = "sha256",
        template_rendered: bool = False,
        # Denial fields (optional — use if your event is a denial/violation)
        denial_reason: str = "",
        violation_type: str = "",
        severity: str = "",
        # Request fields
        request_method: str = "",
        request_path: str = "",
        # Memory governance fields
        query_hash: str = "",
        previous_hash: str = "",
        # Causal ordering
        sequence_number: int = 0,
        causality_ref: str = "",
        trace_id: str = "",
        # Strictness override
        allow_empty_governance_hash: bool = False,
        # Annotations — informational context (not hashed)
        annotations: Optional[dict[str, Any]] = None,
        # Merkle tree (for multi-resource proofs)
        resources: Optional[list[tuple[str, str, str]]] = None,
        include_inclusion_proofs: bool = False,
        # OTel span override
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        """
        Emit an AIGP governance event.

        This is the single entry point for all AIGP events. Standard AIGP
        event types use UPPER_SNAKE_CASE (e.g., ``INJECT_SUCCESS``). Legacy
        dotted event types are normalized for compatibility.

        When ``content`` is provided, AIGP computes the governance_hash
        (SHA-256). When ``resources`` is provided with multiple items,
        AIGP computes a Merkle tree proof. By default, a non-empty
        governance_hash is required; missing proof data raises ValueError.

        Args:
            event_type: Event type string. Standard values are UPPER_SNAKE_CASE
                (e.g., "INJECT_SUCCESS", "PROMPT_USED", "TOOL_INVOKED").
            event_category: Free-form category (e.g., "governance", "audit",
                "a2a", "inference"). Default "governance".
            governance_hash: Pre-computed governance hash (optional when
                content/resources are provided).
            content: Governed content — hashed as governance_hash.
            data_classification: Data sensitivity level.
            policy_name: AGRN policy name (optional).
            policy_version: Policy version (optional).
            prompt_name: AGRN prompt name (optional).
            prompt_version: Prompt version (optional).
            denial_reason: Reason for denial (optional).
            violation_type: Type of violation (optional).
            severity: Severity level (optional).
            request_method: HTTP method or protocol (optional).
            request_path: Request path or URI (optional).
            query_hash: Pre-computed hash of a query (optional).
            previous_hash: Pre-computed hash of previous state (optional).
            sequence_number: Explicit sequence number. When <= 0, auto-generated.
            causality_ref: event_id of the preceding event in causal chain.
            trace_id: Optional trace ID override. Use this when your governance
                server already assigned a trace ID and you want all emitted AIGP
                events to use that same ID without requiring an active OTel span.
            allow_empty_governance_hash: Explicit non-strict override. When
                True and strict mode is disabled on the instrumentor, allows
                fallback hashing for metadata-only audit events.
            annotations: Informational context dict (not hashed).
            resources: List of (resource_type, resource_name, content) tuples
                for Merkle tree proof. When provided with >1 resource,
                produces a merkle-sha256 governance hash.
            include_inclusion_proofs: When True and resources has multiple
                items, include `governance_merkle_tree.inclusion_proofs` so
                consumers can verify selective leaf inclusion against the root
                without reconstructing the full resource set.
            span: Optional OTel span override.

        Returns:
            AIGP event dict with governance_hash, trace_id, span_id, etc.
        """
        span_ctx = self._get_span_context(span)
        if trace_id:
            span_ctx["trace_id"] = trace_id.strip()

        # Compute governance hash
        resolved_governance_hash = (governance_hash or "").strip()
        merkle_tree = None
        actual_hash_type = hash_type

        if not resolved_governance_hash:
            if resources:
                resolved_governance_hash, merkle_tree = compute_merkle_governance_hash(
                    resources,
                    include_inclusion_proofs=include_inclusion_proofs,
                )
                if merkle_tree is not None:
                    actual_hash_type = "merkle-sha256"
            elif content:
                resolved_governance_hash = compute_governance_hash(content)

        if not resolved_governance_hash:
            if self.strict_governance_hash and not allow_empty_governance_hash:
                raise ValueError(
                    "governance_hash is required. Provide governance_hash directly or "
                    "provide content/resources so the SDK can compute one."
                )
            # Non-strict fallback: hash stable event metadata instead of emitting empty proof.
            fallback_material = (
                f"{event_type}:{event_category}:{self.agent_id}:{span_ctx['trace_id']}:"
                f"{policy_name}:{prompt_name}:{request_method}:{request_path}"
            )
            resolved_governance_hash = compute_governance_hash(fallback_material)

        aigp_event = create_aigp_event(
            event_type=event_type,
            event_category=event_category,
            agent_id=self.agent_id,
            trace_id=span_ctx["trace_id"],
            governance_hash=resolved_governance_hash,
            hash_type=actual_hash_type,
            span_id=span_ctx["span_id"],
            parent_span_id=span_ctx["parent_span_id"],
            trace_flags=span_ctx["trace_flags"],
            agent_name=self.agent_name,
            org_id=self.org_id,
            org_name=self.org_name,
            policy_id=policy_id,
            policy_name=policy_name,
            policy_version=policy_version,
            prompt_id=prompt_id,
            prompt_name=prompt_name,
            prompt_version=prompt_version,
            data_classification=data_classification,
            template_rendered=template_rendered,
            denial_reason=denial_reason,
            violation_type=violation_type,
            severity=severity,
            request_method=request_method,
            request_path=request_path,
            query_hash=query_hash,
            previous_hash=previous_hash,
            annotations=annotations,
            sequence_number=sequence_number,
            causality_ref=causality_ref,
            governance_merkle_tree=merkle_tree,
        )

        # Use event_type as the OTel span event name
        return self._dual_emit(event_type, aigp_event, span, causality_ref=causality_ref)

    # ===========================================================
    # Backward-compatible convenience helpers
    # ===========================================================

    def inject_success(
        self,
        *,
        policy_name: str,
        policy_version: int = 0,
        content: str = "",
        data_classification: str = "",
        template_rendered: bool = False,
        request_method: str = "",
        request_path: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        return self.emit(
            "INJECT_SUCCESS",
            event_category="inject",
            policy_name=policy_name,
            policy_version=policy_version,
            content=content,
            data_classification=data_classification,
            template_rendered=template_rendered,
            request_method=request_method,
            request_path=request_path,
            annotations=annotations,
            span=span,
        )

    def multi_policy_inject(
        self,
        *,
        policies: list[dict[str, Any]],
        content: str = "",
        data_classification: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        merged_annotations = dict(annotations or {})
        merged_annotations["policies"] = policies
        return self.emit(
            "INJECT_SUCCESS",
            event_category="inject",
            content=content,
            data_classification=data_classification,
            annotations=merged_annotations,
            span=span,
        )

    def prompt_used(
        self,
        *,
        prompt_name: str,
        prompt_version: int = 0,
        content: str = "",
        data_classification: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        return self.emit(
            "PROMPT_USED",
            event_category="prompt",
            prompt_name=prompt_name,
            prompt_version=prompt_version,
            content=content,
            data_classification=data_classification,
            annotations=annotations,
            span=span,
        )

    def policy_violation(
        self,
        *,
        policy_name: str = "",
        policy_version: int = 0,
        violation_type: str = "",
        severity: str = "",
        denial_reason: str = "",
        data_classification: str = "",
        content: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        return self.emit(
            "POLICY_VIOLATION",
            event_category="policy",
            policy_name=policy_name,
            policy_version=policy_version,
            violation_type=violation_type,
            severity=severity,
            denial_reason=denial_reason,
            data_classification=data_classification,
            content=content,
            annotations=annotations,
            span=span,
        )

    def inference_started(
        self,
        *,
        content: str = "",
        data_classification: str = "",
        causality_ref: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        return self.emit(
            "INFERENCE_STARTED",
            event_category="inference",
            content=content,
            data_classification=data_classification,
            causality_ref=causality_ref,
            annotations=annotations,
            span=span,
        )

    def inference_completed(
        self,
        *,
        content: str = "",
        data_classification: str = "",
        causality_ref: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        return self.emit(
            "INFERENCE_COMPLETED",
            event_category="inference",
            content=content,
            data_classification=data_classification,
            causality_ref=causality_ref,
            annotations=annotations,
            span=span,
        )

    def inference_blocked(
        self,
        *,
        denial_reason: str = "",
        severity: str = "",
        violation_type: str = "",
        causality_ref: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        return self.emit(
            "INFERENCE_BLOCKED",
            event_category="inference",
            denial_reason=denial_reason,
            severity=severity,
            violation_type=violation_type,
            causality_ref=causality_ref,
            annotations=annotations,
            span=span,
        )

    def multi_resource_governance_proof(
        self,
        *,
        resources: list[tuple[str, str, str]],
        data_classification: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        return self.emit(
            "GOVERNANCE_PROOF",
            event_category="governance-proof",
            resources=resources,
            data_classification=data_classification,
            annotations=annotations,
            span=span,
        )

    def memory_read(
        self,
        *,
        memory_name: str = "",
        content: str = "",
        query: str = "",
        query_hash: str = "",
        data_classification: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        actual_query_hash = query_hash or (compute_governance_hash(query) if query else "")
        merged_annotations = dict(annotations or {})
        if memory_name:
            merged_annotations["memory_name"] = memory_name
        return self.emit(
            "MEMORY_READ",
            event_category="memory",
            content=content,
            query_hash=actual_query_hash,
            data_classification=data_classification,
            annotations=merged_annotations,
            span=span,
        )

    def memory_written(
        self,
        *,
        memory_name: str = "",
        content: str = "",
        previous_content: str = "",
        previous_hash: str = "",
        data_classification: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        actual_previous_hash = previous_hash or (
            compute_governance_hash(previous_content) if previous_content else ""
        )
        merged_annotations = dict(annotations or {})
        if memory_name:
            merged_annotations["memory_name"] = memory_name
        return self.emit(
            "MEMORY_WRITTEN",
            event_category="memory",
            content=content,
            previous_hash=actual_previous_hash,
            data_classification=data_classification,
            annotations=merged_annotations,
            span=span,
        )

    def tool_invoked(
        self,
        *,
        tool_name: str = "",
        tool_version: int = 0,
        content: str = "",
        data_classification: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        merged_annotations = dict(annotations or {})
        if tool_name:
            merged_annotations["tool_name"] = tool_name
        if tool_version > 0:
            merged_annotations["tool_version"] = tool_version
        return self.emit(
            "TOOL_INVOKED",
            event_category="tool",
            content=content,
            data_classification=data_classification,
            annotations=merged_annotations,
            span=span,
        )

    def tool_denied(
        self,
        *,
        tool_name: str = "",
        denial_reason: str = "",
        data_classification: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        merged_annotations = dict(annotations or {})
        if tool_name:
            merged_annotations["tool_name"] = tool_name
        return self.emit(
            "TOOL_DENIED",
            event_category="tool",
            denial_reason=denial_reason,
            data_classification=data_classification,
            annotations=merged_annotations,
            span=span,
        )

    def a2a_call(
        self,
        *,
        request_method: str = "A2A",
        request_path: str = "",
        content: str = "",
        data_classification: str = "",
        causality_ref: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        return self.emit(
            "A2A_CALL",
            event_category="a2a",
            request_method=request_method,
            request_path=request_path,
            content=content,
            data_classification=data_classification,
            causality_ref=causality_ref,
            annotations=annotations,
            span=span,
        )

    def model_loaded(
        self,
        *,
        model_name: str = "",
        content: str = "",
        data_classification: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        merged_annotations = dict(annotations or {})
        if model_name:
            merged_annotations["model_name"] = model_name
        return self.emit(
            "MODEL_LOADED",
            event_category="model",
            content=content,
            data_classification=data_classification,
            annotations=merged_annotations,
            span=span,
        )

    def model_switched(
        self,
        *,
        model_name: str = "",
        previous_content: str = "",
        previous_hash: str = "",
        content: str = "",
        data_classification: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        merged_annotations = dict(annotations or {})
        if model_name:
            merged_annotations["model_name"] = model_name
        actual_previous_hash = previous_hash or (
            compute_governance_hash(previous_content) if previous_content else ""
        )
        return self.emit(
            "MODEL_SWITCHED",
            event_category="model",
            previous_hash=actual_previous_hash,
            content=content,
            data_classification=data_classification,
            annotations=merged_annotations,
            span=span,
        )

    def unverified_boundary(
        self,
        *,
        target_agent_id: str = "",
        content: str = "",
        data_classification: str = "",
        annotations: Optional[dict[str, Any]] = None,
        span: Optional[Span] = None,
    ) -> dict[str, Any]:
        merged_annotations = dict(annotations or {})
        if target_agent_id:
            merged_annotations["target_agent_id"] = target_agent_id
        return self.emit(
            "UNVERIFIED_BOUNDARY",
            event_category="boundary",
            content=content,
            data_classification=data_classification,
            annotations=merged_annotations,
            span=span,
        )
