"""
AIGP — AI Governance Proof
==========================

Open instrumentation standard for proving your AI agents used the
approved policies, prompts, and tools — every single time.

What OTel is for observability, AIGP is for AI Governance.

Quick Start::

    from aigp import AIGPInstrumentor

    # Initialize the instrumentor (like OTel TracerProvider)
    instrumentor = AIGPInstrumentor(
        agent_id="agent.trading-agent-v1",
    )

    # Emit governance events using AIGP's recommended RESOURCE_ACTION convention
    instrumentor.emit(
        "INJECT_SUCCESS",
        policy_name="policy.trading-limits",
        content="Max position $10M...",
    )
    instrumentor.emit(
        "PROMPT_USED",
        prompt_name="prompt.trading-system",
        content="You are a trading assistant...",
    )

What AIGP does:
  - Ships 31 standard event types across 15 categories, extensible by design
  - Proves governance was delivered (Merkle proofs, cryptographic hashes)
  - Signs events with JWS ES256 for tamper-proof audit trails
  - Transports via OpenTelemetry, CloudEvents, and OpenLineage
  - Stays vendor-neutral — any governance platform can emit AIGP events

What AIGP does NOT do:
  - Dictate how governance works — that's the governance platform's job
  - Provide policies, prompts, or tools — those come from your governance server
  - Execute governance decisions — AIGP captures proof of what happened

Governance platforms use AIGP internally to emit events,
just like web frameworks use OTel internally to emit spans.

Website: https://open-aigp.org
GitHub:  https://github.com/open-aigp/aigp
"""

# ── Instrumentation: the core AIGP API ──────────────────────────────

from aigp.instrumentor import AIGPInstrumentor

# ── Events & Proof ────────────────────────────────────────────────────

from aigp.events import (
    create_aigp_event,
    compute_governance_hash,
    compute_leaf_hash,
    compute_merkle_governance_hash,
    build_inclusion_proofs,
    verify_inclusion_proof,
    sign_event,
    verify_event_signature,
)
from aigp.signer import (
    EventSigner,
    ES256PrivateKeySigner,
    sign_event_with_signer,
)
from aigp.reliability import (
    RetryPolicy,
    ReliableEmitter,
)

# ── Context propagation (OTel integration) ────────────────────────────

from aigp.attributes import AIGPAttributes
from aigp.baggage import AIGPBaggage
from aigp.tracestate import AIGPTraceState

# ── OpenLineage integration ───────────────────────────────────────────

from aigp.openlineage import (
    build_governance_run_facet,
    build_resource_input_facets,
    build_openlineage_run_event,
)

# ── CloudEvents transport ─────────────────────────────────────────────

from aigp.cloudevents import (
    wrap_as_cloudevent,
    unwrap_from_cloudevent,
    build_ce_headers,
    ce_type_from_event_type,
    event_type_from_ce_type,
)

# ── Decorator framework (for governance platforms to use) ─────────────
# These are building blocks for governance platforms that
# want to provide a decorator-based developer experience. They are NOT
# the primary AIGP API — AIGPInstrumentor is.

from aigp.decorators import (
    configure,
    aigp,
    aigp_action,
    a2a_traced,
    audit_action,
    GovernanceBackend,
    GovernanceResponse,
    GovernanceResult,
    GovernanceError,
    GovernedActionContext,
    get_backend,
    get_instrumentor,
)
from aigp.golden_path import (
    AgentGPConfig,
    AgentGPClientError,
    AgentGPStartupError,
    GovernRunResult,
    LocalRecorder,
    GovernRunner,
    govern,
    BaseGovernedAdapter,
    LangGraphAdapter,
    CrewAIAdapter,
    AutoGenAdapter,
    OpenAIAdapter,
    VertexAdapter,
    BedrockAdapter,
)

__version__ = "1.0.0"
__all__ = [
    # ── Instrumentation (primary API) ──
    "AIGPInstrumentor",
    # ── Events & Proof ──
    "create_aigp_event",
    "compute_governance_hash",
    "compute_leaf_hash",
    "compute_merkle_governance_hash",
    "build_inclusion_proofs",
    "verify_inclusion_proof",
    "sign_event",
    "verify_event_signature",
    "EventSigner",
    "ES256PrivateKeySigner",
    "sign_event_with_signer",
    "RetryPolicy",
    "ReliableEmitter",
    # ── Context propagation ──
    "AIGPAttributes",
    "AIGPBaggage",
    "AIGPTraceState",
    # ── OpenLineage ──
    "build_governance_run_facet",
    "build_resource_input_facets",
    "build_openlineage_run_event",
    # ── CloudEvents ──
    "wrap_as_cloudevent",
    "unwrap_from_cloudevent",
    "build_ce_headers",
    "ce_type_from_event_type",
    "event_type_from_ce_type",
    # ── Decorator framework (for governance platforms) ──
    "configure",
    "aigp",
    "aigp_action",
    "a2a_traced",
    "audit_action",
    "GovernanceBackend",
    "GovernanceResponse",
    "GovernanceResult",
    "GovernanceError",
    "GovernedActionContext",
    "get_backend",
    "get_instrumentor",
    # ── Golden Path (AgentGP integration) ──
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
