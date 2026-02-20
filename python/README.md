# AIGP Python SDK

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](../../LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://www.python.org/)
[![PyPI](https://img.shields.io/pypi/v/aigp.svg)](https://pypi.org/project/aigp/)

**Open instrumentation standard for proving your AI agents used the approved policies, prompts, and tools — every single time.**

What OTel is for observability, AIGP is for AI Governance.

---

## Quick Start

```bash
pip install aigp
```

```python
from aigp import AIGPInstrumentor

# Initialize the instrumentor (like OTel TracerProvider)
instrumentor = AIGPInstrumentor(
    agent_id="agent.trading-agent-v1",
)

# Emit governance events using AIGP's recommended RESOURCE_ACTION convention
event = instrumentor.emit(
    "INJECT_SUCCESS",
    policy_name="policy.trading-limits",
    policy_version=4,
    content="Max position $10M...",
)

print(f"AIGP event: {event['event_type']} — hash: {event['governance_hash'][:16]}...")
```

Success looks like:
- `event_id` is a UUID
- `governance_hash` is 64-char lowercase hex
- `trace_id` is present

Behind the scenes, AIGP:
- Captures governance events with cryptographic proof (Merkle hashes)
- Dual-emits to OTel spans (observability) and AIGP events (compliance store)
- Signs events with JWS ES256 for tamper-proof audit trails
- Stays vendor-neutral — any governance platform can emit AIGP events

---

## Golden Path: `govern(agent).run(...)`

For fastest integration with AgentGP, use the strict golden-path runner:

```python
from aigp import AgentGPConfig, govern

runner = govern(
    AgentGPConfig(
        base_url="https://api.agentgp.ai",
        api_key="sk-...",
        agent_id="agent.support-bot-v2",
        strict=True,
        debug=True,
        required_prompts=["prompt.support-v3"],
        required_policies=["policy.content-filter"],
        required_tools=["tool.search"],
    )
)

result = runner.run(
    {"question": "How do I reset my password?"},
    prompt_name="prompt.support-v3",
    policy_name="policy.content-filter",
    tools=["tool.search"],
    execute=lambda ctx: {"answer": "Use account settings > security."},
)

print(result.trace_id, result.governance_hash, result.allowed)
```

What this does automatically:
- Startup fail-fast checks (`/api/sdk/capabilities`, key/agent/resource validation)
- Register -> prompt -> policy -> tool -> audit-proof event flow
- Automatic `trace_id`, `sequence_number`, `causality_ref`, and `governance_hash`
- Stable response envelope handling (`success`, `data`, `error`, `trace_id`, `governance`)
- Optional local recorder in debug mode (`runner.recorder.requests/responses/events`)

Official adapter classes with identical `run(...)` API:
- `LangGraphAdapter`
- `CrewAIAdapter`
- `AutoGenAdapter`
- `OpenAIAdapter`
- `VertexAdapter`
- `BedrockAdapter`

OpenAPI contract for code generation:
- `aigp/openapi/agentgp-golden-path.openapi.json`

---

## What AIGP Does

| AIGP does | AIGP does NOT |
|-----------|---------------|
| Capture AI Governance events | Dictate how governance works |
| Prove governance was delivered (Merkle proofs) | Provide policies, prompts, or tools |
| Sign events for tamper-proof audit | Execute governance decisions |
| Transport via OTel, CloudEvents, OpenLineage | Couple to any specific governance server |

Governance platforms use AIGP internally to emit events, just like web frameworks use OTel internally to emit spans.

---

## AIGPInstrumentor — The Primary API

A single `emit()` method for any governance event. AIGP ships with 31 standard event types across 15 categories using the `RESOURCE_ACTION` naming convention — and you can define your own.

```python
from aigp import AIGPInstrumentor

instrumentor = AIGPInstrumentor(
    agent_id="agent.trading-bot-v2",
    agent_name="Trading Bot",
    org_id="org.finco",
    event_callback=send_to_governance_store,      # AIGP events -> your store
    openlineage_callback=send_to_lineage_backend,  # OpenLineage facets -> lineage
)

# Policy delivery
instrumentor.emit(
    "INJECT_SUCCESS",
    policy_name="policy.limits",
    policy_version=4,
    content="Max position $10M...",
)

# Prompt delivery
instrumentor.emit(
    "PROMPT_USED",
    prompt_name="prompt.system-v3",
    prompt_version=2,
    content="You are a trading assistant...",
)

# Tool invocation
instrumentor.emit(
    "TOOL_INVOKED",
    content="charge:5000",
    annotations={"tool_name": "tool.stripe-api"},
)

# Denial events
instrumentor.emit(
    "INJECT_DENIED",
    policy_name="policy.limits",
    denial_reason="Amount exceeds limit",
)

# Custom event types — extensible by design
instrumentor.emit(
    "MYPLATFORM_AUDIT_LOGIN",
    event_category="audit",
    content="User logged in",
    annotations={"user_id": "u-123"},
)

# Multi-resource Merkle proof
instrumentor.emit(
    "GOVERNANCE_PROOF",
    resources=[
        ("policy", "policy.limits", "Max $10M..."),
        ("prompt", "prompt.system-v3", "You are a trading..."),
        ("tool", "tool.stripe-api", '{"scope": "charge"}'),
    ],
)

# Boundary events (unverified external calls)
instrumentor.emit(
    "UNVERIFIED_BOUNDARY",
    event_category="boundary",
    content="request payload",
    annotations={"target_agent_id": "agent.external-llm"},
)
```

### Key Parameters

| Parameter | Description |
|-----------|-------------|
| `event_type` | Free-form string (e.g., `"INJECT_SUCCESS"`) |
| `event_category` | Category string (default: `"governance"`) |
| `content` | Content to hash for governance proof |
| `policy_name` / `policy_version` | Policy metadata |
| `prompt_name` / `prompt_version` | Prompt metadata |
| `denial_reason` | Reason for denial (sets enforcement to `"denied"`) |
| `annotations` | Free-form dict for extra metadata (not hashed) |
| `resources` | List of `(type, name, content)` for Merkle proof |
| `causality_ref` | Optional override. By default, SDK auto-links prior event in trace |
| `trace_id` | Optional override for canonical trace correlation (auto-generated if absent) |
| `data_classification` | Data sensitivity level |

---

## Decorator Framework — For Governance Platforms

AIGP provides building blocks for governance platforms that want a decorator-based developer experience. Platform authors implement the `GovernanceBackend` protocol; end-developers use `@aigp()` decorators.

### `configure()` — One-time setup

```python
from aigp import configure

configure(
    backend=my_governance_backend,
    agent_id="agent.my-bot-v1",
)
```

### `@aigp` — Full governance pipeline

```python
from aigp import aigp

@aigp(policy="policy.refund-limits", prompt="prompt.support-v3")
def handle_refund(request: dict, governance=None):
    if governance.denied:
        return {"error": governance.denial_reason}

    rendered = governance.get_rendered("policy.refund-limits")
    system_prompt = governance.get_prompt("prompt.support-v3")
    return process(request, rendered, system_prompt)
```

Parameters:
- `policy` — Policy SRN(s): `str` or `list[str]`
- `prompt` — Prompt SRN(s): `str` or `list[str]`
- `tool` — Tool SRN(s): `str` or `list[str]`
- `deny_raises` — If `True`, raises `GovernanceError` on denial (default: `False`)
- `fail_closed` — If `True`, raises `GovernanceError` when backend is unavailable (default: `False`)

### `GovernanceResult` — What you get back

```python
governance.allowed        # True/False
governance.denied         # opposite of allowed
governance.denial_reason  # "Amount exceeds limit" or None
governance.merkle_root    # cryptographic proof hash

governance.get_rendered("policy.refund-limits")     # rendered policy content
governance.get_prompt("prompt.support-v3")           # rendered prompt content
governance.is_tool_allowed("tool.stripe-api")        # True/False
```

### `GovernanceBackend` Protocol

Any class with the right methods works (no subclassing required):

```python
from aigp import configure

class MyBackend:
    def inject_governance(self, *, policies=None, prompts=None,
                          tools=None, tool_input=None, trace_id=None):
        return {
            "allowed": True,
            "merkle_root": "abc123",
            "policies": {"policy.x": {"content": "rendered policy"}},
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
        return "agent.my-bot"

    def get_trace_id(self):
        return "trace-123"

configure(backend=MyBackend(), agent_id="agent.my-bot")
```

### `aigp_action()` — Context manager for inline governance

```python
from aigp import aigp_action

async def complex_flow(data):
    async with aigp_action(policy="policy.limits", tool="tool.db") as ctx:
        if ctx.denied:
            return {"error": ctx.denial_reason}
        # ... do governed work ...
        ctx.set_result({"status": "ok"})
```

### `@a2a_traced` — Auto-log agent-to-agent calls

```python
from aigp import a2a_traced

@a2a_traced(agent_id="agent.downstream-bot")
def call_other_agent(payload):
    return requests.post("https://other-agent/api", json=payload).json()
```

### `@audit_action` — Simple audit logging

```python
from aigp import audit_action

@audit_action(event_type="user_login")
def login(username: str):
    return authenticate(username)
```

---

## Advanced Features

### Merkle Tree Governance Proofs

Every governance action can compute a Merkle proof over all governed resources:

```python
from aigp import compute_merkle_governance_hash

resources = [
    ("policy", "policy.refund-limits", "Refund max: $500..."),
    ("prompt", "prompt.support-v3", "You are a helpful..."),
    ("tool", "tool.order-lookup", '{"scope": "read"}'),
]

root_hash, merkle_tree = compute_merkle_governance_hash(resources)
# root_hash: cryptographic proof that these exact resources were used
```

Selective verification with inclusion proofs:

```python
from aigp import compute_merkle_governance_hash, verify_inclusion_proof

root_hash, tree = compute_merkle_governance_hash(
    resources,
    include_inclusion_proofs=True,
)

for proof_entry in tree["inclusion_proofs"]:
    ok = verify_inclusion_proof(
        root_hash,
        proof_entry["leaf_hash"],
        proof_entry["proof_path"],
    )
    assert ok
```

### Event Signing (JWS ES256)

Sign events for tamper-proof audit trails:

```python
from aigp import sign_event, verify_event_signature

signed = sign_event(event, private_key_pem, key_id="key.signer-v1")
is_valid = verify_event_signature(signed, public_key_pem)
```

Pluggable signer interface (KMS/HSM compatible):

```python
from aigp import ES256PrivateKeySigner, sign_event_with_signer

signer = ES256PrivateKeySigner(private_key_pem, key_id="key.signer-v1")
signed = sign_event_with_signer(event, signer)
```

### Delivery Reliability Helpers

Transport-agnostic retry/idempotency wrapper around your own sender:

```python
from aigp import ReliableEmitter, RetryPolicy

emitter = ReliableEmitter(
    sender=send_to_my_transport,  # HTTP, Kafka, queue, etc.
    retry_policy=RetryPolicy(max_attempts=5),
)
emitter.emit(event)
```

### OpenLineage Facets

Build OpenLineage RunEvents for data lineage (zero dependency on openlineage-python):

```python
from aigp import build_openlineage_run_event
```

### CloudEvents Transport

Wrap AIGP events as CloudEvents for interop:

```python
from aigp import wrap_as_cloudevent, build_ce_headers
```

### W3C Propagation

Propagate governance context across services:

```python
from aigp import AIGPBaggage, AIGPTraceState
```

---

## Modules

| Module | Purpose |
|--------|---------|
| `aigp.instrumentor` | Primary API — `AIGPInstrumentor` with generic `emit()` |
| `aigp.events` | Event creation, hash computation, Merkle tree, JWS signing |
| `aigp.signer` | Pluggable signer interfaces (vendor-neutral key management boundary) |
| `aigp.reliability` | Retry/idempotency helpers over caller-provided transports |
| `aigp.decorators` | `@aigp`, `configure()`, `GovernanceBackend`, `GovernanceResult` |
| `aigp.attributes` | `aigp.*` semantic attribute constants (OTel convention) |
| `aigp.baggage` | OTel Baggage propagation for A2A |
| `aigp.tracestate` | W3C tracestate vendor key |
| `aigp.cloudevents` | CloudEvents wrapping |
| `aigp.openlineage` | OpenLineage facet builder |

---

## Running Tests

```bash
pip install aigp[dev]
cd sdks/python
pytest tests/ -v
```

## Links

- **Website**: [open-aigp.org](https://open-aigp.org)
- **GitHub**: [github.com/open-aigp/aigp](https://github.com/open-aigp/aigp)
- **PyPI**: [pypi.org/project/aigp](https://pypi.org/project/aigp/)
- **AIGP Specification**: [spec/aigp-spec.md](../../spec/aigp-spec.md)
