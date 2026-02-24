"""AIGP Quickstart — pip install aigp"""

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
