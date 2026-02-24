# AIGP Kotlin SDK

Kotlin SDK for AIGP (AI Governance Proof).

## Build

```bash
cd sdks/kotlin
gradle test
```

## Quick Start

```kotlin
val event = createAIGPEvent(
    CreateEventOptions(
        eventType = "INJECT_SUCCESS",
        eventCategory = "inject",
        agentId = "agent.trading-bot-v2",
        orgId = "org.finco",
        governanceHash = computeGovernanceHash("Max position: $10M", "sha256"),
    )
)

val ce = wrapAsCloudEvent(event)
```

## Includes

- Event creation and normalization
- Auto `sequence_number` assignment per (`agent_id`, `trace_id`) when not explicitly set
- Governance hashing and Merkle proofs (`computeMerkleGovernanceHash(..., includeInclusionProofs = true)`, `buildInclusionProofs`, `verifyInclusionProof`)
- Signer boundary (`EventSigner`, `signEventWithSigner`)
- Delivery reliability helpers (`RetryPolicy`, `ReliableEmitter`)
- CloudEvents helpers
