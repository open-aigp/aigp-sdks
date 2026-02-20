# AIGP Java SDK

Java SDK for AIGP (AI Governance Proof).

## Install

Maven:

```xml
<dependency>
  <groupId>org.open-aigp</groupId>
  <artifactId>aigp-sdk</artifactId>
  <version>0.1.0</version>
</dependency>
```

If your Maven registry mirror does not have this artifact yet, use local source:

```bash
cd sdks/java
mvn install
```

## Quick Start

```java
AIGP.CreateEventOptions options = new AIGP.CreateEventOptions();
options.eventType = "INJECT_SUCCESS";
options.eventCategory = "inject";
options.agentId = "agent.trading-bot-v2";
options.orgId = "org.finco";
options.governanceHash = AIGP.computeGovernanceHash("Max position: $10M", "sha256");

AIGP.AIGPEvent event = AIGP.createAIGPEvent(options);
AIGP.CloudEvent ce = AIGP.wrapAsCloudEvent(event, true);
```

## Includes

- Event creation and normalization (`createAIGPEvent`, `normalizeEventType`)
- Auto `sequence_number` assignment per (`agent_id`, `trace_id`) when not explicitly set
- Governance hashing (`computeGovernanceHash`, `computeLeafHash`)
- Merkle governance proofs (`computeMerkleGovernanceHash`, `buildInclusionProofs`, `verifyInclusionProof`)
- Signer boundary (`EventSigner`, `signEventWithSigner`)
- Delivery reliability helpers (`RetryPolicy`, `ReliableEmitter`)
- CloudEvents helpers (`wrapAsCloudEvent`, `unwrapFromCloudEvent`, `buildCEHeaders`)
