# @aigp/sdk

TypeScript/JavaScript SDK for AIGP (AI Governance Proof).

## Install

```bash
npm install @aigp/sdk
```

## Quick Start

```ts
import {
  emitAIGPEvent,
  wrapAsCloudEvent,
} from "@aigp/sdk";

const event = emitAIGPEvent({
  event_type: "INJECT_SUCCESS",
  event_category: "inject",
  agent_id: "agent.trading-bot-v2",
  policy_name: "policy.trading-limits",
  policy_version: 4,
  content: "Max position: $10M",
});

const cloudevent = wrapAsCloudEvent(event);
console.log(event.event_id, event.governance_hash);
```

Success looks like:
- `event_id` is a UUID
- `governance_hash` is 64-char lowercase hex
- `trace_id` is present
- `sequence_number` auto-increments per `(agent_id, trace_id)`

## Included

- Event helpers: `emitAIGPEvent`, `createAIGPEvent`, `validateAIGPEvent`, event/category normalization
- Hashing: `computeGovernanceHash`, `computeLeafHash`, `computeMerkleGovernanceHash`
- Inclusion proof helpers: `buildInclusionProofs`, `verifyInclusionProof`
- Signer boundary: `signEventWithSigner`, `ES256PrivateKeySigner`
- Delivery reliability helpers: `RetryPolicy`, `ReliableEmitter`
- CloudEvents transport: `wrapAsCloudEvent`, `unwrapFromCloudEvent`, `buildCEHeaders`

## Event Type Normalization

Non-conformant event names (for example `myplatform.audit.login`) are normalized to `UPPER_SNAKE_CASE` (for example `MYPLATFORM_AUDIT_LOGIN`).
