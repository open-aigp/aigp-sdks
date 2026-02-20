# AIGP Go SDK

Go SDK for AIGP (AI Governance Proof).

## Install

```bash
go get github.com/open-aigp/aigp/sdks/go
```

## Quick Start

```go
package main

import (
	"fmt"

	aigp "github.com/open-aigp/aigp/sdks/go"
)

func main() {
	event, _ := aigp.EmitAIGPEvent(aigp.CreateEventOptions{
		EventType:      "INJECT_SUCCESS",
		EventCategory:  "inject",
		AgentID:        "agent.trading-bot-v2",
		OrgID:          "org.finco",
	}, "Max position: $10M")

	ce, _ := aigp.WrapAsCloudEvent(event, true)
	fmt.Println(ce["type"]) // org.aigp.v1.inject_success
	fmt.Println(event.EventID, event.GovernanceHash)
}
```

Success looks like:
- `event_id` is a UUID
- `governance_hash` is 64-char lowercase hex
- `trace_id` is present
- `sequence_number` auto-increments per `(agent_id, trace_id)`

## Includes

- Event creation and normalization (`EmitAIGPEvent`, `CreateAIGPEvent`, `NormalizeEventType`)
- Governance hashing (`ComputeGovernanceHash`, `ComputeLeafHash`)
- Merkle governance proofs (`ComputeMerkleGovernanceHash`, `ComputeMerkleGovernanceHashWithProofs`, `BuildInclusionProofs`, `VerifyInclusionProof`)
- Signer boundary (`EventSigner`, `NewES256PrivateKeySigner`, `SignEventWithSigner`)
- Delivery reliability helpers (`RetryPolicy`, `ReliableEmitter`)
- CloudEvents helpers (`WrapAsCloudEvent`, `UnwrapFromCloudEvent`, `BuildCEHeaders`)
