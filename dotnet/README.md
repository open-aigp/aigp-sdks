# AIGP .NET SDK

.NET SDK for AIGP (AI Governance Proof).

## Install

NuGet:

```bash
dotnet add package AIGP.Sdk
```

From source (in this repo):

```bash
cd sdks/dotnet
dotnet build
```

## Quick Start

```csharp
using AIGP.Sdk;

var evt = AIGP.EmitAIGPEvent(new CreateEventOptions
{
    EventType = "INJECT_SUCCESS",
    EventCategory = "inject",
    AgentID = "agent.trading-bot-v2",
    OrgID = "org.finco",
}, "Max position: $10M");

var cloudEvent = AIGP.WrapAsCloudEvent(evt, includeDataschema: true);
Console.WriteLine(evt.EventID);
Console.WriteLine(evt.GovernanceHash);
```

Success looks like:
- `event_id` is a UUID
- `governance_hash` is 64-char lowercase hex
- `trace_id` is present
- `sequence_number` auto-increments per `(agent_id, trace_id)`

## Includes

- Event creation and normalization (`EmitAIGPEvent`, `CreateAIGPEvent`, `NormalizeEventType`)
- Governance hashing (`ComputeGovernanceHash`, `ComputeLeafHash`)
- Merkle governance proofs (`ComputeMerkleGovernanceHash(..., includeInclusionProofs: true)`, `BuildInclusionProofs`, `VerifyInclusionProof`)
- Signer boundary (`IEventSigner`, `SignEventWithSigner`)
- Delivery reliability helpers (`RetryPolicy`, `ReliableEmitter`)
- CloudEvents helpers (`WrapAsCloudEvent`, `UnwrapFromCloudEvent`, `BuildCEHeaders`)
- Validation helpers (`ValidateAIGPEvent`)

## Test

```bash
cd sdks/dotnet
dotnet run --project tests/AIGP.Sdk.SmokeTests/AIGP.Sdk.SmokeTests.csproj
```
