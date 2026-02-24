# aigp

Rust SDK for AIGP (AI Governance Proof).

## Install

```toml
[dependencies]
aigp = "0.1.0"
```

## Quick Start

```rust
use aigp::{
    compute_governance_hash,
    create_aigp_event,
    wrap_as_cloudevent,
    CreateEventOptions,
};

let event = create_aigp_event(CreateEventOptions {
    event_type: "INJECT_SUCCESS".to_string(),
    event_category: Some("inject".to_string()),
    agent_id: "agent.trading-bot-v2".to_string(),
    trace_id: None,
    governance_hash: Some(compute_governance_hash("Max position: $10M", Some("sha256"))?),
    span_id: None,
    parent_span_id: None,
    trace_flags: None,
    agent_name: None,
    org_id: Some("org.finco".to_string()),
    org_name: None,
    policy_id: None,
    policy_name: None,
    policy_version: None,
    prompt_id: None,
    prompt_name: None,
    prompt_version: None,
    hash_type: None,
    data_classification: None,
    template_rendered: None,
    denial_reason: None,
    violation_type: None,
    severity: None,
    source_ip: None,
    request_method: None,
    request_path: None,
    query_hash: None,
    previous_hash: None,
    annotations: None,
    event_signature: None,
    signature_key_id: None,
    sequence_number: None,
    causality_ref: None,
    spec_version: None,
    governance_merkle_tree: None,
})?;

let ce = wrap_as_cloudevent(&event, true)?;
assert_eq!(ce.r#type, "org.aigp.v1.inject_success");
# Ok::<(), String>(())
```

## Includes

- Event creation and normalization
- Governance hashing and Merkle proofs (`compute_merkle_governance_hash_with_proofs`, `build_inclusion_proofs`, `verify_inclusion_proof`)
- Signer boundary (`EventSigner`, `sign_event_with_signer`)
- Delivery reliability helpers (`RetryPolicy`, `ReliableEmitter`)
- CloudEvents helpers
