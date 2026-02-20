//! AIGP Rust SDK core helpers.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Read;
use std::sync::{Mutex, OnceLock};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const VERSION: &str = "0.1.0";

pub const CE_SPECVERSION: &str = "1.0";
pub const AIGP_TYPE_PREFIX: &str = "org.aigp.v1.";
pub const AIGP_SOURCE_SCHEME: &str = "aigp://";
pub const AIGP_DATA_SCHEMA: &str = "https://open-aigp.org/schema/aigp-event.schema.json";
static SEQUENCE_COUNTERS: OnceLock<Mutex<HashMap<String, i64>>> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleLeaf {
    pub resource_type: String,
    pub resource_name: String,
    pub hash: String,
    pub hash_mode: Option<String>,
    pub content_ref: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProofStep {
    pub sibling_hash: String,
    pub sibling_position: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleInclusionProof {
    pub leaf_hash: String,
    pub proof_path: Vec<MerkleProofStep>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceMerkleTree {
    pub algorithm: String,
    pub leaf_count: usize,
    pub leaves: Vec<MerkleLeaf>,
    pub inclusion_proofs: Option<Vec<MerkleInclusionProof>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleResult {
    pub root_hash: String,
    pub merkle_tree: Option<GovernanceMerkleTree>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    pub resource_type: String,
    pub resource_name: String,
    pub content: String,
    pub hash_mode: Option<String>,
    pub content_ref: Option<String>,
}

impl Resource {
    pub fn new(resource_type: &str, resource_name: &str, content: &str) -> Self {
        Self {
            resource_type: resource_type.to_string(),
            resource_name: resource_name.to_string(),
            content: content.to_string(),
            hash_mode: Some("content".to_string()),
            content_ref: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateEventOptions {
    pub event_type: String,
    pub event_category: Option<String>,
    pub agent_id: String,
    pub trace_id: Option<String>,
    pub governance_hash: Option<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub trace_flags: Option<String>,
    pub agent_name: Option<String>,
    pub org_id: Option<String>,
    pub org_name: Option<String>,
    pub policy_id: Option<String>,
    pub policy_name: Option<String>,
    pub policy_version: Option<i64>,
    pub prompt_id: Option<String>,
    pub prompt_name: Option<String>,
    pub prompt_version: Option<i64>,
    pub hash_type: Option<String>,
    pub data_classification: Option<String>,
    pub template_rendered: Option<bool>,
    pub denial_reason: Option<String>,
    pub violation_type: Option<String>,
    pub severity: Option<String>,
    pub source_ip: Option<String>,
    pub request_method: Option<String>,
    pub request_path: Option<String>,
    pub query_hash: Option<String>,
    pub previous_hash: Option<String>,
    pub annotations: Option<BTreeMap<String, JsonValue>>,
    pub event_signature: Option<String>,
    pub signature_key_id: Option<String>,
    pub sequence_number: Option<i64>,
    pub causality_ref: Option<String>,
    pub spec_version: Option<String>,
    pub governance_merkle_tree: Option<GovernanceMerkleTree>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AIGPEvent {
    pub event_id: String,
    pub event_type: String,
    pub event_category: String,
    pub event_time: String,
    pub agent_id: String,
    pub governance_hash: String,
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: String,
    pub trace_flags: String,
    pub agent_name: String,
    pub org_id: String,
    pub org_name: String,
    pub policy_id: String,
    pub policy_name: String,
    pub policy_version: i64,
    pub prompt_id: String,
    pub prompt_name: String,
    pub prompt_version: i64,
    pub hash_type: String,
    pub data_classification: String,
    pub template_rendered: bool,
    pub denial_reason: String,
    pub violation_type: String,
    pub severity: String,
    pub source_ip: String,
    pub request_method: String,
    pub request_path: String,
    pub query_hash: String,
    pub previous_hash: String,
    pub annotations: BTreeMap<String, JsonValue>,
    pub event_signature: String,
    pub signature_key_id: String,
    pub sequence_number: i64,
    pub causality_ref: String,
    pub spec_version: String,
    pub governance_merkle_tree: Option<GovernanceMerkleTree>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloudEvent {
    pub specversion: String,
    pub id: String,
    pub r#type: String,
    pub source: String,
    pub datacontenttype: String,
    pub time: Option<String>,
    pub dataschema: Option<String>,
    pub subject: Option<String>,
    pub aigpagentid: String,
    pub aigporgid: Option<String>,
    pub aigpcategory: Option<String>,
    pub aigpclassification: Option<String>,
    pub aigpseverity: Option<String>,
    pub aigphashtype: Option<String>,
    pub data: AIGPEvent,
}

pub trait EventSigner {
    fn algorithm(&self) -> &str;
    fn key_id(&self) -> &str;
    fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, String>;
}

#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub max_attempts: usize,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(2),
        }
    }
}

impl RetryPolicy {
    pub fn delay_for_attempt(&self, attempt: usize) -> Duration {
        let pow = 1u32 << (attempt.saturating_sub(1) as u32);
        let delay = self.base_delay.saturating_mul(pow);
        if delay > self.max_delay {
            self.max_delay
        } else {
            delay
        }
    }
}

#[derive(Clone, Debug)]
pub struct FlushResult {
    pub delivered: usize,
    pub pending: usize,
}

pub struct ReliableEmitter<F>
where
    F: Fn(&AIGPEvent) -> Result<(), String>,
{
    sender: F,
    retry_policy: RetryPolicy,
    idempotent: bool,
    delivered_ids: std::collections::HashSet<String>,
    failed_events: Vec<AIGPEvent>,
}

impl<F> ReliableEmitter<F>
where
    F: Fn(&AIGPEvent) -> Result<(), String>,
{
    pub fn new(sender: F, retry_policy: Option<RetryPolicy>, idempotent: bool) -> Self {
        Self {
            sender,
            retry_policy: retry_policy.unwrap_or_default(),
            idempotent,
            delivered_ids: std::collections::HashSet::new(),
            failed_events: vec![],
        }
    }

    pub fn pending_count(&self) -> usize {
        self.failed_events.len()
    }

    pub fn emit(&mut self, event: &AIGPEvent) -> bool {
        let event_id = event.event_id.trim().to_string();
        if self.idempotent && !event_id.is_empty() && self.delivered_ids.contains(&event_id) {
            return true;
        }

        let max_attempts = self.retry_policy.max_attempts.max(1);
        for attempt in 1..=max_attempts {
            match (self.sender)(event) {
                Ok(_) => {
                    if !event_id.is_empty() {
                        self.delivered_ids.insert(event_id.clone());
                    }
                    return true;
                }
                Err(_) => {
                    if attempt < max_attempts {
                        sleep(self.retry_policy.delay_for_attempt(attempt));
                    }
                }
            }
        }

        self.failed_events.push(event.clone());
        false
    }

    pub fn flush_failed(&mut self, max_items: usize) -> FlushResult {
        let limit = if max_items == 0 { 1000 } else { max_items };
        let mut delivered = 0usize;
        let mut remaining = Vec::<AIGPEvent>::new();

        for (idx, event) in self.failed_events.clone().into_iter().enumerate() {
            if idx >= limit {
                remaining.push(event);
                continue;
            }
            if self.emit(&event) {
                delivered += 1;
            } else {
                remaining.push(event);
            }
        }

        self.failed_events = remaining;
        FlushResult {
            delivered,
            pending: self.failed_events.len(),
        }
    }
}

pub fn normalize_event_type(event_type: &str) -> Result<String, String> {
    let raw = event_type.trim();
    if raw.is_empty() {
        return Err("event_type must be a non-empty string".to_string());
    }

    let mapped = event_type_alias(raw).unwrap_or(raw);
    if is_valid_event_type(mapped) {
        return Ok(mapped.to_string());
    }

    let mut normalized = String::new();
    let mut prev_us = false;
    for ch in mapped.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_uppercase());
            prev_us = false;
        } else if !prev_us && !normalized.is_empty() {
            normalized.push('_');
            prev_us = true;
        }
    }
    while normalized.ends_with('_') {
        normalized.pop();
    }

    if normalized.is_empty() || !is_valid_event_type(&normalized) {
        return Err(format!(
            "event_type {event_type:?} cannot be normalized to a valid UPPER_SNAKE_CASE value"
        ));
    }

    Ok(normalized)
}

pub fn normalize_event_category(event_category: &str) -> String {
    let raw = event_category.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return "governance".to_string();
    }

    let mut out = String::new();
    let mut prev_dash = false;
    for ch in raw.chars() {
        let mapped = if ch == '_' { '-' } else { ch };
        if mapped.is_ascii_lowercase() || mapped.is_ascii_digit() {
            out.push(mapped);
            prev_dash = false;
        } else if mapped == '-' {
            if !prev_dash && !out.is_empty() {
                out.push('-');
                prev_dash = true;
            }
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }

    while out.ends_with('-') {
        out.pop();
    }

    if out.is_empty() {
        "governance".to_string()
    } else {
        out
    }
}

pub fn compute_governance_hash(content: &str, algorithm: Option<&str>) -> Result<String, String> {
    let algo = algorithm.unwrap_or("sha256");
    match algo {
        "sha256" => Ok(hex_encode(&sha256_bytes(content.as_bytes()))),
        "sha384" => Ok(hex_encode(&sha384_bytes(content.as_bytes()))),
        "sha512" => Ok(hex_encode(&sha512_bytes(content.as_bytes()))),
        other => Err(format!("unsupported hash algorithm: {other}")),
    }
}

pub fn compute_leaf_hash(
    resource_type: &str,
    resource_name: &str,
    content: &str,
    hash_mode: Option<&str>,
    content_ref: Option<&str>,
) -> Result<String, String> {
    if !is_valid_resource_type(resource_type) {
        return Err(format!("invalid resource_type {resource_type:?}"));
    }

    let mode = hash_mode.unwrap_or("content");
    if mode != "content" && mode != "pointer" {
        return Err(format!(
            "unsupported hash_mode {mode:?} (expected 'content' or 'pointer')"
        ));
    }

    let hashable = if mode == "pointer" {
        match content_ref {
            Some(value) if !value.is_empty() => value,
            _ => return Err("content_ref is required when hash_mode='pointer'".to_string()),
        }
    } else {
        content
    };

    compute_governance_hash(
        &format!("{resource_type}:{resource_name}:{hashable}"),
        Some("sha256"),
    )
}

pub fn compute_merkle_governance_hash(resources: &[Resource]) -> Result<MerkleResult, String> {
    compute_merkle_governance_hash_with_proofs(resources, false)
}

pub fn compute_merkle_governance_hash_with_proofs(
    resources: &[Resource],
    include_inclusion_proofs: bool,
) -> Result<MerkleResult, String> {
    if resources.is_empty() {
        return Err("at least one resource is required".to_string());
    }

    if resources.len() == 1 {
        let single = &resources[0];
        let mode = single.hash_mode.as_deref().unwrap_or("content");
        if mode != "content" && mode != "pointer" {
            return Err(format!(
                "unsupported hash_mode {mode:?} (expected 'content' or 'pointer')"
            ));
        }

        if mode == "pointer" {
            let ptr = single
                .content_ref
                .as_deref()
                .filter(|v| !v.is_empty())
                .ok_or_else(|| "content_ref is required when hash_mode='pointer'".to_string())?;
            return Ok(MerkleResult {
                root_hash: compute_governance_hash(ptr, Some("sha256"))?,
                merkle_tree: None,
            });
        }

        return Ok(MerkleResult {
            root_hash: compute_governance_hash(&single.content, Some("sha256"))?,
            merkle_tree: None,
        });
    }

    let mut leaves = Vec::<MerkleLeaf>::with_capacity(resources.len());
    for resource in resources {
        let mode = resource.hash_mode.as_deref().unwrap_or("content");
        let leaf_hash = compute_leaf_hash(
            &resource.resource_type,
            &resource.resource_name,
            &resource.content,
            Some(mode),
            resource.content_ref.as_deref(),
        )?;
        leaves.push(MerkleLeaf {
            resource_type: resource.resource_type.clone(),
            resource_name: resource.resource_name.clone(),
            hash: leaf_hash,
            hash_mode: if mode == "content" {
                None
            } else {
                Some(mode.to_string())
            },
            content_ref: resource.content_ref.clone().filter(|v| !v.is_empty()),
        });
    }

    leaves.sort_by(|a, b| a.hash.cmp(&b.hash));
    let hashes: Vec<String> = leaves.iter().map(|leaf| leaf.hash.clone()).collect();
    let root = compute_merkle_root(&hashes)?;
    let inclusion_proofs = if include_inclusion_proofs {
        Some(build_inclusion_proofs(&leaves))
    } else {
        None
    };

    Ok(MerkleResult {
        root_hash: root,
        merkle_tree: Some(GovernanceMerkleTree {
            algorithm: "sha256".to_string(),
            leaf_count: leaves.len(),
            leaves,
            inclusion_proofs,
        }),
    })
}

pub fn build_inclusion_proofs(leaves: &[MerkleLeaf]) -> Vec<MerkleInclusionProof> {
    if leaves.is_empty() {
        return vec![];
    }

    #[derive(Clone)]
    struct Node {
        hash: String,
        leaf_indexes: Vec<usize>,
    }

    let mut proof_paths: Vec<Vec<MerkleProofStep>> = vec![Vec::new(); leaves.len()];
    let mut nodes: Vec<Node> = leaves
        .iter()
        .enumerate()
        .map(|(idx, leaf)| Node {
            hash: leaf.hash.clone(),
            leaf_indexes: vec![idx],
        })
        .collect();

    while nodes.len() > 1 {
        let mut next = Vec::<Node>::with_capacity((nodes.len() + 1) / 2);
        let mut i = 0usize;
        while i < nodes.len() {
            if i + 1 >= nodes.len() {
                next.push(nodes[i].clone());
                i += 1;
                continue;
            }

            let left = nodes[i].clone();
            let right = nodes[i + 1].clone();

            for leaf_idx in &left.leaf_indexes {
                proof_paths[*leaf_idx].push(MerkleProofStep {
                    sibling_hash: right.hash.clone(),
                    sibling_position: "right".to_string(),
                });
            }
            for leaf_idx in &right.leaf_indexes {
                proof_paths[*leaf_idx].push(MerkleProofStep {
                    sibling_hash: left.hash.clone(),
                    sibling_position: "left".to_string(),
                });
            }

            let parent = hex_encode(&sha256_bytes((left.hash.clone() + &right.hash).as_bytes()));
            next.push(Node {
                hash: parent,
                leaf_indexes: left
                    .leaf_indexes
                    .into_iter()
                    .chain(right.leaf_indexes.into_iter())
                    .collect(),
            });
            i += 2;
        }
        nodes = next;
    }

    leaves
        .iter()
        .enumerate()
        .map(|(idx, leaf)| MerkleInclusionProof {
            leaf_hash: leaf.hash.clone(),
            proof_path: proof_paths[idx].clone(),
        })
        .collect()
}

pub fn verify_inclusion_proof(
    root_hash: &str,
    leaf_hash: &str,
    proof_path: &[MerkleProofStep],
) -> Result<bool, String> {
    let mut current = leaf_hash.trim().to_string();
    let expected = root_hash.trim().to_string();
    if current.is_empty() || expected.is_empty() {
        return Ok(false);
    }

    for step in proof_path {
        let sibling_hash = step.sibling_hash.trim();
        if sibling_hash.is_empty() {
            return Ok(false);
        }

        current = match step.sibling_position.as_str() {
            "left" => compute_governance_hash(&(format!("{sibling_hash}{current}")), Some("sha256"))?,
            "right" => compute_governance_hash(&(format!("{current}{sibling_hash}")), Some("sha256"))?,
            other => {
                return Err(format!(
                    "invalid sibling_position in proof step: {other:?} (expected \"left\" or \"right\")"
                ))
            }
        };
    }

    Ok(current == expected)
}

pub fn sign_event_with_signer(
    event: &AIGPEvent,
    signer: &dyn EventSigner,
) -> Result<AIGPEvent, String> {
    let mut header = BTreeMap::<String, JsonValue>::new();
    header.insert("alg".to_string(), JsonValue::String(signer.algorithm().to_string()));
    header.insert("typ".to_string(), JsonValue::String("JWT".to_string()));
    if !signer.key_id().trim().is_empty() {
        header.insert("kid".to_string(), JsonValue::String(signer.key_id().to_string()));
    }

    let signable_payload = signable_event_json(event);
    let header_b64 = base64url_encode(canonicalize_json_value(&JsonValue::Object(header)).as_bytes());
    let payload_b64 = base64url_encode(canonicalize_json_value(&signable_payload).as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    let signature = signer.sign(signing_input.as_bytes())?;

    let mut signed = event.clone();
    signed.event_signature = format!("{}.{}", signing_input, base64url_encode(&signature));
    signed.signature_key_id = signer.key_id().to_string();
    Ok(signed)
}

fn signable_event_json(event: &AIGPEvent) -> JsonValue {
    let mut obj = BTreeMap::<String, JsonValue>::new();
    obj.insert("event_id".to_string(), JsonValue::String(event.event_id.clone()));
    obj.insert("event_type".to_string(), JsonValue::String(event.event_type.clone()));
    obj.insert("event_category".to_string(), JsonValue::String(event.event_category.clone()));
    obj.insert("event_time".to_string(), JsonValue::String(event.event_time.clone()));
    obj.insert("agent_id".to_string(), JsonValue::String(event.agent_id.clone()));
    obj.insert(
        "governance_hash".to_string(),
        JsonValue::String(event.governance_hash.clone()),
    );
    obj.insert("trace_id".to_string(), JsonValue::String(event.trace_id.clone()));
    obj.insert("span_id".to_string(), JsonValue::String(event.span_id.clone()));
    obj.insert(
        "parent_span_id".to_string(),
        JsonValue::String(event.parent_span_id.clone()),
    );
    obj.insert("trace_flags".to_string(), JsonValue::String(event.trace_flags.clone()));
    obj.insert("agent_name".to_string(), JsonValue::String(event.agent_name.clone()));
    obj.insert("org_id".to_string(), JsonValue::String(event.org_id.clone()));
    obj.insert("org_name".to_string(), JsonValue::String(event.org_name.clone()));
    obj.insert("policy_id".to_string(), JsonValue::String(event.policy_id.clone()));
    obj.insert(
        "policy_name".to_string(),
        JsonValue::String(event.policy_name.clone()),
    );
    obj.insert(
        "policy_version".to_string(),
        JsonValue::Number(event.policy_version.to_string()),
    );
    obj.insert("prompt_id".to_string(), JsonValue::String(event.prompt_id.clone()));
    obj.insert(
        "prompt_name".to_string(),
        JsonValue::String(event.prompt_name.clone()),
    );
    obj.insert(
        "prompt_version".to_string(),
        JsonValue::Number(event.prompt_version.to_string()),
    );
    obj.insert("hash_type".to_string(), JsonValue::String(event.hash_type.clone()));
    obj.insert(
        "data_classification".to_string(),
        JsonValue::String(event.data_classification.clone()),
    );
    obj.insert(
        "template_rendered".to_string(),
        JsonValue::Bool(event.template_rendered),
    );
    obj.insert(
        "denial_reason".to_string(),
        JsonValue::String(event.denial_reason.clone()),
    );
    obj.insert(
        "violation_type".to_string(),
        JsonValue::String(event.violation_type.clone()),
    );
    obj.insert("severity".to_string(), JsonValue::String(event.severity.clone()));
    obj.insert("source_ip".to_string(), JsonValue::String(event.source_ip.clone()));
    obj.insert(
        "request_method".to_string(),
        JsonValue::String(event.request_method.clone()),
    );
    obj.insert(
        "request_path".to_string(),
        JsonValue::String(event.request_path.clone()),
    );
    obj.insert("query_hash".to_string(), JsonValue::String(event.query_hash.clone()));
    obj.insert(
        "previous_hash".to_string(),
        JsonValue::String(event.previous_hash.clone()),
    );
    obj.insert(
        "annotations".to_string(),
        JsonValue::Object(event.annotations.clone()),
    );
    obj.insert(
        "sequence_number".to_string(),
        JsonValue::Number(event.sequence_number.to_string()),
    );
    obj.insert(
        "causality_ref".to_string(),
        JsonValue::String(event.causality_ref.clone()),
    );
    obj.insert(
        "spec_version".to_string(),
        JsonValue::String(event.spec_version.clone()),
    );
    if let Some(tree) = &event.governance_merkle_tree {
        obj.insert(
            "governance_merkle_tree".to_string(),
            governance_merkle_tree_to_json(tree),
        );
    }
    JsonValue::Object(obj)
}

fn governance_merkle_tree_to_json(tree: &GovernanceMerkleTree) -> JsonValue {
    let mut obj = BTreeMap::<String, JsonValue>::new();
    obj.insert("algorithm".to_string(), JsonValue::String(tree.algorithm.clone()));
    obj.insert(
        "leaf_count".to_string(),
        JsonValue::Number(tree.leaf_count.to_string()),
    );
    obj.insert(
        "leaves".to_string(),
        JsonValue::Array(
            tree.leaves
                .iter()
                .map(|leaf| {
                    let mut leaf_obj = BTreeMap::<String, JsonValue>::new();
                    leaf_obj.insert(
                        "resource_type".to_string(),
                        JsonValue::String(leaf.resource_type.clone()),
                    );
                    leaf_obj.insert(
                        "resource_name".to_string(),
                        JsonValue::String(leaf.resource_name.clone()),
                    );
                    leaf_obj.insert("hash".to_string(), JsonValue::String(leaf.hash.clone()));
                    if let Some(mode) = &leaf.hash_mode {
                        leaf_obj.insert("hash_mode".to_string(), JsonValue::String(mode.clone()));
                    }
                    if let Some(content_ref) = &leaf.content_ref {
                        leaf_obj.insert(
                            "content_ref".to_string(),
                            JsonValue::String(content_ref.clone()),
                        );
                    }
                    JsonValue::Object(leaf_obj)
                })
                .collect(),
        ),
    );
    if let Some(inclusion_proofs) = &tree.inclusion_proofs {
        obj.insert(
            "inclusion_proofs".to_string(),
            JsonValue::Array(
                inclusion_proofs
                    .iter()
                    .map(|proof| {
                        let mut proof_obj = BTreeMap::<String, JsonValue>::new();
                        proof_obj.insert(
                            "leaf_hash".to_string(),
                            JsonValue::String(proof.leaf_hash.clone()),
                        );
                        proof_obj.insert(
                            "proof_path".to_string(),
                            JsonValue::Array(
                                proof
                                    .proof_path
                                    .iter()
                                    .map(|step| {
                                        let mut step_obj = BTreeMap::<String, JsonValue>::new();
                                        step_obj.insert(
                                            "sibling_hash".to_string(),
                                            JsonValue::String(step.sibling_hash.clone()),
                                        );
                                        step_obj.insert(
                                            "sibling_position".to_string(),
                                            JsonValue::String(step.sibling_position.clone()),
                                        );
                                        JsonValue::Object(step_obj)
                                    })
                                    .collect(),
                            ),
                        );
                        JsonValue::Object(proof_obj)
                    })
                    .collect(),
            ),
        );
    }
    JsonValue::Object(obj)
}

fn canonicalize_json_value(value: &JsonValue) -> String {
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Bool(v) => {
            if *v {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        JsonValue::Number(v) => v.clone(),
        JsonValue::String(v) => json_escape(v),
        JsonValue::Array(values) => {
            let items: Vec<String> = values.iter().map(canonicalize_json_value).collect();
            format!("[{}]", items.join(","))
        }
        JsonValue::Object(map) => {
            let pairs: Vec<String> = map
                .iter()
                .map(|(key, val)| format!("{}:{}", json_escape(key), canonicalize_json_value(val)))
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
    }
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0C}' => escaped.push_str("\\f"),
            c if c.is_control() => escaped.push_str(&format!("\\u{:04x}", c as u32)),
            c => escaped.push(c),
        }
    }
    escaped.push('"');
    escaped
}

fn base64url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0usize;
    while i + 3 <= data.len() {
        let chunk = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8) | data[i + 2] as u32;
        out.push(ALPHABET[((chunk >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((chunk >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((chunk >> 6) & 0x3f) as usize] as char);
        out.push(ALPHABET[(chunk & 0x3f) as usize] as char);
        i += 3;
    }
    let rem = data.len() - i;
    if rem == 1 {
        let chunk = (data[i] as u32) << 16;
        out.push(ALPHABET[((chunk >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((chunk >> 12) & 0x3f) as usize] as char);
    } else if rem == 2 {
        let chunk = ((data[i] as u32) << 16) | ((data[i + 1] as u32) << 8);
        out.push(ALPHABET[((chunk >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((chunk >> 12) & 0x3f) as usize] as char);
        out.push(ALPHABET[((chunk >> 6) & 0x3f) as usize] as char);
    }
    out
}

pub fn create_aigp_event(options: CreateEventOptions) -> Result<AIGPEvent, String> {
    let event_type = normalize_event_type(&options.event_type)?;
    let trace_id = match options.trace_id {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => random_hex(16)?,
    };
    let sequence_number = match options.sequence_number {
        Some(value) if value > 0 => value,
        _ => next_sequence_number(&options.agent_id, &trace_id),
    };
    let governance_hash = match options.governance_hash {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => return Err("governance_hash is required and cannot be empty".to_string()),
    };

    Ok(AIGPEvent {
        event_id: generate_event_id()?,
        event_type,
        event_category: normalize_event_category(options.event_category.as_deref().unwrap_or("")),
        event_time: now_iso8601_utc(),
        agent_id: options.agent_id,
        governance_hash,
        trace_id,
        span_id: options.span_id.unwrap_or_default(),
        parent_span_id: options.parent_span_id.unwrap_or_default(),
        trace_flags: options.trace_flags.unwrap_or_default(),
        agent_name: options.agent_name.unwrap_or_default(),
        org_id: options.org_id.unwrap_or_default(),
        org_name: options.org_name.unwrap_or_default(),
        policy_id: options.policy_id.unwrap_or_default(),
        policy_name: options.policy_name.unwrap_or_default(),
        policy_version: options.policy_version.unwrap_or(0),
        prompt_id: options.prompt_id.unwrap_or_default(),
        prompt_name: options.prompt_name.unwrap_or_default(),
        prompt_version: options.prompt_version.unwrap_or(0),
        hash_type: options.hash_type.unwrap_or_else(|| "sha256".to_string()),
        data_classification: options.data_classification.unwrap_or_default(),
        template_rendered: options.template_rendered.unwrap_or(false),
        denial_reason: options.denial_reason.unwrap_or_default(),
        violation_type: options.violation_type.unwrap_or_default(),
        severity: options.severity.unwrap_or_default(),
        source_ip: options.source_ip.unwrap_or_default(),
        request_method: options.request_method.unwrap_or_default(),
        request_path: options.request_path.unwrap_or_default(),
        query_hash: options.query_hash.unwrap_or_default(),
        previous_hash: options.previous_hash.unwrap_or_default(),
        annotations: options.annotations.unwrap_or_default(),
        event_signature: options.event_signature.unwrap_or_default(),
        signature_key_id: options.signature_key_id.unwrap_or_default(),
        sequence_number,
        causality_ref: options.causality_ref.unwrap_or_default(),
        spec_version: options.spec_version.unwrap_or_else(|| "0.10.0".to_string()),
        governance_merkle_tree: options.governance_merkle_tree,
    })
}

fn next_sequence_number(agent_id: &str, trace_id: &str) -> i64 {
    let key = format!("{}|{}", agent_id.trim(), trace_id.trim());
    let counters = SEQUENCE_COUNTERS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = counters.lock().expect("sequence counter lock poisoned");
    let next = guard.get(&key).copied().unwrap_or(0) + 1;
    guard.insert(key, next);
    next
}

pub fn validate_aigp_event(event: &AIGPEvent) -> Vec<String> {
    let mut errors = Vec::<String>::new();

    if event.event_id.is_empty() {
        errors.push("missing required field: event_id".to_string());
    }
    if event.event_type.is_empty() {
        errors.push("missing required field: event_type".to_string());
    } else if !is_valid_event_type(&event.event_type) {
        errors.push("event_type must match ^[A-Z][A-Z0-9_]*$".to_string());
    }
    if event.event_category.is_empty() {
        errors.push("missing required field: event_category".to_string());
    }
    if event.event_time.is_empty() {
        errors.push("missing required field: event_time".to_string());
    }
    if event.agent_id.is_empty() {
        errors.push("missing required field: agent_id".to_string());
    }
    if event.trace_id.is_empty() {
        errors.push("missing required field: trace_id".to_string());
    } else if !is_valid_trace_id(&event.trace_id, &event.span_id) {
        if !event.span_id.is_empty() {
            errors
                .push("trace_id must be 32-char lowercase hex when span_id is present".to_string());
        } else {
            errors.push(
                "trace_id must be 32-char lowercase hex, UUID v4, or trace-/req- prefixed UUID v4"
                    .to_string(),
            );
        }
    }
    if event.governance_hash.trim().is_empty() {
        errors.push("governance_hash must be a non-empty string".to_string());
    }
    if event.sequence_number < 1 {
        errors.push("sequence_number must be an integer >= 1".to_string());
    }

    errors
}

pub fn ce_type_from_event_type(event_type: &str) -> Result<String, String> {
    Ok(format!(
        "{AIGP_TYPE_PREFIX}{}",
        normalize_event_type(event_type)?.to_ascii_lowercase()
    ))
}

pub fn event_type_from_ce_type(ce_type: &str) -> Result<String, String> {
    if !ce_type.starts_with(AIGP_TYPE_PREFIX) {
        return Err(format!(
            "cloudevents type {ce_type:?} does not start with {AIGP_TYPE_PREFIX:?}"
        ));
    }
    Ok(ce_type[AIGP_TYPE_PREFIX.len()..].to_string())
}

pub fn wrap_as_cloudevent(
    event: &AIGPEvent,
    include_dataschema: bool,
) -> Result<CloudEvent, String> {
    if event.event_id.is_empty() || event.event_type.is_empty() || event.agent_id.is_empty() {
        return Err(
            "aigp event must have event_id, event_type, and agent_id to wrap as cloudevent"
                .to_string(),
        );
    }

    let org_id = if event.org_id.is_empty() {
        "default".to_string()
    } else {
        event.org_id.clone()
    };

    Ok(CloudEvent {
        specversion: CE_SPECVERSION.to_string(),
        id: event.event_id.clone(),
        r#type: ce_type_from_event_type(&event.event_type)?,
        source: format!("{AIGP_SOURCE_SCHEME}{org_id}/{}", event.agent_id),
        datacontenttype: "application/json".to_string(),
        time: if event.event_time.is_empty() {
            None
        } else {
            Some(event.event_time.clone())
        },
        dataschema: if include_dataschema {
            Some(AIGP_DATA_SCHEMA.to_string())
        } else {
            None
        },
        subject: if !event.policy_name.is_empty() {
            Some(event.policy_name.clone())
        } else if !event.prompt_name.is_empty() {
            Some(event.prompt_name.clone())
        } else {
            None
        },
        aigpagentid: event.agent_id.clone(),
        aigporgid: if org_id == "default" {
            None
        } else {
            Some(org_id)
        },
        aigpcategory: if event.event_category.is_empty() {
            None
        } else {
            Some(event.event_category.clone())
        },
        aigpclassification: if event.data_classification.is_empty() {
            None
        } else {
            Some(event.data_classification.clone())
        },
        aigpseverity: if event.severity.is_empty() {
            None
        } else {
            Some(event.severity.clone())
        },
        aigphashtype: if event.hash_type.is_empty() {
            None
        } else {
            Some(event.hash_type.clone())
        },
        data: event.clone(),
    })
}

pub fn unwrap_from_cloudevent(ce: &CloudEvent) -> Result<AIGPEvent, String> {
    if ce.specversion != CE_SPECVERSION {
        return Err(format!(
            "unsupported cloudevents specversion: {:?}",
            ce.specversion
        ));
    }
    if !ce.r#type.starts_with(AIGP_TYPE_PREFIX) {
        return Err(format!(
            "cloudevents type {:?} does not start with {:?}",
            ce.r#type, AIGP_TYPE_PREFIX
        ));
    }
    Ok(ce.data.clone())
}

pub fn build_ce_headers(
    event: &AIGPEvent,
    prefix: Option<&str>,
) -> Result<HashMap<String, String>, String> {
    let actual_prefix = prefix.unwrap_or("ce-");
    let ce_type = ce_type_from_event_type(&event.event_type)?;
    let org_id = if event.org_id.is_empty() {
        "default".to_string()
    } else {
        event.org_id.clone()
    };

    let mut headers = HashMap::<String, String>::new();
    headers.insert(
        format!("{actual_prefix}specversion"),
        CE_SPECVERSION.to_string(),
    );
    headers.insert(format!("{actual_prefix}id"), event.event_id.clone());
    headers.insert(format!("{actual_prefix}type"), ce_type);
    headers.insert(
        format!("{actual_prefix}source"),
        format!("{AIGP_SOURCE_SCHEME}{org_id}/{}", event.agent_id),
    );
    headers.insert(
        format!("{actual_prefix}aigpagentid"),
        event.agent_id.clone(),
    );

    if !event.event_time.is_empty() {
        headers.insert(format!("{actual_prefix}time"), event.event_time.clone());
    }
    if org_id != "default" {
        headers.insert(format!("{actual_prefix}aigporgid"), org_id);
    }
    if !event.event_category.is_empty() {
        headers.insert(
            format!("{actual_prefix}aigpcategory"),
            event.event_category.clone(),
        );
    }
    if !event.data_classification.is_empty() {
        headers.insert(
            format!("{actual_prefix}aigpclassification"),
            event.data_classification.clone(),
        );
    }
    if !event.severity.is_empty() {
        headers.insert(
            format!("{actual_prefix}aigpseverity"),
            event.severity.clone(),
        );
    }
    if !event.hash_type.is_empty() {
        headers.insert(
            format!("{actual_prefix}aigphashtype"),
            event.hash_type.clone(),
        );
    }

    Ok(headers)
}

fn event_type_alias(value: &str) -> Option<&'static str> {
    match value {
        "governance.policy.delivered" => Some("INJECT_SUCCESS"),
        "governance.policy.denied" => Some("INJECT_DENIED"),
        "governance.prompt.delivered" => Some("PROMPT_USED"),
        "governance.prompt.denied" => Some("PROMPT_DENIED"),
        "governance.policy.violation" => Some("POLICY_VIOLATION"),
        "governance.a2a.call" => Some("A2A_CALL"),
        "governance.tool.invoked" => Some("TOOL_INVOKED"),
        "governance.tool.denied" => Some("TOOL_DENIED"),
        "governance.boundary.unverified" => Some("UNVERIFIED_BOUNDARY"),
        "governance.inference.started" => Some("INFERENCE_STARTED"),
        "governance.inference.completed" => Some("INFERENCE_COMPLETED"),
        "governance.inference.blocked" => Some("INFERENCE_BLOCKED"),
        "governance.model.loaded" => Some("MODEL_LOADED"),
        "governance.model.switched" => Some("MODEL_SWITCHED"),
        "governance.memory.read" => Some("MEMORY_READ"),
        "governance.memory.written" => Some("MEMORY_WRITTEN"),
        "governance.proof" => Some("GOVERNANCE_PROOF"),
        "governance.proof.delivered" => Some("GOVERNANCE_PROOF"),
        _ => None,
    }
}

fn is_valid_event_type(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_uppercase() {
        return false;
    }
    chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

fn is_valid_resource_type(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    let bytes = value.as_bytes();
    if !(bytes[0] as char).is_ascii_lowercase() {
        return false;
    }
    let mut prev_dash = false;
    for &b in &bytes[1..] {
        let c = b as char;
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            prev_dash = false;
            continue;
        }
        if c == '-' {
            if prev_dash {
                return false;
            }
            prev_dash = true;
            continue;
        }
        return false;
    }
    !prev_dash
}

fn is_valid_trace_id(trace_id: &str, span_id: &str) -> bool {
    if !span_id.is_empty() {
        return is_valid_otel_trace_id(trace_id);
    }
    is_valid_otel_trace_id(trace_id)
        || is_valid_uuid_v4(trace_id)
        || is_valid_prefixed_uuid_v4(trace_id)
}

fn is_valid_otel_trace_id(value: &str) -> bool {
    value.len() == 32
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn is_valid_prefixed_uuid_v4(value: &str) -> bool {
    if let Some(uuid) = value.strip_prefix("trace-") {
        return is_valid_uuid_v4(uuid);
    }
    if let Some(uuid) = value.strip_prefix("req-") {
        return is_valid_uuid_v4(uuid);
    }
    false
}

fn is_valid_uuid_v4(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (idx, b) in bytes.iter().enumerate() {
        match idx {
            8 | 13 | 18 | 23 => {
                if *b != b'-' {
                    return false;
                }
            }
            14 => {
                if *b != b'4' {
                    return false;
                }
            }
            19 => {
                let c = (*b as char).to_ascii_lowercase();
                if c != '8' && c != '9' && c != 'a' && c != 'b' {
                    return false;
                }
            }
            _ => {
                if !(*b as char).is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

fn compute_merkle_root(sorted_hashes: &[String]) -> Result<String, String> {
    if sorted_hashes.is_empty() {
        return Err("cannot compute merkle root of empty list".to_string());
    }
    if sorted_hashes.len() == 1 {
        return Ok(sorted_hashes[0].clone());
    }

    let mut level = sorted_hashes.to_vec();
    while level.len() > 1 {
        let mut next = Vec::<String>::with_capacity((level.len() + 1) / 2);
        let mut i = 0usize;
        while i < level.len() {
            if i + 1 >= level.len() {
                next.push(level[i].clone());
            } else {
                next.push(compute_governance_hash(
                    &format!("{}{}", level[i], level[i + 1]),
                    Some("sha256"),
                )?);
            }
            i += 2;
        }
        level = next;
    }
    Ok(level[0].clone())
}

fn random_hex(bytes: usize) -> Result<String, String> {
    Ok(hex_encode(&random_bytes(bytes)?))
}

fn generate_event_id() -> Result<String, String> {
    let mut bytes = random_bytes(16)?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let h = hex_encode(&bytes);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

fn random_bytes(len: usize) -> Result<Vec<u8>, String> {
    let mut file = File::open("/dev/urandom").map_err(|err| err.to_string())?;
    let mut out = vec![0u8; len];
    file.read_exact(&mut out).map_err(|err| err.to_string())?;
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn now_iso8601_utc() -> String {
    let now = SystemTime::now();
    let duration = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0));
    let secs = duration.as_secs() as i64;
    let millis = duration.subsec_millis();

    let (year, month, day, hour, minute, second) = unix_seconds_to_utc(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn unix_seconds_to_utc(seconds: i64) -> (i32, u32, u32, u32, u32, u32) {
    let days = seconds.div_euclid(86_400);
    let sec_of_day = seconds.rem_euclid(86_400) as u32;
    let (year, month, day) = civil_from_days(days);

    let hour = sec_of_day / 3600;
    let minute = (sec_of_day % 3600) / 60;
    let second = sec_of_day % 60;

    (year, month, day, hour, minute, second)
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if month <= 2 { 1 } else { 0 };
    (year as i32, month as u32, day as u32)
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    const H0: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut message = data.to_vec();
    message.push(0x80);
    while (message.len() % 64) != 56 {
        message.push(0x00);
    }
    let bit_len = (data.len() as u64) * 8;
    message.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = H0;

    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            let base = i * 4;
            w[i] = u32::from_be_bytes([
                chunk[base],
                chunk[base + 1],
                chunk[base + 2],
                chunk[base + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha512_core(data: &[u8], mut h: [u64; 8]) -> [u64; 8] {
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    let mut message = data.to_vec();
    message.push(0x80);
    while (message.len() % 128) != 112 {
        message.push(0x00);
    }
    let bit_len = (data.len() as u128) * 8;
    message.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in message.chunks_exact(128) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            let base = i * 8;
            w[i] = u64::from_be_bytes([
                chunk[base],
                chunk[base + 1],
                chunk[base + 2],
                chunk[base + 3],
                chunk[base + 4],
                chunk[base + 5],
                chunk[base + 6],
                chunk[base + 7],
            ]);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    h
}

fn sha512_bytes(data: &[u8]) -> [u8; 64] {
    let h = sha512_core(
        data,
        [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ],
    );

    let mut out = [0u8; 64];
    for (i, word) in h.iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn sha384_bytes(data: &[u8]) -> [u8; 48] {
    let h = sha512_core(
        data,
        [
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4,
        ],
    );

    let mut out = [0u8; 48];
    for (i, word) in h.iter().take(6).enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::fs;
    use std::rc::Rc;

    #[test]
    fn normalize_event_type_maps_aliases() {
        assert_eq!(
            normalize_event_type("governance.policy.delivered").unwrap(),
            "INJECT_SUCCESS"
        );
        assert_eq!(
            normalize_event_type("governance.prompt.denied").unwrap(),
            "PROMPT_DENIED"
        );
    }

    #[test]
    fn normalize_event_type_normalizes_custom_names() {
        assert_eq!(
            normalize_event_type("myplatform.audit.login").unwrap(),
            "MYPLATFORM_AUDIT_LOGIN"
        );
    }

    #[test]
    fn create_and_validate_event() {
        let event = create_aigp_event(CreateEventOptions {
            event_type: "governance.policy.delivered".to_string(),
            event_category: Some("Inject".to_string()),
            agent_id: "agent.test".to_string(),
            trace_id: None,
            governance_hash: Some(compute_governance_hash("policy", Some("sha256")).unwrap()),
            span_id: None,
            parent_span_id: None,
            trace_flags: None,
            agent_name: None,
            org_id: None,
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
        })
        .unwrap();

        assert_eq!(event.event_type, "INJECT_SUCCESS");
        assert_eq!(event.event_category, "inject");
        assert_eq!(event.trace_id.len(), 32);
        assert_eq!(event.spec_version, "0.10.0");
        assert!(validate_aigp_event(&event).is_empty());
    }

    #[test]
    fn compute_merkle_governance_hash_single_and_multi() {
        let single =
            compute_merkle_governance_hash(&[Resource::new("policy", "policy.limits", "Max $10M")])
                .unwrap();
        assert!(single.merkle_tree.is_none());
        assert_eq!(
            single.root_hash,
            compute_governance_hash("Max $10M", Some("sha256")).unwrap()
        );

        let multi = compute_merkle_governance_hash(&[
            Resource::new("policy", "policy.limits", "Max $10M"),
            Resource::new("prompt", "prompt.system", "You are a trading assistant"),
        ])
        .unwrap();
        assert!(multi.merkle_tree.is_some());
        assert_eq!(multi.merkle_tree.unwrap().leaf_count, 2);
    }

    #[test]
    fn compute_merkle_governance_hash_with_proofs_enabled() {
        let result = compute_merkle_governance_hash_with_proofs(
            &[
                Resource::new("policy", "policy.limits", "Max $10M"),
                Resource::new("prompt", "prompt.system", "You are a trading assistant"),
                Resource::new("tool", "tool.search", "{\"scope\":\"read\"}"),
            ],
            true,
        )
        .unwrap();

        let tree = result.merkle_tree.unwrap();
        assert!(tree.inclusion_proofs.is_some());
        let proofs = tree.inclusion_proofs.unwrap();
        assert_eq!(proofs.len(), tree.leaf_count);
        for proof in &proofs {
            assert!(verify_inclusion_proof(&result.root_hash, &proof.leaf_hash, &proof.proof_path).unwrap());
        }
    }

    #[test]
    fn verify_inclusion_proof_detects_tamper() {
        let result = compute_merkle_governance_hash_with_proofs(
            &[
                Resource::new("policy", "policy.limits", "Max $10M"),
                Resource::new("prompt", "prompt.system", "You are a trading assistant"),
                Resource::new("tool", "tool.search", "{\"scope\":\"read\"}"),
            ],
            true,
        )
        .unwrap();
        let tree = result.merkle_tree.unwrap();
        let sample = tree.inclusion_proofs.unwrap()[0].clone();
        let mut tampered = sample.proof_path.clone();
        if !tampered.is_empty() {
            tampered[0].sibling_hash = "0".repeat(64);
        }
        assert!(!verify_inclusion_proof(&result.root_hash, &sample.leaf_hash, &tampered).unwrap());
    }

    struct DummySigner;

    impl EventSigner for DummySigner {
        fn algorithm(&self) -> &str {
            "DUMMY"
        }

        fn key_id(&self) -> &str {
            "key.test"
        }

        fn sign(&self, signing_input: &[u8]) -> Result<Vec<u8>, String> {
            compute_governance_hash(&hex_encode(signing_input), Some("sha256"))
                .map(|h| h.into_bytes())
        }
    }

    #[test]
    fn sign_event_with_signer_sets_signature_fields() {
        let event = create_aigp_event(CreateEventOptions {
            event_type: "INJECT_SUCCESS".to_string(),
            event_category: Some("inject".to_string()),
            agent_id: "agent.test".to_string(),
            trace_id: Some("a".repeat(32)),
            governance_hash: Some(compute_governance_hash("policy", Some("sha256")).unwrap()),
            span_id: None,
            parent_span_id: None,
            trace_flags: None,
            agent_name: None,
            org_id: None,
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
        })
        .unwrap();

        let signed = sign_event_with_signer(&event, &DummySigner).unwrap();
        assert_eq!(signed.signature_key_id, "key.test");
        assert!(!signed.event_signature.is_empty());
        assert_eq!(signed.event_signature.split('.').count(), 3);
    }

    #[test]
    fn reliable_emitter_retries_and_deduplicates() {
        let attempts = Rc::new(RefCell::new(0usize));
        let sent = Rc::new(RefCell::new(Vec::<String>::new()));

        let attempts_clone = attempts.clone();
        let sent_clone = sent.clone();
        let sender = move |event: &AIGPEvent| -> Result<(), String> {
            let mut n = attempts_clone.borrow_mut();
            *n += 1;
            if *n < 3 {
                return Err("transient".to_string());
            }
            sent_clone.borrow_mut().push(event.event_id.clone());
            Ok(())
        };

        let mut emitter = ReliableEmitter::new(
            sender,
            Some(RetryPolicy {
                max_attempts: 3,
                base_delay: Duration::from_millis(0),
                max_delay: Duration::from_millis(0),
            }),
            true,
        );
        let event = AIGPEvent {
            event_id: "evt-1".to_string(),
            event_type: "INJECT_SUCCESS".to_string(),
            event_category: "inject".to_string(),
            event_time: "".to_string(),
            agent_id: "agent.test".to_string(),
            governance_hash: "abc".to_string(),
            trace_id: "a".repeat(32),
            span_id: "".to_string(),
            parent_span_id: "".to_string(),
            trace_flags: "".to_string(),
            agent_name: "".to_string(),
            org_id: "".to_string(),
            org_name: "".to_string(),
            policy_id: "".to_string(),
            policy_name: "".to_string(),
            policy_version: 0,
            prompt_id: "".to_string(),
            prompt_name: "".to_string(),
            prompt_version: 0,
            hash_type: "sha256".to_string(),
            data_classification: "".to_string(),
            template_rendered: false,
            denial_reason: "".to_string(),
            violation_type: "".to_string(),
            severity: "".to_string(),
            source_ip: "".to_string(),
            request_method: "".to_string(),
            request_path: "".to_string(),
            query_hash: "".to_string(),
            previous_hash: "".to_string(),
            annotations: BTreeMap::new(),
            event_signature: "".to_string(),
            signature_key_id: "".to_string(),
            sequence_number: 1,
            causality_ref: "".to_string(),
            spec_version: "0.10.0".to_string(),
            governance_merkle_tree: None,
        };

        assert!(emitter.emit(&event));
        assert_eq!(*attempts.borrow(), 3);
        assert_eq!(sent.borrow().len(), 1);
        assert!(emitter.emit(&event));
        assert_eq!(sent.borrow().len(), 1);
    }

    #[test]
    fn hash_mode_validation() {
        assert!(
            compute_leaf_hash("policy", "policy.limits", "Max $10M", Some("bogus"), None).is_err()
        );

        let bad_pointer = Resource {
            resource_type: "policy".to_string(),
            resource_name: "policy.limits".to_string(),
            content: String::new(),
            hash_mode: Some("pointer".to_string()),
            content_ref: None,
        };
        assert!(compute_merkle_governance_hash(&[bad_pointer]).is_err());
    }

    #[test]
    fn cloud_events_helpers() {
        let event = create_aigp_event(CreateEventOptions {
            event_type: "INJECT_SUCCESS".to_string(),
            event_category: Some("inject".to_string()),
            agent_id: "agent.test".to_string(),
            trace_id: None,
            governance_hash: Some(compute_governance_hash("policy", Some("sha256")).unwrap()),
            span_id: None,
            parent_span_id: None,
            trace_flags: None,
            agent_name: None,
            org_id: Some("org.acme".to_string()),
            org_name: None,
            policy_id: None,
            policy_name: Some("policy.limits".to_string()),
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
        })
        .unwrap();

        let ce = wrap_as_cloudevent(&event, true).unwrap();
        assert_eq!(ce.r#type, "org.aigp.v1.inject_success");
        assert_eq!(ce.source, "aigp://org.acme/agent.test");
        assert_eq!(ce.subject.as_deref(), Some("policy.limits"));

        let headers = build_ce_headers(&event, Some("ce-")).unwrap();
        assert_eq!(
            headers.get("ce-type").map(String::as_str),
            Some("org.aigp.v1.inject_success")
        );
        assert_eq!(
            headers.get("ce-aigpagentid").map(String::as_str),
            Some("agent.test")
        );
    }

    #[test]
    fn create_rejects_empty_governance_hash() {
        let result = create_aigp_event(CreateEventOptions {
            event_type: "AGENT_REGISTERED".to_string(),
            event_category: Some("agent-lifecycle".to_string()),
            agent_id: "agent.test".to_string(),
            trace_id: Some("trace-550e8400-e29b-41d4-a716-446655440000".to_string()),
            governance_hash: Some(String::new()),
            span_id: None,
            parent_span_id: None,
            trace_flags: None,
            agent_name: None,
            org_id: None,
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
        });

        assert!(result.is_err());
    }

    #[test]
    fn validate_requires_w3c_trace_when_span_present() {
        let event = create_aigp_event(CreateEventOptions {
            event_type: "INJECT_SUCCESS".to_string(),
            event_category: Some("inject".to_string()),
            agent_id: "agent.test".to_string(),
            trace_id: Some("trace-550e8400-e29b-41d4-a716-446655440000".to_string()),
            governance_hash: Some("abc".to_string()),
            span_id: Some("00f067aa0ba902b7".to_string()),
            parent_span_id: None,
            trace_flags: None,
            agent_name: None,
            org_id: None,
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
        })
        .unwrap();

        let errors = validate_aigp_event(&event);
        assert!(errors
            .iter()
            .any(|e| e.contains("trace_id must be 32-char lowercase hex when span_id is present")));
    }

    #[test]
    fn hash_vectors_match_known_results() {
        assert_eq!(
            compute_governance_hash("abc", Some("sha256")).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            compute_governance_hash("abc", Some("sha384")).unwrap(),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
        assert_eq!(
            compute_governance_hash("abc", Some("sha512")).unwrap(),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn conformance_fixtures() {
        let content = fs::read_to_string("../conformance/validation-fixtures.tsv")
            .expect("failed to read conformance fixtures");

        let mut lines = content.lines();
        let header_line = lines.next().expect("missing fixture header");
        let headers: Vec<&str> = header_line.split('\t').collect();

        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            let parts: Vec<&str> = line.split('\t').collect();
            assert_eq!(parts.len(), headers.len(), "invalid fixture row: {line}");
            let mut row = std::collections::HashMap::new();
            for (i, header) in headers.iter().enumerate() {
                row.insert(*header, parts[i]);
            }

            let sequence_number = row
                .get("sequence_number")
                .unwrap_or(&"0")
                .parse::<i64>()
                .expect("invalid sequence_number");

            let event_result = create_aigp_event(CreateEventOptions {
                event_type: row["event_type"].to_string(),
                event_category: Some(row["event_category"].to_string()),
                agent_id: "agent.test".to_string(),
                trace_id: Some(row["trace_id"].to_string()),
                governance_hash: Some(row["governance_hash"].to_string()),
                span_id: if row["span_id"].is_empty() {
                    None
                } else {
                    Some(row["span_id"].to_string())
                },
                parent_span_id: None,
                trace_flags: None,
                agent_name: None,
                org_id: None,
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
                sequence_number: Some(sequence_number),
                causality_ref: Some(row["causality_ref"].to_string()),
                spec_version: None,
                governance_merkle_tree: None,
            });
            let mut is_valid = false;
            if let Ok(mut event) = event_result {
                event.sequence_number = sequence_number;
                event.causality_ref = row["causality_ref"].to_string();
                is_valid = validate_aigp_event(&event).is_empty();
            }
            let expect_valid = row["expect_valid"] == "true";
            assert_eq!(is_valid, expect_valid, "fixture failed: {}", row["case_id"]);
        }
    }
}
