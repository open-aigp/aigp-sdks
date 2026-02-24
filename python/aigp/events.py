"""
AIGP Event Creation
===================

Functions for creating AIGP-compliant governance events with
OpenTelemetry correlation fields (span_id, parent_span_id, trace_flags).

v0.8.0 adds proof integrity (event signing via JWS ES256),
monotonic sequencing, causality references, and the Pointer Pattern
for large/external resource governance.
"""

import base64
import hashlib
import json
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, Union

# Pattern for valid resource types (AIGP Spec Section 8.8.2).
# Open pattern: lowercase kebab-case. Standard types: policy, prompt, tool, lineage, context, memory, model.
# Implementations MAY define custom types matching this pattern.
_RESOURCE_TYPE_PATTERN = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
_EVENT_TYPE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")

# Backward-compatible aliases from old dotted event types to AIGP standard types.
_EVENT_TYPE_ALIASES = {
    "governance.policy.delivered": "INJECT_SUCCESS",
    "governance.policy.denied": "INJECT_DENIED",
    "governance.prompt.delivered": "PROMPT_USED",
    "governance.prompt.denied": "PROMPT_DENIED",
    "governance.policy.violation": "POLICY_VIOLATION",
    "governance.a2a.call": "A2A_CALL",
    "governance.tool.invoked": "TOOL_INVOKED",
    "governance.tool.denied": "TOOL_DENIED",
    "governance.boundary.unverified": "UNVERIFIED_BOUNDARY",
    "governance.inference.started": "INFERENCE_STARTED",
    "governance.inference.completed": "INFERENCE_COMPLETED",
    "governance.inference.blocked": "INFERENCE_BLOCKED",
    "governance.model.loaded": "MODEL_LOADED",
    "governance.model.switched": "MODEL_SWITCHED",
    "governance.memory.read": "MEMORY_READ",
    "governance.memory.written": "MEMORY_WRITTEN",
    "governance.proof": "GOVERNANCE_PROOF",
    "governance.proof.delivered": "GOVERNANCE_PROOF",
}
_SEQUENCE_COUNTERS: dict[str, int] = {}
_SEQUENCE_LOCK = threading.Lock()


def _next_sequence_number(agent_id: str, trace_id: str) -> int:
    key = f"{(agent_id or '').strip()}|{(trace_id or '').strip()}"
    with _SEQUENCE_LOCK:
        next_value = _SEQUENCE_COUNTERS.get(key, 0) + 1
        _SEQUENCE_COUNTERS[key] = next_value
        return next_value


def normalize_event_type(event_type: str) -> str:
    """
    Normalize event_type to an AIGP-conformant UPPER_SNAKE_CASE value.

    - Recognized legacy dotted aliases are mapped to standard AIGP event types.
    - Other values are normalized by replacing non-alphanumerics with '_' and
      uppercasing (e.g., ``myplatform.custom.action`` -> ``MYPLATFORM_CUSTOM_ACTION``).
    """
    raw = (event_type or "").strip()
    if not raw:
        raise ValueError("event_type must be a non-empty string")

    mapped = _EVENT_TYPE_ALIASES.get(raw, raw)
    if _EVENT_TYPE_PATTERN.match(mapped):
        return mapped

    normalized = re.sub(r"[^A-Za-z0-9]+", "_", mapped).strip("_").upper()
    if not normalized or not _EVENT_TYPE_PATTERN.match(normalized):
        raise ValueError(
            f"event_type {event_type!r} cannot be normalized to a valid "
            "UPPER_SNAKE_CASE value"
        )
    return normalized


def normalize_event_category(event_category: str) -> str:
    """Normalize event_category to lowercase kebab-case-ish form."""
    raw = (event_category or "").strip().lower()
    if not raw:
        return "governance"
    raw = raw.replace("_", "-")
    raw = re.sub(r"[^a-z0-9-]+", "-", raw).strip("-")
    return raw or "governance"


def compute_governance_hash(
    content: str, algorithm: str = "sha256"
) -> str:
    """
    Compute the governance hash per AIGP spec Section 8.

    - Input: UTF-8 encoded byte representation (no normalization).
    - Output: Lowercase hexadecimal string.
    - SHA-256 produces exactly 64 characters.

    Args:
        content: The governed content to hash.
        algorithm: Hash algorithm ("sha256", "sha384", "sha512").

    Returns:
        Lowercase hexadecimal hash string.
    """
    if algorithm == "sha256":
        return hashlib.sha256(content.encode("utf-8")).hexdigest()
    elif algorithm == "sha384":
        return hashlib.sha384(content.encode("utf-8")).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(content.encode("utf-8")).hexdigest()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")


def compute_leaf_hash(
    resource_type: str,
    resource_name: str,
    content: str,
    hash_mode: str = "content",
    content_ref: str = "",
) -> str:
    """
    Compute a Merkle leaf hash for a single governed resource.

    Leaf = SHA-256(resource_type + ":" + resource_name + ":" + hashable_content)

    The domain separator (resource_type:resource_name:) prevents
    cross-resource collisions: a policy and a prompt with identical
    content produce different leaf hashes.

    Args:
        resource_type: A lowercase kebab-case string matching ^[a-z][a-z0-9]*(-[a-z0-9]+)*$.
            Standard types: "policy", "prompt", "tool", "lineage", "context", "memory", "model".
            Custom types (e.g., "compliance", "approval") are permitted.
        resource_name: AGRN-format name (e.g., "policy.trading-limits").
        content: The governed content string. Used when hash_mode="content".
        hash_mode: "content" (default) hashes the raw content. "pointer" hashes
            the content_ref URI instead — for large/external content (Pointer Pattern).
        content_ref: When hash_mode="pointer", the URI of the immutable content blob
            (e.g., "s3://aigp-governance/sha256:abc123..."). MUST be provided when
            hash_mode="pointer".

    Returns:
        Lowercase hexadecimal hash string (64 chars, SHA-256).
    """
    if not _RESOURCE_TYPE_PATTERN.match(resource_type):
        raise ValueError(
            f"Invalid resource_type: {resource_type!r}. "
            "Must match pattern ^[a-z][a-z0-9]*(-[a-z0-9]+)*$ "
            "(e.g., 'policy', 'prompt', 'tool', 'lineage', 'context', 'memory', 'model', 'compliance')."
        )
    if hash_mode == "pointer":
        if not content_ref:
            raise ValueError("content_ref is required when hash_mode='pointer'")
        hashable = content_ref
    else:
        hashable = content
    prefixed = f"{resource_type}:{resource_name}:{hashable}"
    return hashlib.sha256(prefixed.encode("utf-8")).hexdigest()


def _compute_merkle_root(sorted_hashes: list[str]) -> str:
    """
    Compute Merkle root from a list of sorted leaf hashes.

    Algorithm (AIGP Spec Section 8.8.3):
    - Pair hashes left-to-right: parent = SHA-256(left + right)
    - If odd number, last hash is promoted (not duplicated)
    - Repeat until one root remains.

    The promotion rule (vs. Bitcoin-style duplication) avoids the
    second-preimage vulnerability where a tree with N leaves could
    have the same root as a tree with N+1 identical-last leaves.

    Args:
        sorted_hashes: Leaf hashes in lexicographic ascending order.

    Returns:
        The Merkle root hash (64-char lowercase hex).
    """
    if len(sorted_hashes) == 0:
        raise ValueError("Cannot compute Merkle root of empty list")
    if len(sorted_hashes) == 1:
        return sorted_hashes[0]

    level = list(sorted_hashes)
    while len(level) > 1:
        next_level: list[str] = []
        i = 0
        while i < len(level) - 1:
            combined = level[i] + level[i + 1]
            parent = hashlib.sha256(combined.encode("utf-8")).hexdigest()
            next_level.append(parent)
            i += 2
        if i == len(level) - 1:
            # Odd node: promote without duplication
            next_level.append(level[i])
        level = next_level
    return level[0]


def build_inclusion_proofs(merkle_tree: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Build Merkle inclusion proofs for each leaf in a Merkle tree.

    The returned proof list is ordered to match `merkle_tree["leaves"]`.
    Each proof object contains:
      - leaf_hash
      - proof: ordered list of sibling path steps where each step has:
          - sibling_hash
          - sibling_position ("left" | "right")

    Args:
        merkle_tree: Tree dict from compute_merkle_governance_hash() for
            multi-resource input (contains "leaves" sorted by hash).

    Returns:
        List of proof objects, one per leaf.
    """
    leaves = (merkle_tree or {}).get("leaves", [])
    if not leaves:
        return []

    hashes = [leaf["hash"] for leaf in leaves]
    proofs: list[list[dict[str, str]]] = [[] for _ in hashes]

    # Track which original leaves are represented by each node as we
    # build the tree level-by-level.
    nodes = [
        {"hash": leaf_hash, "leaf_indexes": [idx]}
        for idx, leaf_hash in enumerate(hashes)
    ]

    while len(nodes) > 1:
        next_level: list[dict[str, Any]] = []
        i = 0
        while i < len(nodes) - 1:
            left = nodes[i]
            right = nodes[i + 1]

            for leaf_index in left["leaf_indexes"]:
                proofs[leaf_index].append(
                    {
                        "sibling_hash": right["hash"],
                        "sibling_position": "right",
                    }
                )
            for leaf_index in right["leaf_indexes"]:
                proofs[leaf_index].append(
                    {
                        "sibling_hash": left["hash"],
                        "sibling_position": "left",
                    }
                )

            parent_hash = hashlib.sha256(
                (left["hash"] + right["hash"]).encode("utf-8")
            ).hexdigest()
            next_level.append(
                {
                    "hash": parent_hash,
                    "leaf_indexes": left["leaf_indexes"] + right["leaf_indexes"],
                }
            )
            i += 2

        if i == len(nodes) - 1:
            # Odd node promotion rule: carry node up unchanged.
            next_level.append(nodes[i])

        nodes = next_level

    inclusion_proofs: list[dict[str, Any]] = []
    for idx, leaf in enumerate(leaves):
        inclusion_proofs.append(
            {
                "leaf_hash": leaf["hash"],
                "proof_path": proofs[idx],
            }
        )

    return inclusion_proofs


def verify_inclusion_proof(
    root_hash: str,
    leaf_hash: str,
    proof_path: list[dict[str, str]],
) -> bool:
    """
    Verify a single Merkle inclusion proof against a known root hash.

    Args:
        root_hash: Expected Merkle root hash.
        leaf_hash: Hash of the leaf being verified.
        proof_path: Ordered sibling path list with entries containing:
            - sibling_hash
            - sibling_position ("left" | "right")

    Returns:
        True if the proof reconstructs root_hash, else False.
    """
    current = (leaf_hash or "").strip()
    expected_root = (root_hash or "").strip()
    if not current or not expected_root:
        return False

    for step in proof_path or []:
        sibling_hash = (step.get("sibling_hash", "") or "").strip()
        sibling_position = (step.get("sibling_position", "") or "").strip()
        if not sibling_hash:
            return False

        if sibling_position == "left":
            current = hashlib.sha256((sibling_hash + current).encode("utf-8")).hexdigest()
        elif sibling_position == "right":
            current = hashlib.sha256((current + sibling_hash).encode("utf-8")).hexdigest()
        else:
            raise ValueError(
                "Invalid sibling_position in proof step. "
                "Expected 'left' or 'right'."
            )

    return current == expected_root


def _normalize_resource(
    resource: Union[tuple, dict],
) -> dict[str, str]:
    """Normalize a resource entry to a dict with standard keys."""
    if isinstance(resource, (list, tuple)):
        return {
            "resource_type": resource[0],
            "resource_name": resource[1],
            "content": resource[2],
            "hash_mode": "content",
            "content_ref": "",
        }
    # dict form — Pointer Pattern support
    return {
        "resource_type": resource["resource_type"],
        "resource_name": resource["resource_name"],
        "content": resource.get("content", ""),
        "hash_mode": resource.get("hash_mode", "content"),
        "content_ref": resource.get("content_ref", ""),
    }


def compute_merkle_governance_hash(
    resources: list[Union[tuple[str, str, str], dict[str, Any]]],
    *,
    include_inclusion_proofs: bool = False,
) -> tuple[str, dict | None]:
    """
    Compute Merkle tree governance hash for multiple governed resources.

    If only one resource is provided, returns a flat SHA-256 hash
    (backward compatible with v0.3.0 — no Merkle tree structure).

    If multiple resources are provided, computes a Merkle tree where
    each resource gets its own leaf hash, and the root becomes the
    governance_hash.

    Args:
        resources: List of (resource_type, resource_name, content) tuples
            OR list of dicts with keys: resource_type, resource_name, content,
            and optional hash_mode ("content"|"pointer"), content_ref (URI).
        include_inclusion_proofs: When True and multiple resources are
            provided, adds `inclusion_proofs` sibling-path data to the
            returned Merkle tree for selective verification.

    Returns:
        Tuple of (root_hash, merkle_tree_dict):
        - root_hash: The governance_hash value (64-char hex).
        - merkle_tree_dict: The governance_merkle_tree object, or None
          if only one resource (single resource uses flat hash).
          When include_inclusion_proofs=True, the tree includes
          governance_merkle_tree.inclusion_proofs.
    """
    if not resources:
        raise ValueError("At least one resource is required")

    normalized = [_normalize_resource(r) for r in resources]

    if len(normalized) == 1:
        entry = normalized[0]
        if entry["hash_mode"] == "pointer":
            flat_hash = compute_governance_hash(entry["content_ref"])
        else:
            flat_hash = compute_governance_hash(entry["content"])
        return flat_hash, None

    # Multiple resources: compute Merkle tree
    leaves = []
    for entry in normalized:
        leaf_hash = compute_leaf_hash(
            entry["resource_type"],
            entry["resource_name"],
            entry["content"],
            hash_mode=entry["hash_mode"],
            content_ref=entry["content_ref"],
        )
        leaf: dict[str, Any] = {
            "resource_type": entry["resource_type"],
            "resource_name": entry["resource_name"],
            "hash": leaf_hash,
        }
        # Include hash_mode and content_ref when non-default (Pointer Pattern)
        if entry["hash_mode"] != "content":
            leaf["hash_mode"] = entry["hash_mode"]
        if entry["content_ref"]:
            leaf["content_ref"] = entry["content_ref"]
        leaves.append(leaf)

    # Sort leaves by hash (lexicographic ascending) for deterministic tree
    leaves.sort(key=lambda leaf: leaf["hash"])
    sorted_hashes = [leaf["hash"] for leaf in leaves]

    root = _compute_merkle_root(sorted_hashes)

    merkle_tree = {
        "algorithm": "sha256",
        "leaf_count": len(leaves),
        "leaves": leaves,
    }
    if include_inclusion_proofs:
        merkle_tree["inclusion_proofs"] = build_inclusion_proofs(merkle_tree)

    return root, merkle_tree


# ---------------------------------------------------------------------------
# Event Signing (v0.8.0 — JWS Compact Serialization with ES256)
# ---------------------------------------------------------------------------

def _base64url_encode(data: bytes) -> str:
    """Base64url encode without padding (per RFC 7515)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _base64url_decode(s: str) -> bytes:
    """Base64url decode with padding restoration."""
    s += "=" * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _canonical_json(event: dict[str, Any]) -> bytes:
    """
    Produce canonical JSON for signing: sorted keys, no whitespace,
    excluding event_signature and signature_key_id fields.
    """
    filtered = {
        k: v for k, v in event.items()
        if k not in ("event_signature", "signature_key_id")
    }
    return json.dumps(filtered, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_event(
    event: dict[str, Any],
    private_key_pem: bytes,
    key_id: str = "",
) -> dict[str, Any]:
    """
    Sign an AIGP event using JWS Compact Serialization with ES256.

    The payload is the canonical JSON of the event (sorted keys, no
    whitespace) with event_signature and signature_key_id excluded.

    Args:
        event: An AIGP event dict (as returned by create_aigp_event).
        private_key_pem: PEM-encoded EC private key bytes (P-256 curve).
        key_id: AGRN-style key identifier to record in signature_key_id.

    Returns:
        A copy of the event dict with event_signature (JWS Compact
        Serialization) and signature_key_id populated.

    Raises:
        ImportError: If the ``cryptography`` package is not installed.
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    except ImportError:
        raise ImportError(
            "The 'cryptography' package is required for event signing. "
            "Install it with: pip install cryptography"
        )

    # Load the private key
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    # Build JWS components
    header = {"alg": "ES256", "typ": "JWT"}
    if key_id:
        header["kid"] = key_id

    header_b64 = _base64url_encode(
        json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    payload_b64 = _base64url_encode(_canonical_json(event))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    # Sign with ES256 (ECDSA using P-256 and SHA-256)
    der_signature = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))

    # Convert DER signature to fixed-size r || s (32 bytes each for P-256)
    r, s = decode_dss_signature(der_signature)
    r_bytes = r.to_bytes(32, byteorder="big")
    s_bytes = s.to_bytes(32, byteorder="big")
    signature_b64 = _base64url_encode(r_bytes + s_bytes)

    jws_compact = f"{header_b64}.{payload_b64}.{signature_b64}"

    signed_event = dict(event)
    signed_event["event_signature"] = jws_compact
    signed_event["signature_key_id"] = key_id
    return signed_event


def verify_event_signature(
    event: dict[str, Any],
    public_key_pem: bytes,
) -> bool:
    """
    Verify the JWS ES256 signature on an AIGP event.

    The canonical JSON is recomputed from the event (excluding
    event_signature and signature_key_id), then verified against
    the signature embedded in event_signature.

    Args:
        event: An AIGP event dict containing event_signature.
        public_key_pem: PEM-encoded EC public key bytes (P-256 curve).

    Returns:
        True if the signature is valid, False otherwise.

    Raises:
        ImportError: If the ``cryptography`` package is not installed.
    """
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    except ImportError:
        raise ImportError(
            "The 'cryptography' package is required for event signature "
            "verification. Install it with: pip install cryptography"
        )

    jws_compact = event.get("event_signature", "")
    if not jws_compact:
        return False

    try:
        parts = jws_compact.split(".")
        if len(parts) != 3:
            return False

        header_b64, _payload_b64, signature_b64 = parts

        # Recompute the payload from the event's canonical JSON
        expected_payload_b64 = _base64url_encode(_canonical_json(event))
        signing_input = f"{header_b64}.{expected_payload_b64}".encode("ascii")

        # Decode the fixed-size r || s signature back to DER
        sig_bytes = _base64url_decode(signature_b64)
        if len(sig_bytes) != 64:
            return False
        r = int.from_bytes(sig_bytes[:32], byteorder="big")
        s = int.from_bytes(sig_bytes[32:], byteorder="big")
        der_signature = encode_dss_signature(r, s)

        # Load public key and verify
        public_key = serialization.load_pem_public_key(public_key_pem)
        public_key.verify(der_signature, signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# AIGP Event Creation
# ---------------------------------------------------------------------------

def create_aigp_event(
    event_type: str,
    event_category: str,
    agent_id: str,
    trace_id: str,
    governance_hash: str,
    # OTel correlation fields
    span_id: str = "",
    parent_span_id: str = "",
    trace_flags: str = "",
    # Agent/Org fields
    agent_name: str = "",
    org_id: str = "",
    org_name: str = "",
    # Policy fields
    policy_id: str = "",
    policy_name: str = "",
    policy_version: int = 0,
    # Prompt fields
    prompt_id: str = "",
    prompt_name: str = "",
    prompt_version: int = 0,
    # Governance fields
    hash_type: str = "sha256",
    data_classification: str = "",
    template_rendered: bool = False,
    # Denial fields
    denial_reason: str = "",
    violation_type: str = "",
    severity: str = "",
    # Request fields
    source_ip: str = "",
    request_method: str = "",
    request_path: str = "",
    # Memory governance fields (Section 5.4)
    query_hash: str = "",
    previous_hash: str = "",
    # Annotations (Section 5.7)
    annotations: Optional[dict[str, Any]] = None,
    # Proof integrity fields (v0.8.0)
    event_signature: str = "",
    signature_key_id: str = "",
    sequence_number: int = 0,
    causality_ref: str = "",
    # Version
    spec_version: str = "0.10.0",
    # Merkle tree (Section 8.8)
    governance_merkle_tree: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Create an AIGP event conforming to the v0.10.0 schema.

    This function creates the standalone AIGP JSON event (the governance
    record). For the OTel span event (the observability record), use
    AIGPInstrumentor which handles dual-emit.

    v0.8.0 adds proof integrity fields: event_signature (JWS Compact
    Serialization), signature_key_id (AGRN-style key identifier),
    sequence_number (monotonic per agent_id+trace_id), and
    causality_ref (preceding event_id for causal ordering).

    Args:
        event_type: AIGP event type (e.g., "INJECT_SUCCESS").
        event_category: Event category (e.g., "inject").
        agent_id: AGRN agent identifier (e.g., "agent.trading-bot-v2").
        trace_id: Distributed trace ID (prefer 32-char hex for OTel).
        governance_hash: SHA-256 hash of governed content. MUST be non-empty.
        span_id: OTel span ID (16-char hex). Optional.
        parent_span_id: OTel parent span ID (16-char hex). Optional.
        trace_flags: W3C trace flags (2-char hex). Optional.
        query_hash: SHA-256 of retrieval query (MEMORY_READ). Optional.
        previous_hash: SHA-256 of prior state (MEMORY_WRITTEN, MODEL_SWITCHED). Optional.
        annotations: Informational context (not hashed). Optional.
        event_signature: JWS Compact Serialization. Typically set via sign_event().
        signature_key_id: AGRN-style key identifier for the signing key.
        sequence_number: Monotonic counter per (agent_id, trace_id). Values <= 0 auto-increment.
        causality_ref: event_id of the preceding event in the causal chain.
        spec_version: AIGP spec version. Default "0.10.0".
        governance_merkle_tree: Merkle tree dict (Section 8.8). Optional.

    Returns:
        Dict conforming to AIGP event schema v0.10.0.
    """
    now = datetime.now(timezone.utc)

    normalized_event_type = normalize_event_type(event_type)
    normalized_event_category = normalize_event_category(event_category)
    normalized_trace_id = (trace_id or "").strip() or uuid.uuid4().hex
    normalized_governance_hash = (governance_hash or "").strip()
    if not normalized_governance_hash:
        raise ValueError("governance_hash is required and cannot be empty")
    resolved_sequence_number = (
        int(sequence_number)
        if int(sequence_number) > 0
        else _next_sequence_number(agent_id, normalized_trace_id)
    )

    event = {
        # Required fields (Section 5.1)
        "event_id": str(uuid.uuid4()),
        "event_type": normalized_event_type,
        "event_category": normalized_event_category,
        "event_time": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
        "agent_id": agent_id,
        "governance_hash": normalized_governance_hash,
        "trace_id": normalized_trace_id,
        # OTel correlation fields (Section 11.4)
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "trace_flags": trace_flags,
        # Agent/Org fields (Section 5.2)
        "agent_name": agent_name,
        "org_id": org_id,
        "org_name": org_name,
        # Policy fields (Section 5.3)
        "policy_id": policy_id,
        "policy_name": policy_name,
        "policy_version": policy_version,
        # Prompt fields (Section 5.3)
        "prompt_id": prompt_id,
        "prompt_name": prompt_name,
        "prompt_version": prompt_version,
        # Governance fields (Section 5.4)
        "hash_type": hash_type,
        "data_classification": data_classification,
        # Timestamps and rendering (Section 5.7)
        "template_rendered": template_rendered,
        # Denial fields (Section 5.5)
        "denial_reason": denial_reason,
        "violation_type": violation_type,
        "severity": severity,
        # Request fields (Section 5.6)
        "source_ip": source_ip,
        "request_method": request_method,
        "request_path": request_path,
        # Memory governance fields (Section 5.4)
        "query_hash": query_hash,
        "previous_hash": previous_hash,
        # Annotations (Section 5.7) — informational, not hashed
        "annotations": annotations or {},
        # Proof integrity fields (v0.8.0)
        "event_signature": event_signature,
        "signature_key_id": signature_key_id,
        "sequence_number": resolved_sequence_number,
        "causality_ref": causality_ref,
        # Version (Section 5.7)
        "spec_version": spec_version,
    }

    # Merkle tree (Section 8.8) — only present when used
    if governance_merkle_tree is not None:
        event["governance_merkle_tree"] = governance_merkle_tree

    return event
