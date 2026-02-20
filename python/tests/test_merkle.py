"""
Tests for Merkle Tree Governance Hash
======================================

Tests the AIGP Merkle tree hash computation (Spec Section 8.8):
- Leaf construction with domain separators
- Tree construction with odd-promotion (not duplication)
- Public API for single/multi-resource hashing
- Integration with AIGP event creation
"""

import hashlib
import json
import re

import pytest

from aigp.events import (
    compute_governance_hash,
    compute_leaf_hash,
    compute_merkle_governance_hash,
    build_inclusion_proofs,
    verify_inclusion_proof,
    _compute_merkle_root,
    create_aigp_event,
)


# ============================================================
# TestComputeLeafHash
# ============================================================


class TestComputeLeafHash:
    """Tests for Merkle leaf hash computation (Section 8.8.2)."""

    def test_leaf_hash_is_64_char_hex(self):
        """Leaf hash output is 64-character lowercase hex (SHA-256)."""
        result = compute_leaf_hash("policy", "policy.trading-limits", "Max $10M")
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_domain_separator_prevents_cross_resource_collision(self):
        """Same content with different resource_type produces different hash."""
        content = "You are a helpful assistant."
        policy_hash = compute_leaf_hash("policy", "policy.assistant", content)
        prompt_hash = compute_leaf_hash("prompt", "prompt.assistant", content)
        assert policy_hash != prompt_hash

    def test_resource_name_affects_hash(self):
        """Same type+content but different name produces different hash."""
        content = "Max position: $10M"
        hash_a = compute_leaf_hash("policy", "policy.limits-v1", content)
        hash_b = compute_leaf_hash("policy", "policy.limits-v2", content)
        assert hash_a != hash_b

    def test_leaf_hash_reproducibility(self):
        """Same inputs produce same hash."""
        h1 = compute_leaf_hash("tool", "tool.order-lookup", '{"scope": "read"}')
        h2 = compute_leaf_hash("tool", "tool.order-lookup", '{"scope": "read"}')
        assert h1 == h2

    def test_leaf_hash_matches_manual_computation(self):
        """Leaf hash matches manually computed SHA-256(type:name:content)."""
        rtype, rname, content = "policy", "policy.test", "hello"
        expected = hashlib.sha256(f"{rtype}:{rname}:{content}".encode("utf-8")).hexdigest()
        assert compute_leaf_hash(rtype, rname, content) == expected

    def test_invalid_resource_type_uppercase(self):
        """Uppercase resource_type is rejected."""
        with pytest.raises(ValueError, match="Invalid resource_type"):
            compute_leaf_hash("Policy", "Policy.test", "content")

    def test_invalid_resource_type_empty(self):
        """Empty resource_type is rejected."""
        with pytest.raises(ValueError, match="Invalid resource_type"):
            compute_leaf_hash("", "", "content")

    def test_invalid_resource_type_spaces(self):
        """Resource type with spaces is rejected."""
        with pytest.raises(ValueError, match="Invalid resource_type"):
            compute_leaf_hash("my type", "my type.test", "content")

    def test_invalid_resource_type_underscores(self):
        """Resource type with underscores is rejected (kebab-case only)."""
        with pytest.raises(ValueError, match="Invalid resource_type"):
            compute_leaf_hash("my_type", "my_type.test", "content")

    def test_custom_resource_type_compliance(self):
        """Custom resource type 'compliance' is accepted (open pattern)."""
        result = compute_leaf_hash("compliance", "compliance.finra-3110", "Rule content")
        assert len(result) == 64

    def test_custom_resource_type_approval(self):
        """Custom resource type 'approval' is accepted (open pattern)."""
        result = compute_leaf_hash("approval", "approval.ciso-sign-off", "Approved")
        assert len(result) == 64

    def test_custom_resource_type_kebab_case(self):
        """Custom resource type with hyphens is accepted."""
        result = compute_leaf_hash("audit-log", "audit-log.session-1", "Log data")
        assert len(result) == 64

    def test_utf8_content(self):
        """Leaf hash handles UTF-8 content correctly."""
        h = compute_leaf_hash("policy", "policy.intl", "Richtlinie: Maximal €10M")
        assert len(h) == 64


# ============================================================
# TestComputeMerkleRoot
# ============================================================


class TestComputeMerkleRoot:
    """Tests for internal Merkle root computation (Section 8.8.3)."""

    def test_single_hash_is_identity(self):
        """A single leaf's hash is the root."""
        h = "a" * 64
        assert _compute_merkle_root([h]) == h

    def test_two_leaves_produces_valid_root(self):
        """Two sorted leaves: root = SHA-256(left + right)."""
        left = "a" * 64
        right = "b" * 64
        expected = hashlib.sha256((left + right).encode("utf-8")).hexdigest()
        assert _compute_merkle_root([left, right]) == expected

    def test_three_leaves_odd_promotion(self):
        """Three leaves: pair first two, promote third, then combine."""
        h_a = "1" * 64
        h_b = "2" * 64
        h_c = "3" * 64

        # Level 0: [h_a, h_b, h_c]
        # Level 1: [SHA-256(h_a + h_b), h_c]  (h_c promoted)
        parent_ab = hashlib.sha256((h_a + h_b).encode("utf-8")).hexdigest()
        # Level 2: SHA-256(parent_ab + h_c)
        expected_root = hashlib.sha256((parent_ab + h_c).encode("utf-8")).hexdigest()

        assert _compute_merkle_root([h_a, h_b, h_c]) == expected_root

    def test_four_leaves_balanced_tree(self):
        """Four leaves: two pairs, then root from two parents."""
        hashes = ["1" * 64, "2" * 64, "3" * 64, "4" * 64]

        parent_12 = hashlib.sha256((hashes[0] + hashes[1]).encode("utf-8")).hexdigest()
        parent_34 = hashlib.sha256((hashes[2] + hashes[3]).encode("utf-8")).hexdigest()
        expected_root = hashlib.sha256((parent_12 + parent_34).encode("utf-8")).hexdigest()

        assert _compute_merkle_root(hashes) == expected_root

    def test_five_leaves_mixed_promotion(self):
        """Five leaves: tests multi-level odd promotion."""
        hashes = [f"{i}" * 64 for i in range(1, 6)]
        result = _compute_merkle_root(hashes)
        assert len(result) == 64
        # Just verify it's deterministic
        assert result == _compute_merkle_root(hashes)

    def test_deterministic_regardless_of_input_order(self):
        """If we sort the same set of hashes, result is always the same."""
        hashes = [
            hashlib.sha256(f"content-{i}".encode()).hexdigest()
            for i in range(5)
        ]
        sorted_hashes = sorted(hashes)
        r1 = _compute_merkle_root(sorted_hashes)
        r2 = _compute_merkle_root(sorted_hashes)
        assert r1 == r2

    def test_empty_list_raises(self):
        """Empty list raises ValueError."""
        with pytest.raises(ValueError, match="empty"):
            _compute_merkle_root([])

    def test_promotion_differs_from_duplication(self):
        """Promoted odd node must differ from Bitcoin-style duplication."""
        h_a = "a" * 64
        h_b = "b" * 64
        h_c = "c" * 64

        # Our algorithm: promote h_c
        parent_ab = hashlib.sha256((h_a + h_b).encode("utf-8")).hexdigest()
        our_root = hashlib.sha256((parent_ab + h_c).encode("utf-8")).hexdigest()

        # Bitcoin-style: duplicate h_c
        parent_cc = hashlib.sha256((h_c + h_c).encode("utf-8")).hexdigest()
        bitcoin_root = hashlib.sha256((parent_ab + parent_cc).encode("utf-8")).hexdigest()

        assert our_root != bitcoin_root
        assert _compute_merkle_root([h_a, h_b, h_c]) == our_root


# ============================================================
# TestComputeMerkleGovernanceHash
# ============================================================


class TestComputeMerkleGovernanceHash:
    """Tests for the public Merkle governance hash API (Section 8.8)."""

    def test_single_resource_returns_flat_hash(self):
        """One resource: returns flat SHA-256 hash (backward compatible)."""
        content = "Max position: $10M"
        root, tree = compute_merkle_governance_hash([
            ("policy", "policy.limits", content)
        ])
        assert root == compute_governance_hash(content)

    def test_single_resource_no_merkle_tree(self):
        """One resource: merkle_tree is None (backward compatible)."""
        _, tree = compute_merkle_governance_hash([
            ("policy", "policy.limits", "content")
        ])
        assert tree is None

    def test_multiple_resources_returns_merkle_root(self):
        """Multiple resources: returns a valid Merkle root hash."""
        root, tree = compute_merkle_governance_hash([
            ("policy", "policy.limits", "Max $10M"),
            ("prompt", "prompt.assistant", "You are helpful"),
        ])
        assert len(root) == 64
        assert tree is not None

    def test_merkle_tree_structure(self):
        """Verify merkle_tree_dict has algorithm, leaf_count, leaves."""
        _, tree = compute_merkle_governance_hash([
            ("policy", "policy.a", "content A"),
            ("prompt", "prompt.b", "content B"),
            ("tool", "tool.c", "content C"),
        ])
        assert tree["algorithm"] == "sha256"
        assert tree["leaf_count"] == 3
        assert len(tree["leaves"]) == 3

    def test_leaves_sorted_by_hash(self):
        """Leaves in the returned tree are sorted by hash value."""
        _, tree = compute_merkle_governance_hash([
            ("policy", "policy.z", "ZZZ"),
            ("prompt", "prompt.a", "AAA"),
            ("tool", "tool.m", "MMM"),
        ])
        hashes = [leaf["hash"] for leaf in tree["leaves"]]
        assert hashes == sorted(hashes)

    def test_leaf_count_matches_leaves_length(self):
        """leaf_count equals len(leaves)."""
        _, tree = compute_merkle_governance_hash([
            ("policy", "policy.a", "A"),
            ("policy", "policy.b", "B"),
        ])
        assert tree["leaf_count"] == len(tree["leaves"])

    def test_leaf_structure(self):
        """Each leaf has resource_type, resource_name, and hash."""
        _, tree = compute_merkle_governance_hash([
            ("policy", "policy.test", "content"),
            ("tool", "tool.search", "search def"),
        ])
        for leaf in tree["leaves"]:
            assert "resource_type" in leaf
            assert "resource_name" in leaf
            assert "hash" in leaf
            assert re.match(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$", leaf["resource_type"])
            assert len(leaf["hash"]) == 64

    def test_different_resource_sets_produce_different_roots(self):
        """Adding or changing a resource changes the root."""
        root_2, _ = compute_merkle_governance_hash([
            ("policy", "policy.a", "A"),
            ("policy", "policy.b", "B"),
        ])
        root_3, _ = compute_merkle_governance_hash([
            ("policy", "policy.a", "A"),
            ("policy", "policy.b", "B"),
            ("tool", "tool.c", "C"),
        ])
        assert root_2 != root_3

    def test_order_independence(self):
        """Same resources in different order produce same root (sorting)."""
        root_1, _ = compute_merkle_governance_hash([
            ("policy", "policy.a", "A"),
            ("prompt", "prompt.b", "B"),
            ("tool", "tool.c", "C"),
        ])
        root_2, _ = compute_merkle_governance_hash([
            ("tool", "tool.c", "C"),
            ("policy", "policy.a", "A"),
            ("prompt", "prompt.b", "B"),
        ])
        assert root_1 == root_2

    def test_empty_resources_raises(self):
        """Empty resource list raises ValueError."""
        with pytest.raises(ValueError, match="At least one resource"):
            compute_merkle_governance_hash([])


# ============================================================
# TestMerkleInEvent
# ============================================================


class TestMerkleInEvent:
    """Tests for Merkle tree data in AIGP events."""

    def test_event_with_merkle_tree_is_json_serializable(self):
        """Event with governance_merkle_tree serializes to valid JSON."""
        root, tree = compute_merkle_governance_hash([
            ("policy", "policy.a", "A"),
            ("prompt", "prompt.b", "B"),
        ])
        event = create_aigp_event(
            event_type="GOVERNANCE_PROOF",
            event_category="governance-proof",
            agent_id="agent.test",
            trace_id="a" * 32,
            governance_hash=root,
            hash_type="merkle-sha256",
            governance_merkle_tree=tree,
        )
        serialized = json.dumps(event)
        assert "governance_merkle_tree" in serialized
        assert "merkle-sha256" in serialized

    def test_event_without_merkle_tree_has_no_key(self):
        """When merkle_tree is None, governance_merkle_tree key is absent."""
        event = create_aigp_event(
            event_type="INJECT_SUCCESS",
            event_category="inject",
            agent_id="agent.test",
            trace_id="b" * 32,
            governance_hash="c" * 64,
        )
        assert "governance_merkle_tree" not in event

    def test_hash_type_set_to_merkle_sha256(self):
        """Multi-resource event has hash_type='merkle-sha256'."""
        root, tree = compute_merkle_governance_hash([
            ("policy", "policy.a", "A"),
            ("tool", "tool.b", "B"),
        ])
        event = create_aigp_event(
            event_type="GOVERNANCE_PROOF",
            event_category="governance-proof",
            agent_id="agent.test",
            trace_id="d" * 32,
            governance_hash=root,
            hash_type="merkle-sha256",
            governance_merkle_tree=tree,
        )
        assert event["hash_type"] == "merkle-sha256"
        assert event["governance_merkle_tree"]["leaf_count"] == 2

    def test_merkle_root_is_governance_hash(self):
        """The Merkle root returned is used as governance_hash in the event."""
        root, tree = compute_merkle_governance_hash([
            ("policy", "policy.x", "X"),
            ("prompt", "prompt.y", "Y"),
            ("tool", "tool.z", "Z"),
        ])
        event = create_aigp_event(
            event_type="GOVERNANCE_PROOF",
            event_category="governance-proof",
            agent_id="agent.test",
            trace_id="e" * 32,
            governance_hash=root,
            hash_type="merkle-sha256",
            governance_merkle_tree=tree,
        )
        assert event["governance_hash"] == root
        assert len(event["governance_hash"]) == 64


# ===================================================================
# Context Resource Type Tests (v0.6.0)
# ===================================================================

class TestContextResourceType:
    """Tests for the 'context' resource type in Merkle tree governance."""

    def test_compute_leaf_hash_context_type(self):
        """context is a valid resource_type for leaf hash computation."""
        result = compute_leaf_hash(
            resource_type="context",
            resource_name="context.upstream-lineage",
            content='{"datasets": ["orders", "customers"], "snapshot_time": "2026-02-15T10:00:00Z"}',
        )
        assert len(result) == 64
        assert re.match(r"^[a-f0-9]{64}$", result)

    def test_context_domain_separation(self):
        """A context leaf and other types with identical content produce different hashes."""
        content = "identical content for testing domain separation"
        context_hash = compute_leaf_hash("context", "context.test", content)
        policy_hash = compute_leaf_hash("policy", "policy.test", content)
        prompt_hash = compute_leaf_hash("prompt", "prompt.test", content)
        tool_hash = compute_leaf_hash("tool", "tool.test", content)
        lineage_hash = compute_leaf_hash("lineage", "lineage.test", content)
        memory_hash = compute_leaf_hash("memory", "memory.test", content)
        model_hash = compute_leaf_hash("model", "model.test", content)

        # All seven standard types must produce different hashes
        all_hashes = {context_hash, policy_hash, prompt_hash, tool_hash, lineage_hash, memory_hash, model_hash}
        assert len(all_hashes) == 7

    def test_merkle_tree_with_context_leaf(self):
        """Context resources participate in Merkle tree alongside policies/prompts/tools."""
        resources = [
            ("policy", "policy.trading-limits", "Max position: $10M"),
            ("prompt", "prompt.support-v3", "You are a helpful assistant"),
            ("context", "context.upstream-lineage", '{"datasets": ["orders"]}'),
        ]
        root_hash, merkle_tree = compute_merkle_governance_hash(resources)
        assert len(root_hash) == 64
        assert merkle_tree is not None
        assert merkle_tree["leaf_count"] == 3
        leaf_types = {leaf["resource_type"] for leaf in merkle_tree["leaves"]}
        assert leaf_types == {"policy", "prompt", "context"}


# ===================================================================
# Lineage Resource Type Tests (v0.6.0)
# ===================================================================

class TestLineageResourceType:
    """Tests for the 'lineage' resource type in Merkle tree governance."""

    def test_compute_leaf_hash_lineage_type(self):
        """lineage is a valid resource_type for leaf hash computation."""
        result = compute_leaf_hash(
            resource_type="lineage",
            resource_name="lineage.upstream-orders",
            content='{"datasets": ["orders", "customers"], "snapshot_time": "2026-02-15T10:00:00Z"}',
        )
        assert len(result) == 64
        assert re.match(r"^[a-f0-9]{64}$", result)

    def test_lineage_domain_separation(self):
        """A lineage leaf and other types with identical content produce different hashes."""
        content = "identical content for testing domain separation"
        lineage_hash = compute_leaf_hash("lineage", "lineage.test", content)
        context_hash = compute_leaf_hash("context", "context.test", content)
        policy_hash = compute_leaf_hash("policy", "policy.test", content)
        prompt_hash = compute_leaf_hash("prompt", "prompt.test", content)
        tool_hash = compute_leaf_hash("tool", "tool.test", content)
        memory_hash = compute_leaf_hash("memory", "memory.test", content)
        model_hash = compute_leaf_hash("model", "model.test", content)

        # All seven standard types must produce different hashes
        all_hashes = {lineage_hash, context_hash, policy_hash, prompt_hash, tool_hash, memory_hash, model_hash}
        assert len(all_hashes) == 7

    def test_merkle_tree_with_lineage_leaf(self):
        """Lineage resources participate in Merkle tree alongside other types."""
        resources = [
            ("policy", "policy.trading-limits", "Max position: $10M"),
            ("prompt", "prompt.support-v3", "You are a helpful assistant"),
            ("lineage", "lineage.upstream-orders", '{"datasets": ["orders"]}'),
            ("context", "context.env-config", '{"env": "production"}'),
        ]
        root_hash, merkle_tree = compute_merkle_governance_hash(resources)
        assert len(root_hash) == 64
        assert merkle_tree is not None
        assert merkle_tree["leaf_count"] == 4
        leaf_types = {leaf["resource_type"] for leaf in merkle_tree["leaves"]}
        assert leaf_types == {"policy", "prompt", "lineage", "context"}


# ===================================================================
# Custom Resource Type Tests (v0.6.0 — Open resource_type pattern)
# ===================================================================

class TestCustomResourceType:
    """Tests for custom (non-standard) resource types in Merkle tree governance."""

    def test_custom_type_in_merkle_tree(self):
        """Custom resource types participate in Merkle tree alongside standard types."""
        resources = [
            ("policy", "policy.trading-limits", "Max position: $10M"),
            ("compliance", "compliance.finra-3110", "FINRA Rule 3110 content"),
        ]
        root_hash, merkle_tree = compute_merkle_governance_hash(resources)
        assert len(root_hash) == 64
        assert merkle_tree is not None
        assert merkle_tree["leaf_count"] == 2
        leaf_types = {leaf["resource_type"] for leaf in merkle_tree["leaves"]}
        assert leaf_types == {"policy", "compliance"}

    def test_custom_type_domain_separation(self):
        """Custom type 'compliance' produces different hash from standard types."""
        content = "same content"
        compliance_hash = compute_leaf_hash("compliance", "compliance.test", content)
        policy_hash = compute_leaf_hash("policy", "policy.test", content)
        assert compliance_hash != policy_hash

    def test_pattern_rejects_invalid_types(self):
        """Invalid patterns are still rejected."""
        with pytest.raises(ValueError, match="Invalid resource_type"):
            compute_leaf_hash("POLICY", "POLICY.test", "content")
        with pytest.raises(ValueError, match="Invalid resource_type"):
            compute_leaf_hash("", "", "content")
        with pytest.raises(ValueError, match="Invalid resource_type"):
            compute_leaf_hash("has spaces", "has spaces.test", "content")
        with pytest.raises(ValueError, match="Invalid resource_type"):
            compute_leaf_hash("under_score", "under_score.test", "content")


# ===================================================================
# Memory Resource Type Tests (v0.7.0)
# ===================================================================

class TestMemoryResourceType:
    """Tests for the 'memory' resource type in Merkle tree governance."""

    def test_compute_leaf_hash_memory_type(self):
        """memory is a valid resource_type for leaf hash computation."""
        result = compute_leaf_hash(
            resource_type="memory",
            resource_name="memory.conversation-history",
            content='[{"role": "user", "content": "Hello"}, {"role": "assistant", "content": "Hi!"}]',
        )
        assert len(result) == 64
        assert re.match(r"^[a-f0-9]{64}$", result)

    def test_memory_domain_separation(self):
        """A memory leaf and other types with identical content produce different hashes."""
        content = "identical content for testing domain separation"
        memory_hash = compute_leaf_hash("memory", "memory.test", content)
        policy_hash = compute_leaf_hash("policy", "policy.test", content)
        prompt_hash = compute_leaf_hash("prompt", "prompt.test", content)
        tool_hash = compute_leaf_hash("tool", "tool.test", content)
        lineage_hash = compute_leaf_hash("lineage", "lineage.test", content)
        context_hash = compute_leaf_hash("context", "context.test", content)
        model_hash = compute_leaf_hash("model", "model.test", content)

        # All seven standard types must produce different hashes
        all_hashes = {memory_hash, policy_hash, prompt_hash, tool_hash, lineage_hash, context_hash, model_hash}
        assert len(all_hashes) == 7

    def test_merkle_tree_with_memory_leaf(self):
        """Memory resources participate in Merkle tree alongside other types."""
        resources = [
            ("policy", "policy.trading-limits", "Max position: $10M"),
            ("prompt", "prompt.support-v3", "You are a helpful assistant"),
            ("memory", "memory.conversation-history", '{"messages": []}'),
        ]
        root_hash, merkle_tree = compute_merkle_governance_hash(resources)
        assert len(root_hash) == 64
        assert merkle_tree is not None
        assert merkle_tree["leaf_count"] == 3
        leaf_types = {leaf["resource_type"] for leaf in merkle_tree["leaves"]}
        assert leaf_types == {"policy", "prompt", "memory"}


# ===================================================================
# Model Resource Type Tests (v0.7.0)
# ===================================================================

class TestModelResourceType:
    """Tests for the 'model' resource type in Merkle tree governance."""

    def test_compute_leaf_hash_model_type(self):
        """model is a valid resource_type for leaf hash computation."""
        result = compute_leaf_hash(
            resource_type="model",
            resource_name="model.gpt4-trading-v2",
            content='{"model": "gpt-4", "version": "2024-01", "weights_hash": "abc123"}',
        )
        assert len(result) == 64
        assert re.match(r"^[a-f0-9]{64}$", result)

    def test_model_domain_separation(self):
        """A model leaf and other types with identical content produce different hashes."""
        content = "identical content for testing domain separation"
        model_hash = compute_leaf_hash("model", "model.test", content)
        policy_hash = compute_leaf_hash("policy", "policy.test", content)
        prompt_hash = compute_leaf_hash("prompt", "prompt.test", content)
        tool_hash = compute_leaf_hash("tool", "tool.test", content)
        lineage_hash = compute_leaf_hash("lineage", "lineage.test", content)
        context_hash = compute_leaf_hash("context", "context.test", content)
        memory_hash = compute_leaf_hash("memory", "memory.test", content)

        # All seven standard types must produce different hashes
        all_hashes = {model_hash, policy_hash, prompt_hash, tool_hash, lineage_hash, context_hash, memory_hash}
        assert len(all_hashes) == 7

    def test_merkle_tree_with_model_leaf(self):
        """Model resources participate in Merkle tree alongside other types."""
        resources = [
            ("policy", "policy.trading-limits", "Max position: $10M"),
            ("model", "model.gpt4-trading-v2", '{"model": "gpt-4"}'),
            ("memory", "memory.session-state", '{"turn": 5}'),
        ]
        root_hash, merkle_tree = compute_merkle_governance_hash(resources)
        assert len(root_hash) == 64
        assert merkle_tree is not None
        assert merkle_tree["leaf_count"] == 3
        leaf_types = {leaf["resource_type"] for leaf in merkle_tree["leaves"]}
        assert leaf_types == {"policy", "model", "memory"}

    def test_merkle_tree_all_seven_standard_types(self):
        """All seven standard resource types work together in a single Merkle tree."""
        resources = [
            ("policy", "policy.limits", "Max $10M"),
            ("prompt", "prompt.assist", "You are helpful"),
            ("tool", "tool.search", '{"scope": "read"}'),
            ("lineage", "lineage.upstream", '{"datasets": ["orders"]}'),
            ("context", "context.env", '{"env": "prod"}'),
            ("memory", "memory.history", '{"messages": []}'),
            ("model", "model.gpt4", '{"model": "gpt-4"}'),
        ]
        root_hash, merkle_tree = compute_merkle_governance_hash(resources)
        assert len(root_hash) == 64
        assert merkle_tree is not None
        assert merkle_tree["leaf_count"] == 7
        leaf_types = {leaf["resource_type"] for leaf in merkle_tree["leaves"]}
        assert leaf_types == {"policy", "prompt", "tool", "lineage", "context", "memory", "model"}


# ===================================================================
# Inclusion Proof Tests (v0.10.0)
# ===================================================================

class TestInclusionProofs:
    """Tests for selective Merkle verification helpers."""

    def test_compute_merkle_can_include_proofs(self):
        resources = [
            ("policy", "policy.limits", "Max $10M"),
            ("prompt", "prompt.assist", "You are helpful"),
            ("tool", "tool.search", '{"scope":"read"}'),
        ]
        root_hash, merkle_tree = compute_merkle_governance_hash(
            resources,
            include_inclusion_proofs=True,
        )
        assert merkle_tree is not None
        assert "inclusion_proofs" in merkle_tree
        assert len(merkle_tree["inclusion_proofs"]) == merkle_tree["leaf_count"]

        for proof_entry in merkle_tree["inclusion_proofs"]:
            assert verify_inclusion_proof(
                root_hash,
                proof_entry["leaf_hash"],
                proof_entry["proof_path"],
            )

    def test_build_inclusion_proofs_from_tree(self):
        root_hash, merkle_tree = compute_merkle_governance_hash(
            [
                ("policy", "policy.a", "A"),
                ("prompt", "prompt.b", "B"),
            ]
        )
        assert merkle_tree is not None
        inclusion_proofs = build_inclusion_proofs(merkle_tree)
        assert len(inclusion_proofs) == 2
        for proof_entry in inclusion_proofs:
            assert verify_inclusion_proof(root_hash, proof_entry["leaf_hash"], proof_entry["proof_path"])

    def test_verify_inclusion_proof_fails_on_tamper(self):
        root_hash, merkle_tree = compute_merkle_governance_hash(
            [
                ("policy", "policy.a", "A"),
                ("prompt", "prompt.b", "B"),
                ("tool", "tool.c", "C"),
            ],
            include_inclusion_proofs=True,
        )
        proof_entry = merkle_tree["inclusion_proofs"][0]
        tampered = [dict(step) for step in proof_entry["proof_path"]]
        if tampered:
            tampered[0]["sibling_hash"] = "0" * 64
        assert not verify_inclusion_proof(root_hash, proof_entry["leaf_hash"], tampered)

    def test_verify_inclusion_proof_rejects_invalid_position(self):
        with pytest.raises(ValueError, match="Invalid sibling_position"):
            verify_inclusion_proof(
                "a" * 64,
                "b" * 64,
                [{"sibling_hash": "c" * 64, "sibling_position": "middle"}],
            )
