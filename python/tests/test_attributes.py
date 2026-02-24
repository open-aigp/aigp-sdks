"""
Tests for aigp.attributes — AIGP semantic attribute constants.
"""

from aigp.attributes import AIGPAttributes


class TestNamespaceConvention:
    """All AIGP attribute names must follow OTel naming conventions."""

    def test_all_attributes_start_with_aigp(self):
        """Every attribute constant must be in the aigp.* namespace."""
        for name in dir(AIGPAttributes):
            if name.startswith("_"):
                continue
            value = getattr(AIGPAttributes, name)
            if isinstance(value, str) and "." in value:
                assert value.startswith("aigp."), (
                    f"AIGPAttributes.{name} = {value!r} is not in the aigp.* namespace"
                )

    def test_all_attributes_are_lowercase(self):
        """OTel convention: attribute names are lowercase, dot-separated."""
        for name in dir(AIGPAttributes):
            if name.startswith("_"):
                continue
            value = getattr(AIGPAttributes, name)
            if isinstance(value, str) and value.startswith("aigp."):
                assert value == value.lower(), (
                    f"AIGPAttributes.{name} = {value!r} is not lowercase"
                )

    def test_no_spaces_or_dashes(self):
        """Attribute names use dots and underscores only — no spaces or dashes."""
        for name in dir(AIGPAttributes):
            if name.startswith("_"):
                continue
            value = getattr(AIGPAttributes, name)
            if isinstance(value, str) and value.startswith("aigp."):
                assert " " not in value, f"AIGPAttributes.{name} contains a space"
                assert "-" not in value, f"AIGPAttributes.{name} contains a dash"


class TestResourceAttributes:
    """Resource attributes — constant per agent process."""

    def test_agent_id(self):
        assert AIGPAttributes.AGENT_ID == "aigp.agent.id"

    def test_agent_name(self):
        assert AIGPAttributes.AGENT_NAME == "aigp.agent.name"

    def test_org_id(self):
        assert AIGPAttributes.ORG_ID == "aigp.org.id"

    def test_org_name(self):
        assert AIGPAttributes.ORG_NAME == "aigp.org.name"


class TestCoreGovernanceAttributes:
    """Span attributes for core governance fields."""

    def test_event_id(self):
        assert AIGPAttributes.EVENT_ID == "aigp.event.id"

    def test_event_type(self):
        assert AIGPAttributes.EVENT_TYPE == "aigp.event.type"

    def test_event_category(self):
        assert AIGPAttributes.EVENT_CATEGORY == "aigp.event.category"

    def test_governance_hash(self):
        assert AIGPAttributes.GOVERNANCE_HASH == "aigp.governance.hash"

    def test_governance_hash_type(self):
        assert AIGPAttributes.GOVERNANCE_HASH_TYPE == "aigp.governance.hash_type"

    def test_data_classification(self):
        assert AIGPAttributes.DATA_CLASSIFICATION == "aigp.data.classification"

    def test_enforcement_result(self):
        assert AIGPAttributes.ENFORCEMENT_RESULT == "aigp.enforcement.result"

    def test_event_signature(self):
        assert AIGPAttributes.EVENT_SIGNATURE == "aigp.event.signature"

    def test_signature_key_id(self):
        assert AIGPAttributes.SIGNATURE_KEY_ID == "aigp.signature.key_id"

    def test_sequence_number(self):
        assert AIGPAttributes.SEQUENCE_NUMBER == "aigp.sequence.number"

    def test_causality_ref(self):
        assert AIGPAttributes.CAUSALITY_REF == "aigp.causality.ref"


class TestPolicyAndPromptAttributes:
    """Singular policy/prompt attributes."""

    def test_policy_name(self):
        assert AIGPAttributes.POLICY_NAME == "aigp.policy.name"

    def test_policy_version(self):
        assert AIGPAttributes.POLICY_VERSION == "aigp.policy.version"

    def test_policy_id(self):
        assert AIGPAttributes.POLICY_ID == "aigp.policy.id"

    def test_prompt_name(self):
        assert AIGPAttributes.PROMPT_NAME == "aigp.prompt.name"

    def test_prompt_version(self):
        assert AIGPAttributes.PROMPT_VERSION == "aigp.prompt.version"

    def test_prompt_id(self):
        assert AIGPAttributes.PROMPT_ID == "aigp.prompt.id"


class TestMultiResourceAttributes:
    """Array-valued attributes for multi-resource operations."""

    def test_policies_names(self):
        assert AIGPAttributes.POLICIES_NAMES == "aigp.policies.names"

    def test_prompts_names(self):
        assert AIGPAttributes.PROMPTS_NAMES == "aigp.prompts.names"

    def test_tools_names(self):
        assert AIGPAttributes.TOOLS_NAMES == "aigp.tools.names"

    def test_contexts_names(self):
        assert AIGPAttributes.CONTEXTS_NAMES == "aigp.contexts.names"

    def test_lineages_names(self):
        assert AIGPAttributes.LINEAGES_NAMES == "aigp.lineages.names"

    def test_memories_names(self):
        assert AIGPAttributes.MEMORIES_NAMES == "aigp.memories.names"

    def test_models_names(self):
        assert AIGPAttributes.MODELS_NAMES == "aigp.models.names"


class TestDenialAttributes:
    """Denial and violation attributes."""

    def test_severity(self):
        assert AIGPAttributes.SEVERITY == "aigp.severity"

    def test_violation_type(self):
        assert AIGPAttributes.VIOLATION_TYPE == "aigp.violation.type"

    def test_denial_reason(self):
        assert AIGPAttributes.DENIAL_REASON == "aigp.denial.reason"


class TestMerkleAttributes:
    """Merkle tree governance attributes."""

    def test_merkle_leaf_count(self):
        assert AIGPAttributes.MERKLE_LEAF_COUNT == "aigp.governance.merkle.leaf_count"


class TestEnforcementValues:
    """Enforcement result string constants."""

    def test_allowed(self):
        assert AIGPAttributes.ENFORCEMENT_ALLOWED == "allowed"

    def test_denied(self):
        assert AIGPAttributes.ENFORCEMENT_DENIED == "denied"


class TestClassificationValues:
    """Data classification constants and abbreviations."""

    def test_classification_levels(self):
        assert AIGPAttributes.CLASSIFICATION_PUBLIC == "public"
        assert AIGPAttributes.CLASSIFICATION_INTERNAL == "internal"
        assert AIGPAttributes.CLASSIFICATION_CONFIDENTIAL == "confidential"
        assert AIGPAttributes.CLASSIFICATION_RESTRICTED == "restricted"

    def test_abbreviations_map_all_levels(self):
        """Every classification level must have an abbreviation."""
        levels = [
            AIGPAttributes.CLASSIFICATION_PUBLIC,
            AIGPAttributes.CLASSIFICATION_INTERNAL,
            AIGPAttributes.CLASSIFICATION_CONFIDENTIAL,
            AIGPAttributes.CLASSIFICATION_RESTRICTED,
        ]
        for level in levels:
            assert level in AIGPAttributes.CLASSIFICATION_ABBREV, (
                f"Missing abbreviation for {level}"
            )

    def test_abbreviations_are_3_chars(self):
        """All abbreviations should be exactly 3 characters (compact for tracestate)."""
        for level, abbrev in AIGPAttributes.CLASSIFICATION_ABBREV.items():
            assert len(abbrev) == 3, (
                f"Abbreviation for {level} is {abbrev!r} (expected 3 chars)"
            )


class TestNoHardcodedEventTypes:
    """AIGP does not prescribe event types — attributes.py should NOT
    contain EVENT_* constants."""

    def test_no_event_name_constants(self):
        """AIGPAttributes should not have any EVENT_* constants
        (except EVENT_ID, EVENT_TYPE, EVENT_CATEGORY, EVENT_SIGNATURE)."""
        allowed_event_attrs = {
            "EVENT_ID", "EVENT_TYPE", "EVENT_CATEGORY", "EVENT_SIGNATURE",
        }
        event_attrs = [
            name for name in dir(AIGPAttributes)
            if name.startswith("EVENT_") and name not in allowed_event_attrs
        ]
        assert len(event_attrs) == 0, (
            f"Found hardcoded event type constants (should not exist): {event_attrs}"
        )
