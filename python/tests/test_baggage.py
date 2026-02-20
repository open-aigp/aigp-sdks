"""
Tests for aigp.baggage — AIGP Baggage propagation via OTel.
"""

from opentelemetry import baggage, context

from aigp.attributes import AIGPAttributes
from aigp.baggage import AIGPBaggage


class TestSafeKeys:
    """SAFE_KEYS defines which attributes are allowed in Baggage."""

    def test_safe_keys_contains_policy_name(self):
        assert AIGPAttributes.POLICY_NAME in AIGPBaggage.SAFE_KEYS

    def test_safe_keys_contains_data_classification(self):
        assert AIGPAttributes.DATA_CLASSIFICATION in AIGPBaggage.SAFE_KEYS

    def test_safe_keys_contains_org_id(self):
        assert AIGPAttributes.ORG_ID in AIGPBaggage.SAFE_KEYS

    def test_safe_keys_count(self):
        """Exactly 3 safe keys — policy, classification, org."""
        assert len(AIGPBaggage.SAFE_KEYS) == 3


class TestForbiddenKeys:
    """FORBIDDEN_KEYS must never be placed in Baggage (security)."""

    def test_governance_hash_forbidden(self):
        assert AIGPAttributes.GOVERNANCE_HASH in AIGPBaggage.FORBIDDEN_KEYS

    def test_denial_reason_forbidden(self):
        assert AIGPAttributes.DENIAL_REASON in AIGPBaggage.FORBIDDEN_KEYS

    def test_violation_type_forbidden(self):
        assert AIGPAttributes.VIOLATION_TYPE in AIGPBaggage.FORBIDDEN_KEYS

    def test_no_overlap_between_safe_and_forbidden(self):
        """Safe and forbidden sets must never overlap."""
        overlap = AIGPBaggage.SAFE_KEYS & AIGPBaggage.FORBIDDEN_KEYS
        assert len(overlap) == 0, f"Keys in both SAFE and FORBIDDEN: {overlap}"


class TestInject:
    """AIGPBaggage.inject() places governance context into OTel Baggage."""

    def test_inject_policy_name(self):
        ctx = AIGPBaggage.inject(policy_name="policy.trading-limits")
        value = baggage.get_baggage(AIGPAttributes.POLICY_NAME, context=ctx)
        assert value == "policy.trading-limits"

    def test_inject_data_classification(self):
        ctx = AIGPBaggage.inject(data_classification="confidential")
        value = baggage.get_baggage(AIGPAttributes.DATA_CLASSIFICATION, context=ctx)
        assert value == "confidential"

    def test_inject_org_id(self):
        ctx = AIGPBaggage.inject(org_id="org.acme-trading")
        value = baggage.get_baggage(AIGPAttributes.ORG_ID, context=ctx)
        assert value == "org.acme-trading"

    def test_inject_all_three(self):
        ctx = AIGPBaggage.inject(
            policy_name="policy.limits",
            data_classification="restricted",
            org_id="org.bank",
        )
        assert baggage.get_baggage(AIGPAttributes.POLICY_NAME, context=ctx) == "policy.limits"
        assert baggage.get_baggage(AIGPAttributes.DATA_CLASSIFICATION, context=ctx) == "restricted"
        assert baggage.get_baggage(AIGPAttributes.ORG_ID, context=ctx) == "org.bank"

    def test_inject_empty_values_skipped(self):
        """Empty strings should not be injected."""
        ctx = AIGPBaggage.inject(policy_name="", data_classification="", org_id="")
        assert baggage.get_baggage(AIGPAttributes.POLICY_NAME, context=ctx) is None
        assert baggage.get_baggage(AIGPAttributes.DATA_CLASSIFICATION, context=ctx) is None
        assert baggage.get_baggage(AIGPAttributes.ORG_ID, context=ctx) is None

    def test_inject_returns_context(self):
        """inject() returns an OTel Context object."""
        ctx = AIGPBaggage.inject(policy_name="policy.x")
        assert ctx is not None

    def test_inject_with_explicit_context(self):
        """Can inject into a specific context (not just current)."""
        base_ctx = context.get_current()
        ctx = AIGPBaggage.inject(policy_name="policy.test", ctx=base_ctx)
        value = baggage.get_baggage(AIGPAttributes.POLICY_NAME, context=ctx)
        assert value == "policy.test"


class TestExtract:
    """AIGPBaggage.extract() reads governance context from OTel Baggage."""

    def test_extract_finds_injected_values(self):
        ctx = AIGPBaggage.inject(
            policy_name="policy.limits",
            data_classification="internal",
        )
        result = AIGPBaggage.extract(ctx=ctx)
        assert result[AIGPAttributes.POLICY_NAME] == "policy.limits"
        assert result[AIGPAttributes.DATA_CLASSIFICATION] == "internal"

    def test_extract_empty_when_nothing_injected(self):
        ctx = context.get_current()
        result = AIGPBaggage.extract(ctx=ctx)
        # May or may not be empty depending on global state, but should not error
        assert isinstance(result, dict)

    def test_extract_only_returns_safe_keys(self):
        """extract() only looks for SAFE_KEYS — never forbidden ones."""
        ctx = AIGPBaggage.inject(policy_name="policy.x")
        result = AIGPBaggage.extract(ctx=ctx)
        for key in result:
            assert key in AIGPBaggage.SAFE_KEYS, (
                f"extract() returned forbidden key: {key}"
            )


class TestClear:
    """AIGPBaggage.clear() removes all AIGP items from Baggage."""

    def test_clear_removes_all_aigp_baggage(self):
        ctx = AIGPBaggage.inject(
            policy_name="policy.limits",
            data_classification="restricted",
            org_id="org.bank",
        )
        # Verify they're there
        assert baggage.get_baggage(AIGPAttributes.POLICY_NAME, context=ctx) is not None

        # Clear
        cleared_ctx = AIGPBaggage.clear(ctx=ctx)

        # Verify they're gone
        assert baggage.get_baggage(AIGPAttributes.POLICY_NAME, context=cleared_ctx) is None
        assert baggage.get_baggage(AIGPAttributes.DATA_CLASSIFICATION, context=cleared_ctx) is None
        assert baggage.get_baggage(AIGPAttributes.ORG_ID, context=cleared_ctx) is None

    def test_clear_returns_context(self):
        ctx = AIGPBaggage.clear()
        assert ctx is not None
