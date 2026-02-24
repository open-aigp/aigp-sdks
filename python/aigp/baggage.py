"""
AIGP Baggage Propagation
========================

Manages OTel Baggage for propagating governance context across
agent-to-agent calls.

When Agent A calls Agent B, the governance context (active policy,
data classification, org) travels via OTel Baggage in HTTP headers.

Security: Sensitive data (governance_hash, denial_reason, raw content)
MUST NOT be placed in Baggage as it leaks in HTTP headers.
"""

from opentelemetry import baggage, context
from opentelemetry.context import Context
from typing import Optional

from aigp.attributes import AIGPAttributes


class AIGPBaggage:
    """
    Manages AIGP governance context in OTel Baggage.

    Baggage items are propagated automatically across service boundaries
    when OTel instrumentation is active (HTTP, gRPC, etc.).
    """

    # Keys that are safe to propagate in Baggage (non-sensitive)
    SAFE_KEYS = {
        AIGPAttributes.POLICY_NAME,
        AIGPAttributes.DATA_CLASSIFICATION,
        AIGPAttributes.ORG_ID,
    }

    # Keys that MUST NOT be propagated (sensitive)
    FORBIDDEN_KEYS = {
        AIGPAttributes.GOVERNANCE_HASH,
        AIGPAttributes.DENIAL_REASON,
        AIGPAttributes.VIOLATION_TYPE,
    }

    @staticmethod
    def inject(
        policy_name: str = "",
        data_classification: str = "",
        org_id: str = "",
        ctx: Optional[Context] = None,
    ) -> Context:
        """
        Inject AIGP governance context into OTel Baggage.

        Call this before making an agent-to-agent request so that the
        receiving agent inherits governance context.

        Args:
            policy_name: Active governed policy (AGRN format).
            data_classification: Data sensitivity level.
            org_id: Organization identifier (AGRN format).
            ctx: Optional OTel context. Defaults to current context.

        Returns:
            Updated OTel context with Baggage items.
        """
        current_ctx = ctx or context.get_current()

        if policy_name:
            current_ctx = baggage.set_baggage(
                AIGPAttributes.POLICY_NAME, policy_name, context=current_ctx
            )
        if data_classification:
            current_ctx = baggage.set_baggage(
                AIGPAttributes.DATA_CLASSIFICATION, data_classification, context=current_ctx
            )
        if org_id:
            current_ctx = baggage.set_baggage(
                AIGPAttributes.ORG_ID, org_id, context=current_ctx
            )

        return current_ctx

    @staticmethod
    def extract(ctx: Optional[Context] = None) -> dict[str, str]:
        """
        Extract AIGP governance context from OTel Baggage.

        Call this on the receiving side of an agent-to-agent call to
        recover governance context set by the calling agent.

        Args:
            ctx: Optional OTel context. Defaults to current context.

        Returns:
            Dict of AIGP Baggage items found.
        """
        current_ctx = ctx or context.get_current()
        result = {}

        for key in AIGPBaggage.SAFE_KEYS:
            value = baggage.get_baggage(key, context=current_ctx)
            if value:
                result[key] = value

        return result

    @staticmethod
    def clear(ctx: Optional[Context] = None) -> Context:
        """
        Remove all AIGP Baggage items from context.

        Useful when crossing trust boundaries where governance context
        should not leak further.

        Args:
            ctx: Optional OTel context. Defaults to current context.

        Returns:
            Updated context with AIGP Baggage items removed.
        """
        current_ctx = ctx or context.get_current()

        for key in AIGPBaggage.SAFE_KEYS:
            current_ctx = baggage.remove_baggage(key, context=current_ctx)

        return current_ctx
