"""
AIGP Semantic Attributes for OpenTelemetry
==========================================

Defines the `aigp.*` namespace attributes as constants, organized by
their OTel signal type (Resource vs Span).

These follow OTel naming conventions:
- Lowercase, dot-separated namespace hierarchy
- Domain-first approach: aigp.{component}.{property}

AIGP standard event types use UPPER_SNAKE_CASE (e.g., ``INJECT_SUCCESS``).
Custom event types
are also supported — the ``aigp.event.type`` attribute accepts any string.
"""


class AIGPAttributes:
    """Constants for AIGP semantic attributes in the aigp.* namespace."""

    # -------------------------------------------------------
    # Resource Attributes (constant per agent process)
    # -------------------------------------------------------
    AGENT_ID = "aigp.agent.id"
    AGENT_NAME = "aigp.agent.name"
    ORG_ID = "aigp.org.id"
    ORG_NAME = "aigp.org.name"

    # -------------------------------------------------------
    # Span Attributes: Core Governance
    # -------------------------------------------------------
    EVENT_ID = "aigp.event.id"
    EVENT_TYPE = "aigp.event.type"
    EVENT_CATEGORY = "aigp.event.category"
    GOVERNANCE_HASH = "aigp.governance.hash"
    GOVERNANCE_HASH_TYPE = "aigp.governance.hash_type"
    DATA_CLASSIFICATION = "aigp.data.classification"
    ENFORCEMENT_RESULT = "aigp.enforcement.result"
    EVENT_SIGNATURE = "aigp.event.signature"
    SIGNATURE_KEY_ID = "aigp.signature.key_id"
    SEQUENCE_NUMBER = "aigp.sequence.number"
    CAUSALITY_REF = "aigp.causality.ref"

    # -------------------------------------------------------
    # Span Attributes: Policy (singular — one policy per span)
    # -------------------------------------------------------
    POLICY_NAME = "aigp.policy.name"
    POLICY_VERSION = "aigp.policy.version"
    POLICY_ID = "aigp.policy.id"

    # -------------------------------------------------------
    # Span Attributes: Prompt (singular — one prompt per span)
    # -------------------------------------------------------
    PROMPT_NAME = "aigp.prompt.name"
    PROMPT_VERSION = "aigp.prompt.version"
    PROMPT_ID = "aigp.prompt.id"

    # -------------------------------------------------------
    # Span Attributes: Multi-Resource
    # Array-valued attributes for operations involving multiple
    # governed resources simultaneously.
    # -------------------------------------------------------
    POLICIES_NAMES = "aigp.policies.names"
    POLICIES_VERSIONS = "aigp.policies.versions"
    PROMPTS_NAMES = "aigp.prompts.names"
    PROMPTS_VERSIONS = "aigp.prompts.versions"
    TOOLS_NAMES = "aigp.tools.names"
    CONTEXTS_NAMES = "aigp.contexts.names"
    LINEAGES_NAMES = "aigp.lineages.names"
    MEMORIES_NAMES = "aigp.memories.names"
    MODELS_NAMES = "aigp.models.names"

    # -------------------------------------------------------
    # Span Attributes: Merkle Tree Governance
    # -------------------------------------------------------
    MERKLE_LEAF_COUNT = "aigp.governance.merkle.leaf_count"

    # -------------------------------------------------------
    # Span Attributes: Denial and Violation
    # -------------------------------------------------------
    SEVERITY = "aigp.severity"
    VIOLATION_TYPE = "aigp.violation.type"
    DENIAL_REASON = "aigp.denial.reason"

    # -------------------------------------------------------
    # Enforcement result values
    # -------------------------------------------------------
    ENFORCEMENT_ALLOWED = "allowed"
    ENFORCEMENT_DENIED = "denied"

    # -------------------------------------------------------
    # Data classification values
    # -------------------------------------------------------
    CLASSIFICATION_PUBLIC = "public"
    CLASSIFICATION_INTERNAL = "internal"
    CLASSIFICATION_CONFIDENTIAL = "confidential"
    CLASSIFICATION_RESTRICTED = "restricted"

    # -------------------------------------------------------
    # Classification abbreviations for tracestate
    # -------------------------------------------------------
    CLASSIFICATION_ABBREV = {
        "public": "pub",
        "internal": "int",
        "confidential": "con",
        "restricted": "res",
    }
