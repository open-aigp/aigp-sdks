"""
AIGP OpenLineage Facet Builder
==============================

Constructs OpenLineage-compatible facet dicts from AIGP governance events.
No OpenLineage library dependency -- produces plain dicts conforming to
the OpenLineage custom facet JSON Schema.

AIGP defines two custom facets for OpenLineage:

1. **AIGPGovernanceRunFacet** (run facet) -- aggregate governance proof
   attached to ``run.facets.aigp_governance``.
2. **AIGPResourceInputFacet** (input dataset facet) -- per-resource
   governance metadata attached to ``inputs[].inputFacets.aigp_resource``.

Usage::

    from aigp.openlineage import (
        build_governance_run_facet,
        build_resource_input_facets,
        build_openlineage_run_event,
    )

    # From an existing AIGP event dict:
    run_facet = build_governance_run_facet(aigp_event)
    input_facets = build_resource_input_facets(aigp_event)

    # Or build a complete OpenLineage RunEvent:
    ol_event = build_openlineage_run_event(
        aigp_event,
        job_namespace="finco.trading",
        job_name="trading-bot-v2.invoke",
    )

Architectural note -- Emission Granularity:
    Implementations SHOULD emit at most one OpenLineage RunEvent per
    governance session or task, using ``trace_id`` as the ``runId``.
    Individual agent steps within a session SHOULD be tracked as OTel
    spans, not as separate OpenLineage runs.  OpenLineage was designed
    for discrete Job Runs in a DAG; AI agents are conversational and
    iterative -- emitting per-step runs overwhelms lineage backends.

Architectural note -- Active vs. Passive Lineage:
    OpenLineage integration is PASSIVE (eventually consistent).  It MUST
    NOT be used for real-time enforcement decisions.  Enforcement MUST use
    the AIGP + OTel path.  When pre-execution lineage context is needed
    for governance, snapshot it, hash it as a ``"context"`` resource in
    the Merkle tree -- making it an active governed artifact.
"""

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PRODUCER = "https://github.com/open-aigp/aigp"

RUN_FACET_SCHEMA_URL = (
    "https://github.com/open-aigp/aigp/blob/v0.10.0/"
    "integrations/openlineage/facets/AIGPGovernanceRunFacet.json"
)

RESOURCE_FACET_SCHEMA_URL = (
    "https://github.com/open-aigp/aigp/blob/v0.10.0/"
    "integrations/openlineage/facets/AIGPResourceInputFacet.json"
)

OPENLINEAGE_SCHEMA_URL = (
    "https://openlineage.io/spec/2-0-2/OpenLineage.json#/$defs/RunEvent"
)


# ---------------------------------------------------------------------------
# Facet Builders
# ---------------------------------------------------------------------------

def build_governance_run_facet(aigp_event: dict[str, Any]) -> dict[str, Any]:
    """
    Build an AIGPGovernanceRunFacet from an AIGP event dict.

    The returned dict conforms to the ``AIGPGovernanceRunFacet`` JSON Schema
    and is ready to be placed in ``run.facets.aigp_governance`` of an
    OpenLineage RunEvent.

    Args:
        aigp_event: AIGP event dict (from ``create_aigp_event`` or any
            ``AIGPInstrumentor`` method).

    Returns:
        Dict conforming to AIGPGovernanceRunFacet schema.
    """
    merkle_tree = aigp_event.get("governance_merkle_tree")
    leaf_count = merkle_tree["leaf_count"] if merkle_tree else 1

    facet: dict[str, Any] = {
        "_producer": PRODUCER,
        "_schemaURL": RUN_FACET_SCHEMA_URL,
        "governanceHash": aigp_event.get("governance_hash", ""),
        "hashType": aigp_event.get("hash_type", "sha256"),
        "leafCount": leaf_count,
        "agentId": aigp_event.get("agent_id", ""),
        "traceId": aigp_event.get("trace_id", ""),
        "specVersion": aigp_event.get("spec_version", "0.10.0"),
    }

    # Infer enforcement result from event type (case-insensitive)
    event_type = aigp_event.get("event_type", "").upper()
    if "DENIED" in event_type or "VIOLATION" in event_type or "BLOCKED" in event_type:
        facet["enforcementResult"] = "denied"
    elif event_type:
        facet["enforcementResult"] = "allowed"

    # Optional: data classification
    classification = aigp_event.get("data_classification", "")
    if classification:
        facet["dataClassification"] = classification

    return facet


def build_resource_input_facets(
    aigp_event: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    Build AIGPResourceInputFacet dicts from an AIGP event's governed resources.

    If the event has a ``governance_merkle_tree``, produces one facet per leaf.
    Otherwise, produces a single facet from the event's primary resource
    (``policy_name`` or ``prompt_name``).

    Args:
        aigp_event: AIGP event dict.

    Returns:
        List of dicts, each conforming to AIGPResourceInputFacet schema.
        Each dict is meant for ``inputs[].inputFacets.aigp_resource``.
    """
    merkle_tree = aigp_event.get("governance_merkle_tree")

    if merkle_tree:
        facets: list[dict[str, Any]] = []
        for leaf in merkle_tree.get("leaves", []):
            facets.append({
                "_producer": PRODUCER,
                "_schemaURL": RESOURCE_FACET_SCHEMA_URL,
                "resourceType": leaf["resource_type"],
                "resourceName": leaf["resource_name"],
                "leafHash": leaf["hash"],
            })
        return facets

    # Single resource: infer from event fields
    facet: dict[str, Any] = {
        "_producer": PRODUCER,
        "_schemaURL": RESOURCE_FACET_SCHEMA_URL,
    }
    annotations = aigp_event.get("annotations", {}) or {}
    event_type = (aigp_event.get("event_type", "") or "").upper()

    if aigp_event.get("policy_name"):
        facet["resourceType"] = "policy"
        facet["resourceName"] = aigp_event["policy_name"]
        if aigp_event.get("policy_version"):
            facet["resourceVersion"] = aigp_event["policy_version"]
    elif aigp_event.get("prompt_name"):
        facet["resourceType"] = "prompt"
        facet["resourceName"] = aigp_event["prompt_name"]
        if aigp_event.get("prompt_version"):
            facet["resourceVersion"] = aigp_event["prompt_version"]
    elif event_type in ("TOOL_INVOKED", "TOOL_DENIED"):
        tool_name = annotations.get("tool_name", "")
        if not tool_name:
            return []
        facet["resourceType"] = "tool"
        facet["resourceName"] = tool_name
    elif event_type in ("MEMORY_READ", "MEMORY_WRITTEN"):
        memory_name = annotations.get("memory_name", "")
        if not memory_name:
            return []
        facet["resourceType"] = "memory"
        facet["resourceName"] = memory_name
    elif event_type in ("MODEL_LOADED", "MODEL_SWITCHED"):
        model_name = annotations.get("model_name", "")
        if not model_name:
            return []
        facet["resourceType"] = "model"
        facet["resourceName"] = model_name
    else:
        return []  # No identifiable resource

    if aigp_event.get("governance_hash"):
        facet["leafHash"] = aigp_event["governance_hash"]

    return [facet]


def build_openlineage_run_event(
    aigp_event: dict[str, Any],
    job_namespace: str,
    job_name: str,
    run_id: str = "",
    event_type: str = "COMPLETE",
) -> dict[str, Any]:
    """
    Build a complete OpenLineage RunEvent with AIGP governance facets.

    This convenience function creates a full RunEvent dict that can be
    sent to any OpenLineage-compatible lineage backend.

    Governed resources become OpenLineage InputDatasets with the
    ``aigp_resource`` input facet.

    **Emission granularity:** Use ``trace_id`` as ``run_id`` to ensure
    one RunEvent per governance session (not per agent step).

    Args:
        aigp_event: AIGP event dict.
        job_namespace: OpenLineage job namespace (e.g., ``"finco.trading"``).
        job_name: OpenLineage job name (e.g., ``"trading-bot-v2.invoke"``).
        run_id: Optional run ID (UUID string).  If not provided, uses the
            AIGP event's ``trace_id``; falls back to a generated UUID.
        event_type: OpenLineage event type.  One of ``"START"``,
            ``"RUNNING"``, ``"COMPLETE"``, ``"FAIL"``, ``"ABORT"``.

    Returns:
        Dict conforming to OpenLineage RunEvent schema with AIGP facets.
    """
    if not run_id:
        # Prefer trace_id as run_id (one RunEvent per session).
        run_id = aigp_event.get("trace_id") or str(_uuid.uuid4())

    run_facet = build_governance_run_facet(aigp_event)
    resource_facets = build_resource_input_facets(aigp_event)

    # Each governed resource becomes an OpenLineage InputDataset.
    inputs: list[dict[str, Any]] = []
    for rf in resource_facets:
        inputs.append({
            "namespace": job_namespace,
            "name": rf.get("resourceName", "unknown"),
            "inputFacets": {
                "aigp_resource": rf,
            },
        })

    now = datetime.now(timezone.utc)

    return {
        "eventType": event_type,
        "eventTime": now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z",
        "run": {
            "runId": run_id,
            "facets": {
                "aigp_governance": run_facet,
            },
        },
        "job": {
            "namespace": job_namespace,
            "name": job_name,
        },
        "inputs": inputs,
        "outputs": [],
        "producer": PRODUCER,
        "schemaURL": OPENLINEAGE_SCHEMA_URL,
    }
