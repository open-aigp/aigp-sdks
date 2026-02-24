"""
AIGP CloudEvents Binding
========================

Wraps AIGP events in CloudEvents envelopes (structured mode) and
unwraps CloudEvents back to raw AIGP events. Implements the binding
defined in AIGP Specification Section 13.

CloudEvents spec: https://cloudevents.io/
AIGP binding:     Section 13 — Transport Bindings via CloudEvents

Usage:
    from aigp.cloudevents import wrap_as_cloudevent, unwrap_from_cloudevent

    ce = wrap_as_cloudevent(aigp_event)
    # -> {"specversion": "1.0", "type": "org.aigp.v1.inject_success", ...}

    aigp_event = unwrap_from_cloudevent(ce)
    # -> {"event_id": "...", "event_type": "INJECT_SUCCESS", ...}
"""

from __future__ import annotations

from typing import Any

# CloudEvents spec version
CE_SPECVERSION = "1.0"

# AIGP type prefix (reverse-DNS, versioned)
AIGP_TYPE_PREFIX = "org.aigp.v1."

# AIGP source scheme
AIGP_SOURCE_SCHEME = "aigp://"

# AIGP JSON Schema URI
AIGP_DATA_SCHEMA = "https://open-aigp.org/schema/aigp-event.schema.json"


def wrap_as_cloudevent(
    aigp_event: dict[str, Any],
    *,
    include_dataschema: bool = True,
) -> dict[str, Any]:
    """
    Wrap an AIGP event in a CloudEvents structured-mode envelope.

    Maps AIGP fields to CloudEvents context attributes and AIGP extension
    attributes per Spec Section 13.

    Args:
        aigp_event: An AIGP event dict (from ``create_aigp_event`` or any
            ``AIGPInstrumentor`` method).
        include_dataschema: Whether to include the ``dataschema`` attribute
            pointing to the AIGP JSON Schema. Default True.

    Returns:
        Dict conforming to CloudEvents JSON Format (structured mode).
        The AIGP event is in the ``data`` field.

    Raises:
        ValueError: If required AIGP fields are missing.
    """
    event_id = aigp_event.get("event_id", "")
    event_type = aigp_event.get("event_type", "")
    agent_id = aigp_event.get("agent_id", "")

    if not event_id or not event_type or not agent_id:
        raise ValueError(
            "AIGP event must have event_id, event_type, and agent_id "
            "to wrap as CloudEvent"
        )

    # Build source URI: aigp://<org_id>/<agent_id>
    org_id = aigp_event.get("org_id", "") or "default"
    source = f"{AIGP_SOURCE_SCHEME}{org_id}/{agent_id}"

    # Build type: org.aigp.v1.<lowercase_event_type>
    ce_type = f"{AIGP_TYPE_PREFIX}{event_type.lower()}"

    # Core context attributes
    ce: dict[str, Any] = {
        "specversion": CE_SPECVERSION,
        "id": event_id,
        "type": ce_type,
        "source": source,
    }

    # Optional context attributes
    event_time = aigp_event.get("event_time", "")
    if event_time:
        ce["time"] = event_time

    ce["datacontenttype"] = "application/json"

    if include_dataschema:
        ce["dataschema"] = AIGP_DATA_SCHEMA

    # Subject: primary governed resource (policy or prompt name)
    policy_name = aigp_event.get("policy_name", "")
    prompt_name = aigp_event.get("prompt_name", "")
    subject = policy_name or prompt_name
    if subject:
        ce["subject"] = subject

    # AIGP extension attributes (lowercase a-z0-9 only per CE spec)
    ce["aigpagentid"] = agent_id

    if org_id != "default":
        ce["aigporgid"] = org_id

    event_category = aigp_event.get("event_category", "")
    if event_category:
        ce["aigpcategory"] = event_category

    data_classification = aigp_event.get("data_classification", "")
    if data_classification:
        ce["aigpclassification"] = data_classification

    severity = aigp_event.get("severity", "")
    if severity:
        ce["aigpseverity"] = severity

    hash_type = aigp_event.get("hash_type", "")
    if hash_type:
        ce["aigphashtype"] = hash_type

    # Data payload: the full AIGP event
    ce["data"] = aigp_event

    return ce


def unwrap_from_cloudevent(ce: dict[str, Any]) -> dict[str, Any]:
    """
    Extract the AIGP event from a CloudEvents structured-mode envelope.

    Validates that the CloudEvents envelope has the expected structure
    and returns the ``data`` payload.

    Args:
        ce: A CloudEvents dict in structured JSON format.

    Returns:
        The AIGP event dict from the ``data`` field.

    Raises:
        ValueError: If the envelope is not a valid AIGP CloudEvent.
    """
    specversion = ce.get("specversion", "")
    if specversion != CE_SPECVERSION:
        raise ValueError(
            f"Unsupported CloudEvents specversion: {specversion!r} "
            f"(expected {CE_SPECVERSION!r})"
        )

    ce_type = ce.get("type", "")
    if not ce_type.startswith(AIGP_TYPE_PREFIX):
        raise ValueError(
            f"CloudEvents type {ce_type!r} does not start with "
            f"{AIGP_TYPE_PREFIX!r} — not an AIGP event"
        )

    data = ce.get("data")
    if data is None:
        raise ValueError("CloudEvents envelope has no 'data' field")

    if not isinstance(data, dict):
        raise ValueError(
            f"CloudEvents 'data' must be a dict, got {type(data).__name__}"
        )

    return data


def ce_type_from_event_type(event_type: str) -> str:
    """
    Convert an AIGP event_type to a CloudEvents type string.

    Args:
        event_type: AIGP event type (e.g., "INJECT_SUCCESS").

    Returns:
        CloudEvents type (e.g., "org.aigp.v1.inject_success").
    """
    return f"{AIGP_TYPE_PREFIX}{event_type.lower()}"


def event_type_from_ce_type(ce_type: str) -> str:
    """
    Convert a CloudEvents type string back to an AIGP event_type.

    CloudEvents type values are lowercase per AIGP transport convention.
    This function returns the suffix exactly as present in the CE type.

    Args:
        ce_type: CloudEvents type (e.g., "org.aigp.v1.inject_success").

    Returns:
        AIGP event type suffix (e.g., "inject_success").

    Raises:
        ValueError: If the type does not have the AIGP prefix.
    """
    if not ce_type.startswith(AIGP_TYPE_PREFIX):
        raise ValueError(
            f"CloudEvents type {ce_type!r} does not start with "
            f"{AIGP_TYPE_PREFIX!r}"
        )
    return ce_type[len(AIGP_TYPE_PREFIX):]


def build_ce_headers(
    aigp_event: dict[str, Any],
    *,
    prefix: str = "ce-",
) -> dict[str, str]:
    """
    Build CloudEvents binary-mode headers from an AIGP event.

    For HTTP, use prefix="ce-" (default). For Kafka, use prefix="ce_".

    Args:
        aigp_event: An AIGP event dict.
        prefix: Header prefix. "ce-" for HTTP, "ce_" for Kafka.

    Returns:
        Dict of header name -> header value strings.
    """
    event_id = aigp_event.get("event_id", "")
    event_type = aigp_event.get("event_type", "")
    agent_id = aigp_event.get("agent_id", "")
    org_id = aigp_event.get("org_id", "") or "default"

    headers: dict[str, str] = {
        f"{prefix}specversion": CE_SPECVERSION,
        f"{prefix}id": event_id,
        f"{prefix}type": f"{AIGP_TYPE_PREFIX}{event_type.lower()}",
        f"{prefix}source": f"{AIGP_SOURCE_SCHEME}{org_id}/{agent_id}",
    }

    event_time = aigp_event.get("event_time", "")
    if event_time:
        headers[f"{prefix}time"] = event_time

    # AIGP extension attributes
    headers[f"{prefix}aigpagentid"] = agent_id

    if org_id != "default":
        headers[f"{prefix}aigporgid"] = org_id

    event_category = aigp_event.get("event_category", "")
    if event_category:
        headers[f"{prefix}aigpcategory"] = event_category

    data_classification = aigp_event.get("data_classification", "")
    if data_classification:
        headers[f"{prefix}aigpclassification"] = data_classification

    severity = aigp_event.get("severity", "")
    if severity:
        headers[f"{prefix}aigpseverity"] = severity

    hash_type = aigp_event.get("hash_type", "")
    if hash_type:
        headers[f"{prefix}aigphashtype"] = hash_type

    return headers
