import pathlib
import re

from aigp.events import create_aigp_event


TRACE_ID_OTEL_RE = re.compile(r"^[a-f0-9]{32}$")
TRACE_ID_UUID_V4_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")
TRACE_ID_PREFIXED_UUID_V4_RE = re.compile(
    r"^(trace|req)-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)


def _is_valid_trace_id(trace_id: str, span_id: str) -> bool:
    if span_id:
        return bool(TRACE_ID_OTEL_RE.fullmatch(trace_id))
    return bool(
        TRACE_ID_OTEL_RE.fullmatch(trace_id)
        or TRACE_ID_UUID_V4_RE.fullmatch(trace_id)
        or TRACE_ID_PREFIXED_UUID_V4_RE.fullmatch(trace_id)
    )


def _validate_event(event: dict) -> list[str]:
    errors = []
    for field in ("event_id", "event_type", "event_category", "event_time", "agent_id", "trace_id"):
        if not event.get(field):
            errors.append(f"Missing required field: {field}")

    governance_hash = (event.get("governance_hash", "") or "").strip()
    if "governance_hash" not in event:
        errors.append("Missing required field: governance_hash")
    elif not governance_hash:
        errors.append("governance_hash must be a non-empty string")

    if event.get("trace_id") and not _is_valid_trace_id(event["trace_id"], event.get("span_id", "")):
        if event.get("span_id"):
            errors.append("trace_id must be 32-char lowercase hex when span_id is present")
        else:
            errors.append("trace_id must be 32-char lowercase hex, UUID v4, or trace-/req- prefixed UUID v4")

    sequence_number = int(event.get("sequence_number", 0) or 0)
    if sequence_number < 1:
        errors.append("sequence_number must be an integer >= 1")

    return errors


def test_conformance_fixtures():
    fixture_path = pathlib.Path(__file__).resolve().parents[2] / "conformance" / "validation-fixtures.tsv"
    lines = fixture_path.read_text(encoding="utf-8").splitlines()

    header = lines[0].split("\t")
    for line in lines[1:]:
        if not line.strip():
            continue
        values = line.split("\t")
        row = {header[i]: (values[i] if i < len(values) else "") for i in range(len(header))}
        sequence_number = int(row.get("sequence_number", "0") or 0)
        expected_valid = row["expect_valid"] == "true"
        try:
            event = create_aigp_event(
                event_type=row["event_type"],
                event_category=row["event_category"],
                agent_id="agent.test",
                trace_id=row["trace_id"],
                span_id=row["span_id"],
                governance_hash=row["governance_hash"],
                sequence_number=sequence_number,
                causality_ref=row.get("causality_ref", ""),
            )
            event["sequence_number"] = sequence_number
            event["causality_ref"] = row.get("causality_ref", "")
            is_valid = len(_validate_event(event)) == 0
        except ValueError:
            is_valid = False
        assert is_valid == expected_valid, f"fixture failed: {row['case_id']}"
