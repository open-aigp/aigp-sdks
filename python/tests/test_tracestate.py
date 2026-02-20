"""Tests for AIGP W3C tracestate vendor key encoding/decoding."""

from aigp.tracestate import AIGPTraceState


class TestTraceStateEncode:
    """Tests for encoding AIGP governance context into tracestate values."""

    def test_encode_full_context(self):
        result = AIGPTraceState.encode(
            data_classification="confidential",
            policy_name="policy.trading-limits",
            policy_version=4,
        )
        assert result == "cls:con;pol:policy.trading-limits;ver:4"

    def test_encode_classification_abbreviations(self):
        assert "cls:pub" in AIGPTraceState.encode(data_classification="public")
        assert "cls:int" in AIGPTraceState.encode(data_classification="internal")
        assert "cls:con" in AIGPTraceState.encode(data_classification="confidential")
        assert "cls:res" in AIGPTraceState.encode(data_classification="restricted")

    def test_encode_partial_context(self):
        result = AIGPTraceState.encode(policy_name="policy.test")
        assert result == "pol:policy.test"

    def test_encode_empty_returns_empty(self):
        result = AIGPTraceState.encode()
        assert result == ""


class TestTraceStateDecode:
    """Tests for decoding AIGP tracestate values."""

    def test_decode_full_context(self):
        result = AIGPTraceState.decode("cls:con;pol:policy.trading-limits;ver:4")
        assert result["data_classification"] == "confidential"
        assert result["policy_name"] == "policy.trading-limits"
        assert result["policy_version"] == "4"

    def test_decode_classification_abbreviations(self):
        assert AIGPTraceState.decode("cls:pub")["data_classification"] == "public"
        assert AIGPTraceState.decode("cls:int")["data_classification"] == "internal"
        assert AIGPTraceState.decode("cls:con")["data_classification"] == "confidential"
        assert AIGPTraceState.decode("cls:res")["data_classification"] == "restricted"

    def test_decode_partial(self):
        result = AIGPTraceState.decode("pol:policy.test")
        assert result["policy_name"] == "policy.test"
        assert "data_classification" not in result


class TestTraceStateInject:
    """Tests for injecting/extracting AIGP entries in tracestate headers."""

    def test_inject_into_empty_tracestate(self):
        result = AIGPTraceState.inject_into_tracestate(
            "",
            data_classification="confidential",
            policy_name="policy.trading-limits",
            policy_version=4,
        )
        assert result == "aigp=cls:con;pol:policy.trading-limits;ver:4"

    def test_inject_prepends_to_existing(self):
        result = AIGPTraceState.inject_into_tracestate(
            "dd=s:1,rojo=t61rcWkgMzE",
            data_classification="restricted",
            policy_name="policy.risk-controls",
            policy_version=2,
        )
        assert result.startswith("aigp=")
        assert "dd=s:1" in result
        assert "rojo=t61rcWkgMzE" in result

    def test_inject_replaces_existing_aigp_entry(self):
        result = AIGPTraceState.inject_into_tracestate(
            "aigp=cls:pub;pol:policy.old;ver:1,dd=s:1",
            data_classification="restricted",
            policy_name="policy.new",
            policy_version=5,
        )
        # Should have exactly one aigp entry, at the front
        aigp_count = result.count("aigp=")
        assert aigp_count == 1
        assert result.startswith("aigp=cls:res;pol:policy.new;ver:5")

    def test_extract_from_tracestate(self):
        result = AIGPTraceState.extract_from_tracestate(
            "aigp=cls:con;pol:policy.trading-limits;ver:4,dd=s:1"
        )
        assert result["data_classification"] == "confidential"
        assert result["policy_name"] == "policy.trading-limits"
        assert result["policy_version"] == "4"

    def test_extract_from_tracestate_no_aigp(self):
        result = AIGPTraceState.extract_from_tracestate("dd=s:1,rojo=t61rcWkgMzE")
        assert result == {}
