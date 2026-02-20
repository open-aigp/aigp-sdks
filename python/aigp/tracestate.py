"""
AIGP W3C tracestate Vendor Key
===============================

Manages the `aigp` vendor key in the W3C tracestate header for
lightweight governance signaling that survives through proxies
and load balancers.

Format:
    tracestate: aigp=cls:{classification};pol:{policy_name};ver:{policy_version}

Unlike Baggage, tracestate is part of the W3C Trace Context standard
and is preserved by all compliant tracing infrastructure.
"""

from aigp.attributes import AIGPAttributes


class AIGPTraceState:
    """
    Encodes and decodes AIGP governance context for the W3C tracestate header.
    """

    VENDOR_KEY = "aigp"

    @staticmethod
    def encode(
        data_classification: str = "",
        policy_name: str = "",
        policy_version: int = 0,
    ) -> str:
        """
        Encode AIGP governance context as a tracestate vendor value.

        Args:
            data_classification: AIGP classification level.
            policy_name: AGRN policy name.
            policy_version: Policy version number.

        Returns:
            Encoded vendor value string (e.g., "cls:con;pol:policy.trading-limits;ver:4").
        """
        parts = []

        if data_classification:
            abbrev = AIGPAttributes.CLASSIFICATION_ABBREV.get(
                data_classification, data_classification[:3]
            )
            parts.append(f"cls:{abbrev}")

        if policy_name:
            parts.append(f"pol:{policy_name}")

        if policy_version > 0:
            parts.append(f"ver:{policy_version}")

        return ";".join(parts)

    @staticmethod
    def decode(vendor_value: str) -> dict[str, str]:
        """
        Decode AIGP governance context from a tracestate vendor value.

        Args:
            vendor_value: The value portion of the aigp tracestate entry
                          (e.g., "cls:con;pol:policy.trading-limits;ver:4").

        Returns:
            Dict with decoded governance context.
        """
        result = {}
        abbrev_reverse = {v: k for k, v in AIGPAttributes.CLASSIFICATION_ABBREV.items()}

        for part in vendor_value.split(";"):
            if ":" not in part:
                continue
            key, value = part.split(":", 1)

            if key == "cls":
                result["data_classification"] = abbrev_reverse.get(value, value)
            elif key == "pol":
                result["policy_name"] = value
            elif key == "ver":
                result["policy_version"] = value

        return result

    @staticmethod
    def inject_into_tracestate(
        existing_tracestate: str,
        data_classification: str = "",
        policy_name: str = "",
        policy_version: int = 0,
    ) -> str:
        """
        Inject AIGP vendor entry into an existing tracestate header value.

        Per W3C spec, the most recently updated vendor entry moves to the front.

        Args:
            existing_tracestate: Current tracestate header value.
            data_classification: AIGP classification level.
            policy_name: AGRN policy name.
            policy_version: Policy version number.

        Returns:
            Updated tracestate header value with aigp entry prepended.
        """
        aigp_value = AIGPTraceState.encode(
            data_classification=data_classification,
            policy_name=policy_name,
            policy_version=policy_version,
        )

        if not aigp_value:
            return existing_tracestate

        aigp_entry = f"{AIGPTraceState.VENDOR_KEY}={aigp_value}"

        # Remove existing aigp entry if present
        if existing_tracestate:
            entries = [
                e.strip()
                for e in existing_tracestate.split(",")
                if not e.strip().startswith(f"{AIGPTraceState.VENDOR_KEY}=")
            ]
            if entries:
                return f"{aigp_entry},{','.join(entries)}"

        return aigp_entry

    @staticmethod
    def extract_from_tracestate(tracestate: str) -> dict[str, str]:
        """
        Extract AIGP governance context from a tracestate header value.

        Args:
            tracestate: The full tracestate header value.

        Returns:
            Dict with decoded governance context, or empty dict if no aigp entry.
        """
        for entry in tracestate.split(","):
            entry = entry.strip()
            if entry.startswith(f"{AIGPTraceState.VENDOR_KEY}="):
                vendor_value = entry[len(f"{AIGPTraceState.VENDOR_KEY}="):]
                return AIGPTraceState.decode(vendor_value)

        return {}
