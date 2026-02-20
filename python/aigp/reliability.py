"""
Transport-agnostic reliability helpers for AIGP event delivery.

These utilities intentionally do not assume HTTP, Kafka, or any vendor
transport. They wrap a caller-provided sender callback with retry and
idempotency behavior.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable


Sender = Callable[[dict[str, Any]], None]
SleepFn = Callable[[float], None]


@dataclass
class RetryPolicy:
    """Basic exponential-backoff retry policy."""

    max_attempts: int = 3
    base_delay_s: float = 0.1
    max_delay_s: float = 2.0

    def delay_for_attempt(self, attempt: int) -> float:
        # attempt is 1-based
        delay = self.base_delay_s * (2 ** max(0, attempt - 1))
        return min(delay, self.max_delay_s)


class ReliableEmitter:
    """
    In-memory reliable sender wrapper.

    - Retries transient sender failures using RetryPolicy.
    - Optionally deduplicates by event_id for idempotent delivery.
    - Keeps failed events in memory for later flush().
    """

    def __init__(
        self,
        sender: Sender,
        *,
        retry_policy: RetryPolicy | None = None,
        idempotent: bool = True,
        sleep_fn: SleepFn = time.sleep,
    ):
        self._sender = sender
        self._retry_policy = retry_policy or RetryPolicy()
        self._idempotent = idempotent
        self._sleep_fn = sleep_fn
        self._delivered_ids: set[str] = set()
        self._failed_events: list[dict[str, Any]] = []

    @property
    def pending_count(self) -> int:
        return len(self._failed_events)

    def emit(self, event: dict[str, Any]) -> bool:
        event_id = str(event.get("event_id", "")).strip()
        if self._idempotent and event_id and event_id in self._delivered_ids:
            return True

        last_error: Exception | None = None
        for attempt in range(1, self._retry_policy.max_attempts + 1):
            try:
                self._sender(event)
                if event_id:
                    self._delivered_ids.add(event_id)
                return True
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                if attempt < self._retry_policy.max_attempts:
                    self._sleep_fn(self._retry_policy.delay_for_attempt(attempt))

        failure_entry = dict(event)
        if last_error is not None:
            failure_entry["_delivery_error"] = str(last_error)
        self._failed_events.append(failure_entry)
        return False

    def flush_failed(self, *, max_items: int = 1000) -> dict[str, int]:
        delivered = 0
        remaining: list[dict[str, Any]] = []
        for event in self._failed_events[:max_items]:
            retry_event = {k: v for k, v in event.items() if k != "_delivery_error"}
            if self.emit(retry_event):
                delivered += 1
            else:
                remaining.append(event)

        remaining.extend(self._failed_events[max_items:])
        self._failed_events = remaining
        return {"delivered": delivered, "pending": len(self._failed_events)}


__all__ = [
    "RetryPolicy",
    "ReliableEmitter",
]
