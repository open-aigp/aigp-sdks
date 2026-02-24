"""Tests for transport-agnostic reliability helpers."""

from aigp import ReliableEmitter, RetryPolicy


def test_reliable_emitter_retries_then_succeeds():
    attempts = {"n": 0}
    sent = []

    def flaky_sender(event):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise RuntimeError("transient failure")
        sent.append(event["event_id"])

    emitter = ReliableEmitter(
        flaky_sender,
        retry_policy=RetryPolicy(max_attempts=3, base_delay_s=0.0, max_delay_s=0.0),
        sleep_fn=lambda _: None,
    )
    assert emitter.emit({"event_id": "evt-1"}) is True
    assert attempts["n"] == 3
    assert sent == ["evt-1"]
    assert emitter.pending_count == 0


def test_reliable_emitter_tracks_failed_events():
    def failing_sender(_event):
        raise RuntimeError("down")

    emitter = ReliableEmitter(
        failing_sender,
        retry_policy=RetryPolicy(max_attempts=2, base_delay_s=0.0, max_delay_s=0.0),
        sleep_fn=lambda _: None,
    )
    assert emitter.emit({"event_id": "evt-2"}) is False
    assert emitter.pending_count == 1


def test_reliable_emitter_idempotent_by_event_id():
    sent = []

    def sender(event):
        sent.append(event["event_id"])

    emitter = ReliableEmitter(sender)
    assert emitter.emit({"event_id": "evt-3"}) is True
    assert emitter.emit({"event_id": "evt-3"}) is True
    assert sent == ["evt-3"]
