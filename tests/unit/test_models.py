from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from src.ingestion.models import AuthEvent


def make_event(**overrides):
    data = {
        "timestamp": datetime(2026, 10, 1, 3, 0, 0, tzinfo=UTC),
        "source_ip": "203.0.113.5",
        "username": "root",
        "outcome": "failure",
        "raw": "linie de test",
    }
    data.update(overrides)
    return AuthEvent(**data)


def failed_fields(exc_info):
    return [error["loc"][0] for error in exc_info.value.errors()]


def test_valid_event_is_created():
    event = make_event()
    assert event.username == "root"
    assert str(event.source_ip) == "203.0.113.5"
    assert event.outcome == "failure"


def test_invalid_ip_is_rejected():
    with pytest.raises(ValidationError) as exc_info:
        make_event(source_ip="abc")
    assert exc_info.value.errors()[0]["loc"] == ("source_ip",)


def test_naive_timestamp_is_rejeected():
    with pytest.raises(ValidationError) as exc_info:
        make_event(timestamp=datetime(2026, 10, 1, 3, 0, 0))
    assert failed_fields(exc_info) == ["timestamp"]


def test_username_at_limit_is_accepted():
    assert make_event(username="a" * 64).username == "a" * 64


def test_username_over_limit_is_rejected():
    with pytest.raises(ValidationError) as exc_info:
        make_event(username="a" * 65)
    assert failed_fields(exc_info) == ["username"]


def test_event_is_immutable():
    event = make_event()
    with pytest.raises(ValidationError):
        event.username = "someone"
