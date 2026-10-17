import pytest
from datetime import datetime, timezone
from src.ingestion.models import AuthEvent
from pydantic import ValidationError

def test_invalid_ip_is_rejected():
    with pytest.raises(ValidationError):
        AuthEvent(
            timestamp=datetime(2026, 10, 3, 0, 0, 0, tzinfo=timezone.utc),
            source_ip="abc",
            username = "root",
            outcome = "failure",
            raw = "test line"
        )

def test_invalid_timestamp_is_rejected():
    with pytest.raises(ValidationError):
        AuthEvent(
            timestamp=datetime(2026, 10, 3, 0, 0, 0),
            source_ip="192.168.0.92",
            username = "root",
            outcome = "failure",
            raw = "test line"
        )

def test_invalid_ip_is_rejected():
    with pytest.raises(ValidationError):
        AuthEvent(
            timestamp=datetime(2026, 10, 3, 0, 0, 0, tzinfo=timezone.utc),
            source_ip="192.168.0.92",
            username = "dasdajkdajkdjasdajksbdajksbdakjbdaskpdas[d[asdjbas[dbjsajbdaskbdkasbdkasbdjsbdsaakjdjskadbj]]]",
            outcome = "failure",
            raw = "test line"
        )
