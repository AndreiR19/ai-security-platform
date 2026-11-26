from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from src.detection.models import MAX_EVIDENCE_EVENTS, Alert
from src.ingestion.models import AuthEvent


def make_event(**overrides):
    data = {
        "timestamp": datetime(2026, 10, 1, 3, 0, 0,tzinfo=UTC),
        "source_ip": "203.0.113.5",
        "username": "root",
        "outcome": "failure",
        "raw": "test line"
    }
    data.update(overrides)
    return AuthEvent(**data)

def make_alert(**overrides):
    data = {
        "rule_id": "brute_force",
        "severity": "high",
        "mitre_technique": "T1110.001",
        "source_ip": "203.0.113.5",
        "username": "root",
        "first_seen": datetime(2026, 10, 1, 3, 0, 0, tzinfo=UTC), 
        "last_seen": datetime(2026, 10, 1, 3, 2, 0, tzinfo=UTC),
        "evidence": (make_event(), ),
        "event_count": 1,
    }
    data.update(overrides)
    return Alert(**data)

def failed_fields(exc_info):
    return [error["loc"][0] for error in exc_info.value.errors()]

def test_valid_alert_is_created():
    alert = make_alert()
    assert alert.rule_id == "brute_force"
    assert str(alert.source_ip) == "203.0.113.5"
    assert len(alert.evidence) == 1

def test_alert_accepts_many_evidence_events():
    alert = make_alert(evidence=(make_event(), make_event(), make_event()), event_count=3)
    assert len(alert.evidence) == 3

def test_alert_without_username_is_allowed():
    assert make_alert(username=None).username is None

def test_empty_evidence_is_rejected():
    with pytest.raises(ValidationError) as exc_info:
        make_alert(evidence=())
    assert failed_fields(exc_info) == ["evidence"]

def test_unknown_severity_is_rejected():
    with pytest.raises(ValidationError) as exc_info:
        make_alert(severity="urgent")
    assert failed_fields(exc_info) == ["severity"]

def test_alert_is_immutable():
    alert = make_alert()
    with pytest.raises(ValidationError):
        alert.severity = "low"

def test_evidence_cannot_be_appended_to():
    alert = make_alert()
    with pytest.raises(AttributeError):
        alert.evidence.append(make_event())

def test_invalid_ip_is_rejected():
    with pytest.raises(ValidationError) as exc_info:
        make_alert(source_ip="abc")
    assert failed_fields(exc_info) == ["source_ip"]

def test_evidence_at_maximum_is_accepted():
    alert = make_alert(
        evidence=tuple(make_event() for _ in range(MAX_EVIDENCE_EVENTS)),
        event_count=MAX_EVIDENCE_EVENTS,
    )
    assert len(alert.evidence) == MAX_EVIDENCE_EVENTS

def test_evidence_above_maximum_is_rejected():
    with pytest.raises(ValidationError) as exc_info:
        make_alert(
            evidence=tuple(make_event() for _ in range(MAX_EVIDENCE_EVENTS + 1)),
            event_count=MAX_EVIDENCE_EVENTS + 1,
        )
    assert failed_fields(exc_info) == ["evidence"]

def test_event_count_can_exceed_evidence_length():
    alert = make_alert(
        evidence=tuple(make_event() for _ in range(MAX_EVIDENCE_EVENTS)),
        event_count=500,
    )
    assert alert.event_count == 500

def test_zero_event_count_is_rejected():
    with pytest.raises(ValidationError) as exc_info:
        make_alert(event_count=0)
    assert failed_fields(exc_info) == ["event_count"]

def test_missing_event_count_is_rejected():
    data = make_alert().model_dump(exclude={"event_count"})
    with pytest.raises(ValidationError) as exc_info:
        Alert(**data)
    assert failed_fields(exc_info) == ["event_count"]

def test_event_count_smaller_than_evidence_is_rejected():
    with pytest.raises(ValidationError, match="event_count"):
        make_alert(evidence=(make_event(), make_event()), event_count=1)

def test_evidence_shorter_than_possible_for_event_count_is_rejected():
    with pytest.raises(ValidationError, match="evidence length"):
        make_alert(evidence=(make_event(), make_event(), make_event()), event_count=500)

def test_first_seen_after_last_seen_is_rejected():
    with pytest.raises(ValidationError, match="first_seen"):
        make_alert(
            first_seen=datetime(2026, 10, 1, 3, 5, 0, tzinfo=UTC),
            last_seen=datetime(2026, 10, 1, 3, 0, 0, tzinfo=UTC),
        )

def test_first_seen_equal_to_last_seen_is_accepted():
    moment = datetime(2026, 10, 1, 3, 0, 0, tzinfo=UTC)
    assert make_alert(first_seen=moment, last_seen=moment).first_seen == moment
