import random
from datetime import UTC, datetime

import pytest

from scripts.generate_logs import brute_force, format_line
from src.ingestion.parser import parse_line

START = datetime(2026, 10, 1, 3, 0, 0, tzinfo=UTC)
IP = "203.0.113.5"


def test_format_line_round_trips_through_parser():
    rng = random.Random(1)
    ts = datetime(2026, 10, 1, 3, 12, 5, tzinfo=UTC)
    line = format_line(ts, "failure", "root", "203.0.113.5", rng)
    event = parse_line(line, 2026)
    assert event is not None
    assert event.timestamp == ts
    assert event.username == "root"
    assert str(event.source_ip) == "203.0.113.5"
    assert event.outcome == "failure"


def test_format_line_pads_single_digit_day_with_two_spaces():
    rng = random.Random(1)
    ts = datetime(2026, 10, 1, 3, 12, 5, tzinfo=UTC)
    line = format_line(ts, "failure", "root", "203.0.113.5", rng)
    event = parse_line(line, 2026)
    assert event is not None
    assert line.startswith("Oct  1 03:12:05 ")
    assert event.timestamp == ts
    assert event.username == "root"
    assert str(event.source_ip) == "203.0.113.5"
    assert event.outcome == "failure"


def test_brute_force_events_are_failures_for_root_from_given_ip():
    events, _ = brute_force(random.Random(7), START, IP)
    for _, line in events:
        event = parse_line(line, 2026)
        assert event is not None
        assert event.outcome == "failure"
        assert event.username == "root"
        assert str(event.source_ip) == IP


@pytest.mark.parametrize("seed", range(20))
def test_brute_force_event_count_is_in_range(seed):
    events, _ = brute_force(random.Random(seed), START, IP)
    assert 30 <= len(events) <= 60


def test_brute_force_label_matches_events():
    events, label = brute_force(random.Random(7), START, IP)
    assert label["scenario"] == "brute_force"
    assert label["source_ip"] == IP
    assert label["start"] == events[0][0].isoformat()
    assert label["end"] == events[-1][0].isoformat()
