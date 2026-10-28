import json
import random
from collections import Counter
from datetime import UTC, datetime

import pytest

from scripts.generate_logs import (
    USERS,
    brute_force,
    build_dataset,
    compromise,
    format_line,
    main,
    normal_traffic,
    password_spraying,
)
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

def test_spraying_is_deterministic():
    a = password_spraying(random.Random(7), START, IP)
    b = password_spraying(random.Random(7), START, IP)
    assert a == b

def test_spraying_hits_many_distinct_accounts_from_one_ip():
    events, _ = password_spraying(random.Random(7), START, IP)
    parsed = [parse_line(line, 2026) for _, line in events]
    assert all(e is not None and e.outcome == "failure" for e in parsed)
    assert {str(e.source_ip) for e in parsed} == {IP}
    assert len({e.username for e in parsed}) == 12

@pytest.mark.parametrize("seed", range(20))
def test_spraying_never_tries_an_account_more_than_twice(seed):
    events, _ = password_spraying(random.Random(seed), START, IP)
    attempts = Counter(parse_line(line, 2026).username for _, line in events)
    assert max(attempts.values()) <= 2

def test_compromise_is_deterministic():
    a = compromise(random.Random(7), START, IP)
    b = compromise(random.Random(7), START, IP)
    assert a == b

@pytest.mark.parametrize("seed", range(20))
def test_compromise_is_failures_then_one_success(seed):
    events, _ = compromise(random.Random(seed), START, IP)
    parsed = [parse_line(line, 2026) for _, line in events]
    assert all(e is not None for e in parsed)
    assert [e.outcome for e in parsed[:-1]] == ["failure"] * (len(parsed) - 1)
    assert parsed[-1].outcome == "success"
    assert 8 <= len(parsed) - 1 <= 12

def test_compromise_targets_one_valid_account_from_one_ip():
    events, _ = compromise(random.Random(7), START, IP)
    parsed = [parse_line(line, 2026) for _ ,line in events]
    assert {e.username for e in parsed} == {"alice"}
    assert {str(e.source_ip) for e in parsed} == {IP}
    assert all("invalid user" not in line for _, line in events)

def test_normal_traffic_is_deterministic():
    a = normal_traffic(random.Random(7), START, 24)
    b = normal_traffic(random.Random(7), START, 24)
    assert a == b

def test_normal_traffic_uses_known_users_from_internal_ip():
    events = normal_traffic(random.Random(7), START, 24)
    parsed = [parse_line(line, 2026) for _, line in events]
    assert all(e is not None for e in parsed)
    assert {e.username for e in parsed} == set(USERS)
    assert all(str(e.source_ip).startswith("10.0.0.") for e in parsed)

def test_normal_traffic_failures_are_typos_followed_by_success():
    events = normal_traffic(random.Random(7), START, 24)
    parsed = [parse_line(line, 2026) for _, line in events]
    for user in USERS:
        mine = sorted([e for e in parsed if e.username == user], key=lambda e: e.timestamp)
        for i, event in enumerate(mine):
            if event.outcome == "failure":
                nxt = mine[i + 1]
                assert nxt.outcome == "success"
                assert (nxt.timestamp - event.timestamp).total_seconds() <= 20

def test_dataset_is_deterministic():
    assert build_dataset(42) == build_dataset(42)

def test_dataset_lines_are_sorted_by_time_and_all_parse():
    lines, _ = build_dataset(42)
    parsed = [parse_line(line, 2026) for line in lines]
    assert all(e is not None for e in parsed)
    timestamps = [e.timestamp for e in parsed]
    assert timestamps == sorted(timestamps)

def test_dataset_has_three_labeled_attacks_present_in_log():
    lines, labels = build_dataset(42)
    assert {item["scenario"] for item in labels} == {"brute_force", "password_spraying", "compromise_after_bruteforce"}
    for item in labels:
        assert any(item["source_ip"] in line for line in lines)

def test_main_writes_log_and_labels(tmp_path):
    main(["--seed", "1", "--out", str(tmp_path)])
    lines = (tmp_path / "auth.log").read_text().splitlines()
    labels = json.loads((tmp_path / "labels.json").read_text())
    assert len(lines) > 0
    assert len(labels) == 3
    