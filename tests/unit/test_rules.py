from datetime import UTC, datetime, timedelta

import pytest

from src.detection.models import MAX_EVIDENCE_EVENTS
from src.detection.rules import (
    detect_brute_force,
    detect_password_spraying,
    detect_success_after_failures,
)
from src.ingestion.models import AuthEvent

START = datetime(2026, 10, 1, 3, 0, 0, tzinfo=UTC)
USERS = ("alice", "bob", "carol", "dave", "erin")
ACCOUNTS = ["admin", "oracle", "git", "test", "deploy", "ftp", "pi", "guest"]

def make_event(**overrides):
    data = {
        "timestamp": START,
        "source_ip": "203.0.113.5",
        "username": "root",
        "outcome": "failure",
        "raw": "test line"
    }
    data.update(overrides)
    return AuthEvent(**data)

def failures(offsets, ip="203.0.113.5", user="root"):
    return [make_event(source_ip=ip, username=user, timestamp=START+timedelta(seconds=s)) for s in offsets]

def spray(users, ip="203.0.113.5", step=30, start=START):
    """One failure per username from `ip`, `step` seconds apart, starting at `start`."""
    return [
        make_event(source_ip=ip, username=user, timestamp=start + timedelta(seconds=i * step))
        for i, user in enumerate(users)
    ]

def test_five_failures_in_ten_seconds_raise_one_alert():
    alerts = detect_brute_force(failures([0, 2, 4, 6, 8]))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "brute_force"
    assert alert.severity == "high"
    assert alert.mitre_technique == "T1110.001"
    assert alert.username == "root"
    assert str(alert.source_ip) == "203.0.113.5"
    assert len(alert.evidence) == 5
    assert alert.first_seen == START
    assert alert.last_seen == START + timedelta(seconds=8)

def test_below_threshold_raises_nothing():
    assert detect_brute_force(failures([0, 2, 4, 6])) == []

def test_slow_failures_raise_nothing():
    assert detect_brute_force(failures([0, 150, 300, 450, 600])) == []

def test_failures_on_different_accounts_do_not_add_up():
    events = []
    for i, user in enumerate(["a", "b", "c", "d", "e"]):
        events += failures([i], user=user)
    assert detect_brute_force(events) == []

def test_successes_are_ignored():
    events = [make_event(outcome="success", timestamp=START +timedelta(seconds=s)) for s in range(5)]
    assert detect_brute_force(events) == []

def test_unsorted_input_still_detects():
    events = failures([8, 0, 6, 2, 4])
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    # Without sorting, first_seen would be +8 s and last_seen +4 s.
    assert alerts[0].first_seen == START
    assert alerts[0].last_seen == START + timedelta(seconds=8)

def test_one_long_burst_raises_a_single_alert():
    alerts = detect_brute_force(failures(range(0, 120, 3)))
    assert len(alerts) == 1
    assert len(alerts[0].evidence) == MAX_EVIDENCE_EVENTS
    assert alerts[0].event_count == 40

def test_two_separate_bursts_raise_two_alerts():
    events = failures([0, 1, 2, 3, 4]) + failures([3600, 3601, 3602, 3603, 3604])
    assert len(detect_brute_force(events)) == 2

def test_failures_from_different_ips_do_not_add_up():
    events = failures([0, 1, 2], ip="203.0.113.5") + failures([0, 1, 2], ip="198.51.100.23")
    assert detect_brute_force(events, threshold=5) == []

def test_only_the_ip_over_threshold_raises_an_alert():
    events = failures([0, 1, 2, 3, 4], ip="203.0.113.5") + failures([0, 1], ip="198.51.100.23")
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert str(alerts[0].source_ip) == "203.0.113.5"

@pytest.mark.parametrize("count, expected_alerts", [(2, 0), (3, 1), (4, 1)])
def test_threshold_boundary(count, expected_alerts):
    alerts = detect_brute_force(failures(range(count)), threshold=3)
    assert len(alerts) == expected_alerts

@pytest.mark.parametrize("last_offset, expected_alerts", [(60,1), (61, 0),])
def test_window_boundary(last_offset, expected_alerts):
    alerts = detect_brute_force(failures([0, 15, 30, 45, last_offset]), window_seconds=60)
    assert len(alerts) == expected_alerts

def test_five_users_from_one_ip_raise_one_alert():
    alerts = detect_password_spraying(spray(USERS))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "password_spraying"
    assert alert.severity == "medium"
    assert alert.mitre_technique == "T1110.003"
    assert alert.username is None
    assert str(alert.source_ip) == "203.0.113.5"
    assert len(alert.evidence) == 5
    assert alert.first_seen == START
    assert alert.last_seen == START + timedelta(seconds=120)

def test_one_long_spray_raises_a_single_alert():
    # 30 events, 30 s apart -> last one at 870 s, so the 600 s window really slides.
    alerts = detect_password_spraying(spray(USERS * 6))
    assert len(alerts) == 1
    assert len(alerts[0].evidence) == MAX_EVIDENCE_EVENTS
    assert alerts[0].event_count == 30
    assert alerts[0].first_seen == START
    assert alerts[0].last_seen == START + timedelta(seconds=870)

def test_two_separate_sprays_raise_two_alerts():
    later = START + timedelta(hours=1)
    events = spray(USERS) + spray(USERS, start=later)
    assert len(detect_password_spraying(events)) == 2

def test_unsorted_input_still_detects_spraying():
    events = list(reversed(spray(USERS)))
    alerts = detect_password_spraying(events)
    assert len(alerts) == 1
    assert alerts[0].first_seen == START
    assert alerts[0].last_seen == START + timedelta(seconds=120)

def test_four_users_raise_nothing():
    assert detect_password_spraying(spray(USERS[:4])) == []

def test_repeated_failures_on_two_users_raise_nothing():
    assert detect_password_spraying(spray(USERS[:2] * 5)) == []

def test_users_spread_beyond_the_window_raise_nothing():
    assert detect_password_spraying(spray(USERS, step=200)) == []

def test_users_split_across_ips_do_not_add_up():
    events = spray(USERS[:3], ip="203.0.113.5") + spray(USERS[3:], ip="203.0.113.6")
    assert detect_password_spraying(events) == []

def test_successful_logins_are_not_spraying():
    events = [
        make_event(source_ip="203.0.113.5", username=user, outcome="success",
                   timestamp=START + timedelta(seconds=i * 30))
        for i, user in enumerate(USERS)
    ]
    assert detect_password_spraying(events) == []

def test_success_does_not_count_toward_distinct_users():
    events = spray(USERS[:4]) + [
        make_event(username=USERS[4], outcome="success", timestamp=START + timedelta(seconds=120))
    ]
    assert detect_password_spraying(events) == []

@pytest.mark.parametrize("count, expected_alerts", [(2, 0), (3, 1), (4, 1)])
def test_spraying_threshold_boundary(count, expected_alerts):
    alerts = detect_password_spraying(spray(USERS[:count]), threshold=3)
    assert len(alerts) == expected_alerts


@pytest.mark.parametrize(
    "window_seconds, step, expected_alerts",
    [
        (600, 150, 1),  # span 600 s = window -> inside
        (600, 151, 0),  # span 604 s > window -> outside
        (120, 30, 1),   # non-default window: span 120 s -> inside
        (120, 31, 0),   # span 124 s -> outside (proves window_seconds is really used)
    ],
)
def test_spraying_window_boundary(window_seconds, step, expected_alerts):
    alerts = detect_password_spraying(spray(USERS, step=step), window_seconds=window_seconds)
    assert len(alerts) == expected_alerts

def test_empty_input_returns_no_alerts():
    assert detect_password_spraying([]) == []


def test_two_ips_spraying_at_the_same_time_raise_two_alerts():
    events = spray(ACCOUNTS, ip="203.0.113.5") + spray(ACCOUNTS, ip="198.51.100.23")
    alerts = detect_password_spraying(events)
    assert len(alerts) == 2
    assert {str(a.source_ip) for a in alerts} == {"203.0.113.5", "198.51.100.23"}
    for alert in alerts:
        assert len(alert.evidence) == 8
        assert {str(e.source_ip) for e in alert.evidence} == {str(alert.source_ip)}


def test_only_the_ip_over_threshold_raises_a_spraying_alert():
    events = spray(ACCOUNTS, ip="203.0.113.5") + spray(ACCOUNTS[:3], ip="198.51.100.23")
    alerts = detect_password_spraying(events)
    assert len(alerts) == 1
    assert str(alerts[0].source_ip) == "203.0.113.5"
    assert len(alerts[0].evidence) == 8


def test_usernames_differing_only_in_case_are_different_accounts_for_brute_force():
    events = failures([0, 1, 2], user="root") + failures([3, 4], user="Root")
    assert detect_brute_force(events) == []


def test_usernames_differing_only_in_case_count_as_distinct_for_spraying():
    alerts = detect_password_spraying(spray(["root", "Root", "ROOT", "rOot", "roOt"]))
    assert len(alerts) == 1


@pytest.mark.parametrize(
    "rule", [detect_brute_force, detect_password_spraying, detect_success_after_failures]
)
@pytest.mark.parametrize("kwargs", [{"threshold": 0}, {"threshold": -1}, {"window_seconds": -1}])
def test_invalid_parameters_raise_value_error(rule, kwargs):
    with pytest.raises(ValueError):
        rule(failures([0, 1, 2]), **kwargs)


def success(offset, ip="203.0.113.5", user="root"):
    return make_event(source_ip=ip, username=user, outcome="success",
                      timestamp=START + timedelta(seconds=offset))


def test_success_after_five_failures_raises_one_critical_alert():
    alerts = detect_success_after_failures(failures([0, 2, 4, 6, 8]) + [success(10)])
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "success_after_failures"
    assert alert.severity == "critical"
    assert alert.mitre_technique == "T1078"
    assert alert.username == "root"
    assert len(alert.evidence) == 6
    assert alert.evidence[-1].outcome == "success"
    assert alert.first_seen == START
    assert alert.last_seen == START + timedelta(seconds=10)


def test_failures_without_success_raise_nothing():
    assert detect_success_after_failures(failures(range(20))) == []


def test_one_typo_then_success_raises_nothing():
    assert detect_success_after_failures(failures([0]) + [success(5)]) == []


def test_success_before_failures_raises_nothing():
    assert detect_success_after_failures([success(0)] + failures([1, 2, 3, 4, 5])) == []


def test_failures_outside_the_window_do_not_count():
    events = failures([0, 1, 2, 3, 4]) + [success(400)]
    assert detect_success_after_failures(events) == []


@pytest.mark.parametrize("success_at, expected_alerts", [(300, 1), (301, 0)])
def test_success_after_failures_window_boundary(success_at, expected_alerts):
    events = failures([0, 0, 0, 0, 0]) + [success(success_at)]
    assert len(detect_success_after_failures(events)) == expected_alerts


def test_success_resets_the_failure_count():
    events = failures([0, 1, 2, 3, 4]) + [success(5)] + failures([6]) + [success(7)]
    alerts = detect_success_after_failures(events)
    assert len(alerts) == 1
    assert alerts[0].last_seen == START + timedelta(seconds=5)


def test_failures_on_another_account_do_not_count():
    events = failures([0, 1, 2, 3, 4], user="bob") + [success(5, user="alice")]
    assert detect_success_after_failures(events) == []


def test_failures_from_another_ip_do_not_count():
    events = failures([0, 1, 2, 3, 4], ip="198.51.100.23") + [success(5)]
    assert detect_success_after_failures(events) == []


def test_unsorted_input_still_detects_compromise():
    events = [success(10)] + list(reversed(failures([0, 2, 4, 6, 8])))
    alerts = detect_success_after_failures(events)
    assert len(alerts) == 1
    assert alerts[0].first_seen == START


@pytest.mark.parametrize("count, expected_alerts", [(1, 0), (2, 1), (3, 1)])
def test_success_after_failures_threshold_boundary(count, expected_alerts):
    events = failures(range(count)) + [success(count)]
    assert len(detect_success_after_failures(events, threshold=2)) == expected_alerts


def test_long_burst_keeps_first_and_last_events():
    alerts = detect_brute_force(failures(range(0, 120, 3)))
    offsets = [(e.timestamp - START).total_seconds() for e in alerts[0].evidence]
    assert offsets == [0, 3, 6, 9, 12, 105, 108, 111, 114, 117]


def test_long_success_after_failures_keeps_the_success():
    alerts = detect_success_after_failures(failures(range(0, 60, 2)) + [success(60)])
    alert = alerts[0]
    assert alert.event_count == 31
    assert len(alert.evidence) == MAX_EVIDENCE_EVENTS
    assert alert.evidence[-1].outcome == "success"
    assert alert.last_seen == START + timedelta(seconds=60)
