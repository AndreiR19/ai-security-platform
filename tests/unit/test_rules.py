from datetime import UTC, datetime, timedelta

import pytest

from src.detection.rules import detect_brute_force, detect_password_spraying
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

def attempts(pairs, ip="203.0.113.5"):
    return [make_event(source_ip=ip, username=user, timestamp=START + timedelta(seconds=s))
            for s, user in pairs]

def test_five_failures_in_ten_seconds_raise_one_alert():
    alerts = detect_brute_force(failures([0, 2, 4, 6, 8]))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "brute_force"
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
    assert len(detect_brute_force(events)) == 1

def test_one_long_burst_raises_a_single_alert():
    alerts = detect_brute_force(failures(range(0, 120, 3)))
    assert len(alerts) == 1
    assert len(alerts[0].evidence) == 40

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

def spray(users, ip="203.0.113.5", step=30, start=START):
    return [
        make_event(source_ip=ip, username=user, timestamp=start + timedelta(seconds=i * step))
        for i, user in enumerate(users)
    ]    

def test_five_users_from_one_ip_raise_one_alert():
    alerts = detect_password_spraying(spray(USERS))
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.rule_id == "password_spraying"
    assert alert.username is None
    assert str(alert.source_ip) == "203.0.113.5"
    assert len(alert.evidence) == 5
    assert alert.first_seen == START
    assert alert.last_seen == START + timedelta(seconds=120)

def test_one_long_spray_raises_a_single_alert():
    alerts = detect_password_spraying(spray(USERS * 4))
    assert len(alerts) == 1
    assert len(alerts[0].evidence) == 20

def test_two_separate_sprays_raise_two_alerts():
    later = START + timedelta(hours=1)
    events = spray(USERS) + spray(USERS, start=later)
    assert len(detect_password_spraying(events)) == 2

def test_unsorted_input_still_detects_spraying():
    events = list(reversed(spray(USERS)))
    assert len(detect_password_spraying(events)) == 1

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

@pytest.mark.parametrize("count, expected_alerts", [(2, 0), (3, 1), (4, 1)])
def test_spraying_threshold_boundary(count, expected_alerts):
    alerts = detect_password_spraying(spray(USERS[:count]), threshold=3)
    assert len(alerts) == expected_alerts


@pytest.mark.parametrize("step, expected_alerts", [(150, 1), (151, 0)])
def test_spraying_window_boundary(step, expected_alerts):
    alerts = detect_password_spraying(spray(USERS, step=step), window_seconds=600)
    assert len(alerts) == expected_alerts

def test_empty_input_returns_no_alerts():
    assert detect_password_spraying([]) == []


def test_two_ips_spraying_at_the_same_time_raise_two_alerts():
    events = (attempts([(i * 30, u) for i, u in enumerate(ACCOUNTS)], ip="203.0.113.5")
              + attempts([(i * 30, u) for i, u in enumerate(ACCOUNTS)], ip="198.51.100.23"))
    alerts = detect_password_spraying(events)
    assert len(alerts) == 2
    assert {str(a.source_ip) for a in alerts} == {"203.0.113.5", "198.51.100.23"}
    for alert in alerts:
        assert len(alert.evidence) == 8
        assert {str(e.source_ip) for e in alert.evidence} == {str(alert.source_ip)}


def test_only_the_ip_over_threshold_raises_a_spraying_alert():
    events = (attempts([(i * 30, u) for i, u in enumerate(ACCOUNTS)], ip="203.0.113.5")
              + attempts([(i * 30, u) for i, u in enumerate(ACCOUNTS[:3])], ip="198.51.100.23"))
    alerts = detect_password_spraying(events)
    assert len(alerts) == 1
    assert str(alerts[0].source_ip) == "203.0.113.5"
    assert len(alerts[0].evidence) == 8