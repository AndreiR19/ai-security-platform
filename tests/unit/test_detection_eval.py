from datetime import UTC, datetime, timedelta

import pytest

from evals.detection_eval import evaluate, match_alerts, precision_recall
from src.detection.models import Alert
from src.ingestion.models import AuthEvent

START = datetime(2026, 10, 1, 3, 0, 0, tzinfo=UTC)


def alert(ip="203.0.113.5", start=0, end=60):
    event = AuthEvent(timestamp=START, source_ip=ip, username="root", outcome="failure", raw="x")
    return Alert(
        rule_id="brute_force",
        severity="high",
        mitre_technique="T1110.001",
        source_ip=ip,
        first_seen=START + timedelta(seconds=start),
        last_seen=START + timedelta(seconds=end),
        evidence=(event,),
    )


def label(ip="203.0.113.5", start=0, end=60):
    return {
        "scenario": "brute_force",
        "source_ip": ip,
        "start": (START + timedelta(seconds=start)).isoformat(),
        "end": (START + timedelta(seconds=end)).isoformat(),
    }


def test_matching_alert_is_a_detection():
    assert match_alerts([alert()], [label()]) == (1, 0, 0)


def test_two_alerts_for_one_attack_count_as_one_detection():
    assert match_alerts([alert(), alert(start=10, end=20)], [label()]) == (1, 0, 0)


def test_alert_on_wrong_ip_is_false_alarm_and_attack_is_missed():
    assert match_alerts([alert(ip="10.0.0.5")], [label()]) == (0, 1, 1)


def test_alert_outside_attack_time_does_not_match():
    assert match_alerts([alert(start=100, end=200)], [label(end=60)]) == (0, 1, 1)


def test_touching_time_ranges_overlap():
    assert match_alerts([alert(start=60, end=90)], [label(end=60)]) == (1, 0, 0)


def test_no_alerts_and_no_labels():
    assert match_alerts([], []) == (0, 0, 0)


@pytest.mark.parametrize(
    "counts, expected",
    [((3, 0, 0), (1.0, 1.0)), ((1, 1, 1), (0.5, 0.5)), ((0, 0, 0), (1.0, 1.0)), ((0, 2, 0), (0.0, 1.0))],
)
def test_precision_recall(counts, expected):
    assert precision_recall(*counts) == pytest.approx(expected)


def test_rules_reach_full_recall_and_precision_on_seeds_0_to_19():
    tp, fp, fn = evaluate(range(20))
    assert (fp, fn) == (0, 0)
    assert tp == 60
