from collections import defaultdict

from src.detection.models import Alert


def detect_brute_force(events, threshold=5, window_seconds=60):
    groups = defaultdict(list)
    for event in events:
        if event.outcome == "failure":
            groups[(event.source_ip, event.username)].append(event)

    alerts = []
    for group in groups.values():
        group.sort(key=lambda e: e.timestamp)
        alerts += _scan(group, threshold, window_seconds)
    alerts.sort(key=lambda a: a.first_seen)
    return alerts


def _scan(group, threshold, window_seconds):
    alerts = []
    start = 0
    burst_start = None
    for end, event in enumerate(group):
        while (event.timestamp - group[start].timestamp).total_seconds() > window_seconds:
            start += 1
        count = end - start + 1
        if count >= threshold:
            if burst_start is None:
                burst_start = start
        elif burst_start is not None:
            alerts.append(_make_alert(group[burst_start:end]))
            burst_start = None
    if burst_start is not None:
        alerts.append(_make_alert(group[burst_start:]))
    return alerts


def _make_alert(evidence):
    return Alert(
        rule_id="brute_force",
        severity="high",
        mitre_technique="T1110.001",
        source_ip=evidence[0].source_ip,
        username=evidence[0].username,
        first_seen=evidence[0].timestamp,
        last_seen=evidence[-1].timestamp,
        evidence=tuple(evidence),
    )