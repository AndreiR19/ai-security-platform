from collections import Counter, defaultdict
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv6Address

from src.detection.models import Alert
from src.ingestion.models import AuthEvent


def detect_brute_force(events: Iterable[AuthEvent], threshold: int = 5, window_seconds: int = 60) -> list[Alert]:
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

def detect_password_spraying(events: Iterable[AuthEvent], threshold: int = 5, window_seconds: int = 600) -> list[Alert]:
    groups: defaultdict[IPv4Address | IPv6Address, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if event.outcome == "failure":
            groups[event.source_ip].append(event) 

    alerts: list[Alert] = []
    for group in groups.values():
        group.sort(key=lambda e: e.timestamp)
        alerts += _scan_spraying(group, threshold, window_seconds)
    alerts.sort(key=lambda a: a.first_seen)
    return alerts


def _scan_spraying(group: list[AuthEvent], threshold: int, window_seconds: int) -> list[Alert]:
    alerts: list[Alert] = []
    users: Counter[str] = Counter()
    start = 0
    burst_start: int | None = None
    for end, event in enumerate(group):
        users[event.username] += 1 
        while (event.timestamp - group[start].timestamp).total_seconds() > window_seconds:
            old = group[start].username  
            users[old] -= 1
            if users[old] == 0:
                del users[old]
            start += 1
        if len(users) >= threshold:
            if burst_start is None:
                burst_start = start  
        elif burst_start is not None:
            alerts.append(_make_spraying_alert(group[burst_start:end]))
            burst_start = None
    if burst_start is not None:
        alerts.append(_make_spraying_alert(group[burst_start:]))
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

def _make_spraying_alert(evidence: list[AuthEvent]) -> Alert:
    return Alert(
        rule_id="password_spraying",
        severity="medium",
        mitre_technique="T1110.003",
        source_ip=evidence[0].source_ip,
        first_seen=evidence[0].timestamp,
        last_seen=evidence[-1].timestamp,
        evidence=tuple(evidence),
    )