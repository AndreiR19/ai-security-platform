from collections import Counter, defaultdict, deque
from collections.abc import Callable, Hashable, Iterable, Sequence
from dataclasses import dataclass
from typing import Literal

from src.detection.models import MAX_EVIDENCE_EVENTS, Alert
from src.ingestion.models import AuthEvent

Severity = Literal["low", "medium", "high", "critical"]
Rule = Callable[[Sequence[AuthEvent]], list[Alert]]


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    severity: Severity
    mitre_technique: str


BRUTE_FORCE = RuleSpec("brute_force", "high", "T1110.001")
PASSWORD_SPRAYING = RuleSpec("password_spraying", "medium", "T1110.003")
SUCCESS_AFTER_FAILURES = RuleSpec("success_after_failures", "critical", "T1078")


def detect_brute_force(
    events: Iterable[AuthEvent], threshold: int = 5, window_seconds: int = 60
) -> list[Alert]:
    _validate(threshold, window_seconds)
    groups = _group(events, key=lambda e: (e.source_ip, e.username), failures_only=True)
    alerts: list[Alert] = []
    for group in groups.values():
        alerts += _scan(group, threshold, window_seconds)
    return _sorted(alerts)


def detect_password_spraying(
    events: Iterable[AuthEvent], threshold: int = 5, window_seconds: int = 600
) -> list[Alert]:
    _validate(threshold, window_seconds)
    groups = _group(events, key=lambda e: e.source_ip, failures_only=True)
    alerts: list[Alert] = []
    for group in groups.values():
        alerts += _scan_spraying(group, threshold, window_seconds)
    return _sorted(alerts)


def detect_success_after_failures(
    events: Iterable[AuthEvent], threshold: int = 5, window_seconds: int = 300
) -> list[Alert]:
    _validate(threshold, window_seconds)
    groups = _group(events, key=lambda e: (e.source_ip, e.username), failures_only=False)
    alerts: list[Alert] = []
    for group in groups.values():
        alerts += _scan_success_after_failures(group, threshold, window_seconds)
    return _sorted(alerts)


ALL_RULES: tuple[Rule, ...] = (
    detect_brute_force,
    detect_password_spraying,
    detect_success_after_failures,
)


def _validate(threshold: int, window_seconds: int) -> None:
    if threshold < 1:
        raise ValueError("threshold must be >= 1")
    if window_seconds < 0:
        raise ValueError("window_seconds must be >= 0")


def _group(
    events: Iterable[AuthEvent],
    key: Callable[[AuthEvent], Hashable],
    failures_only: bool,
) -> dict[Hashable, list[AuthEvent]]:
    groups: defaultdict[Hashable, list[AuthEvent]] = defaultdict(list)
    for event in events:
        if failures_only and event.outcome != "failure":
            continue
        groups[key(event)].append(event)
    for group in groups.values():
        group.sort(key=lambda e: e.timestamp)
    return groups


def _sorted(alerts: list[Alert]) -> list[Alert]:
    return sorted(alerts, key=lambda a: a.first_seen)


def _make_alert(spec: RuleSpec, evidence: Sequence[AuthEvent], per_user: bool) -> Alert:
    return Alert(
        rule_id=spec.rule_id,
        severity=spec.severity,
        mitre_technique=spec.mitre_technique,
        source_ip=evidence[0].source_ip,
        username=evidence[0].username if per_user else None,
        first_seen=evidence[0].timestamp,
        last_seen=evidence[-1].timestamp,
        evidence=_cap(evidence),
        event_count=len(evidence),
    )


def _cap(evidence: Sequence[AuthEvent]) -> tuple[AuthEvent, ...]:
    if len(evidence) <= MAX_EVIDENCE_EVENTS:
        return tuple(evidence)
    head = MAX_EVIDENCE_EVENTS // 2
    tail = MAX_EVIDENCE_EVENTS - head
    return (*evidence[:head], *evidence[-tail:])


def _gap(later: AuthEvent, earlier: AuthEvent) -> float:
    return (later.timestamp - earlier.timestamp).total_seconds()


def _scan(group: list[AuthEvent], threshold: int, window_seconds: int) -> list[Alert]:
    alerts: list[Alert] = []
    start = 0
    burst_start: int | None = None
    for end, event in enumerate(group):
        while _gap(event, group[start]) > window_seconds:
            start += 1
        if end - start + 1 >= threshold:
            if burst_start is None:
                burst_start = start
        elif burst_start is not None:
            alerts.append(_make_alert(BRUTE_FORCE, group[burst_start:end], per_user=True))
            burst_start = None
    if burst_start is not None:
        alerts.append(_make_alert(BRUTE_FORCE, group[burst_start:], per_user=True))
    return alerts


def _scan_spraying(group: list[AuthEvent], threshold: int, window_seconds: int) -> list[Alert]:
    alerts: list[Alert] = []
    users: Counter[str] = Counter()
    start = 0
    burst_start: int | None = None
    for end, event in enumerate(group):
        users[event.username] += 1
        while _gap(event, group[start]) > window_seconds:
            old = group[start].username
            users[old] -= 1
            if users[old] == 0:
                del users[old]
            start += 1
        if len(users) >= threshold:
            if burst_start is None:
                burst_start = start
        elif burst_start is not None:
            alerts.append(_make_alert(PASSWORD_SPRAYING, group[burst_start:end], per_user=False))
            burst_start = None
    if burst_start is not None:
        alerts.append(_make_alert(PASSWORD_SPRAYING, group[burst_start:], per_user=False))
    return alerts


def _scan_success_after_failures(
    group: list[AuthEvent], threshold: int, window_seconds: int
) -> list[Alert]:
    alerts: list[Alert] = []
    recent_failures: deque[AuthEvent] = deque()
    for event in group:
        if event.outcome == "failure":
            recent_failures.append(event)
            continue
        while recent_failures and _gap(event, recent_failures[0]) > window_seconds:
            recent_failures.popleft()
        if len(recent_failures) >= threshold:
            alerts.append(
                _make_alert(SUCCESS_AFTER_FAILURES, [*recent_failures, event], per_user=True)
            )
        recent_failures.clear()
    return alerts
