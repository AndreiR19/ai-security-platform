from collections.abc import Iterable, Sequence

from src.detection.models import Alert
from src.detection.rules import ALL_RULES, Rule
from src.ingestion.models import AuthEvent


def run_rules(events: Iterable[AuthEvent], rules: Sequence[Rule] = ALL_RULES) -> list[Alert]:
    snapshot = tuple(events)
    alerts: list[Alert] = []
    for rule in rules:
        alerts += rule(snapshot)
    return sorted(alerts, key=lambda a: (a.first_seen, a.rule_id))
