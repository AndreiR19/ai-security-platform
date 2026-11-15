import json

import pytest

from scripts.detect import main
from scripts.generate_logs import build_dataset
from src.detection.engine import run_rules
from src.detection.rules import detect_brute_force
from src.ingestion.parser import parse_lines

ATTACKERS = {"203.0.113.5", "198.51.100.23", "203.0.113.77"}


def alerts_for_seed(seed):
    lines, _ = build_dataset(seed)
    return run_rules(parse_lines(lines, 2026))


def test_seed_42_alerts_on_exactly_the_three_attackers():
    alerts = alerts_for_seed(42)
    assert {str(a.source_ip) for a in alerts} == ATTACKERS
    assert not any(str(a.source_ip).startswith("10.0.0.") for a in alerts)


def test_seed_42_each_rule_fires_on_its_scenario():
    alerts = alerts_for_seed(42)
    by_rule = {}
    for alert in alerts:
        by_rule.setdefault(alert.rule_id, set()).add(str(alert.source_ip))
    assert by_rule["password_spraying"] == {"198.51.100.23"}
    assert by_rule["success_after_failures"] == {"203.0.113.77"}
    assert "203.0.113.5" in by_rule["brute_force"]


@pytest.mark.parametrize("seed", range(20))
def test_compromise_is_flagged_only_for_the_compromised_ip(seed):
    alerts = alerts_for_seed(seed)
    flagged = {str(a.source_ip) for a in alerts if a.rule_id == "success_after_failures"}
    assert flagged == {"203.0.113.77"}


def test_rules_all_see_events_from_a_generator():
    lines, _ = build_dataset(42)
    events = parse_lines(lines, 2026)
    from_generator = run_rules(e for e in events)
    assert len(from_generator) == len(run_rules(events))


def test_custom_rule_list_is_respected():
    lines, _ = build_dataset(42)
    alerts = run_rules(parse_lines(lines, 2026), rules=[detect_brute_force])
    assert {a.rule_id for a in alerts} == {"brute_force"}


def test_cli_prints_one_json_line_per_alert(tmp_path, capsys):
    lines, _ = build_dataset(42)
    log = tmp_path / "auth.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert main([str(log), "--year", "2026"]) == 0
    output = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert {o["source_ip"] for o in output} == ATTACKERS
    assert all("evidence" not in o and o["event_count"] >= 1 for o in output)


def test_cli_rejects_missing_file(tmp_path):
    with pytest.raises(SystemExit):
        main([str(tmp_path / "missing.log"), "--year", "2026"])
