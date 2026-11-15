import argparse
import logging
import sys
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime

from scripts.generate_logs import build_dataset
from src.detection.engine import run_rules
from src.detection.models import Alert
from src.ingestion.parser import parse_lines

DATASET_YEAR = 2026


def _overlaps(alert: Alert, label: Mapping[str, str]) -> bool:
    start = datetime.fromisoformat(label["start"])
    end = datetime.fromisoformat(label["end"])
    return alert.first_seen <= end and start <= alert.last_seen


def _matches(alert: Alert, label: Mapping[str, str]) -> bool:
    return str(alert.source_ip) == label["source_ip"] and _overlaps(alert, label)


def match_alerts(
    alerts: Sequence[Alert], labels: Sequence[Mapping[str, str]]
) -> tuple[int, int, int]:
    detected = sum(1 for label in labels if any(_matches(a, label) for a in alerts))
    false_alarms = sum(1 for alert in alerts if not any(_matches(alert, lb) for lb in labels))
    return detected, false_alarms, len(labels) - detected


def precision_recall(tp: int, fp: int, fn: int) -> tuple[float, float]:
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return precision, recall


def evaluate(seeds: Iterable[int]) -> tuple[int, int, int]:
    total_tp = total_fp = total_fn = 0
    for seed in seeds:
        lines, labels = build_dataset(seed)
        alerts = run_rules(parse_lines(lines, DATASET_YEAR))
        tp, fp, fn = match_alerts(alerts, labels)
        total_tp, total_fp, total_fn = total_tp + tp, total_fp + fp, total_fn + fn
    return total_tp, total_fp, total_fn


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure detection rules on synthetic datasets.")
    parser.add_argument("--seeds", type=int, default=20)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

    tp, fp, fn = evaluate(range(args.seeds))
    precision, recall = precision_recall(tp, fp, fn)
    sys.stdout.write(
        f"seeds={args.seeds} detected={tp} false_alarms={fp} missed={fn} "
        f"precision={precision:.3f} recall={recall:.3f}\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
