import argparse
import json
import logging
import sys
from collections.abc import Sequence
from pathlib import Path

from src.detection.engine import run_rules
from src.detection.models import Alert
from src.ingestion.parser import parse_file


def alert_summary(alert: Alert) -> dict[str, object]:
    return alert.model_dump(mode="json", exclude={"evidence"})


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run detection rules on an sshd auth log.")
    parser.add_argument("log", type=Path)
    parser.add_argument("--year", type=int, required=True)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if not args.log.is_file():
        parser.error(f"not a file: {args.log}")

    try:
        events = parse_file(args.log, args.year)
    except OSError as error:
        parser.error(f"cannot read {args.log}: {error.strerror}")
    alerts = run_rules(events)
    for alert in alerts:
        sys.stdout.write(json.dumps(alert_summary(alert)) + "\n")
    logging.getLogger(__name__).info("%d alerts", len(alerts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
