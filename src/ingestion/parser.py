import re
from collections.abc import Iterable
from datetime import UTC, datetime

from pydantic import ValidationError

from src.ingestion.models import AuthEvent

_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"\S+ "
    r"sshd\[\d+\]: "
    r"(?P<kind>Failed|Accepted) password for "
    r"(?:invalid user )?"
    r"(?P<user>\S+) "
    r"from (?P<ip>\S+) "
    r"port \d+ ssh2$"
)

_OUTCOMES = {"Failed": "failure", "Accepted": "success"}

def parse_line(line: str, year: int) -> AuthEvent | None:
    line = line.rstrip("\n") # elimina linia de la final ca sa ajute regex ul
    match = _PATTERN.match(line)
    if match is None:
        return None
    try:
        ts_text = " ".join(match["ts"].split())
        timestamp = datetime.strptime(f"{year} {ts_text}", "%Y %b %d %H:%M:%S")
        timestamp = timestamp.replace(tzinfo=UTC)
        return AuthEvent(
            timestamp = timestamp,
            source_ip = match["ip"],
            username = match["user"],
            outcome=_OUTCOMES[match["kind"]],
            raw = line,
        )
    except (ValueError, ValidationError):
        return None

def parse_lines(lines: Iterable[str], year: int) -> list[AuthEvent]:
    events = []
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            events.append(event)
    return events

def parse_file(path: str, year: int) -> list[AuthEvent]:
    with open(path, encoding = "UTF-8", errors = "replace") as f:
        return parse_lines(f, year) 