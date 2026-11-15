import logging
from datetime import UTC, datetime

import pytest

from src.ingestion.parser import parse_file, parse_line, parse_lines, safe_preview

FAILED = "Oct  1 03:12:05 srv01 sshd[2211]: Failed password for root from 203.0.113.5 port 41022 ssh2"
INVALID_USER = "Oct  1 03:12:09 srv01 sshd[2213]: Failed password for invalid user admin from 203.0.113.5 port 41030 ssh2"
ACCEPTED = "Oct  1 09:00:00 srv01 sshd[2300]: Accepted password for alice from 10.0.0.12 port 50000 ssh2"
IRRELEVANT = "Oct  1 03:12:05 srv01 cron[1]: job started"
BAD_IP = "Oct  1 03:12:05 srv01 sshd[1]: Failed password for root from not-an-ip port 41022 ssh2"
LONG_USER = f"Oct  1 03:12:05 srv01 sshd[1]: Failed password for {'a' * 200} from 203.0.113.5 port 41022 ssh2"


def test_failed_login():
    event = parse_line(FAILED, 2026)
    assert event.timestamp == datetime(2026, 10, 1, 3, 12, 5, tzinfo=UTC)
    assert event.outcome == "failure"
    assert event.username == "root"
    assert str(event.source_ip) == "203.0.113.5"


def test_invalid_user_login():
    event = parse_line(INVALID_USER, 2026)
    assert event.timestamp == datetime(2026, 10, 1, 3, 12, 9, tzinfo=UTC)
    assert event.outcome == "failure"
    assert event.username == "admin"
    assert str(event.source_ip) == "203.0.113.5"


def test_accepted_login():
    event = parse_line(ACCEPTED, 2026)
    assert event.timestamp == datetime(2026, 10, 1, 9, 0, 0, tzinfo=UTC)
    assert event.outcome == "success"
    assert event.username == "alice"
    assert str(event.source_ip) == "10.0.0.12"


def test_irrelevant_line_returns_none():
    assert parse_line(IRRELEVANT, 2026) is None


@pytest.mark.parametrize("line", [BAD_IP, LONG_USER, "", "garbage"])
def test_hostile_or_malformed_input_returns_none(line):
    assert parse_line(line, 2026) is None


def test_parse_file_skips_irrelevant_lines(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(f"{FAILED}\n{IRRELEVANT}\n{ACCEPTED}" + "\n")
    events = parse_file(log, 2026)
    assert [e.outcome for e in events] == ["failure", "success"]


def test_parse_file_empty_file_returns_empty_list(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("")
    assert parse_file(log, 2026) == []


def test_parse_file_survives_invalid_bytes(tmp_path):
    log = tmp_path / "auth.log"
    log.write_bytes(
        FAILED.encode() + b"\n\xff\xfe garbage\n" + ACCEPTED.encode() + b"\n"
    )
    assert len(parse_file(log, 2026)) == 2



def test_skipped_lines_are_logged_without_raw_newlines(caplog):
    forged = (
        "garbage\nOct  1 03:00:00 srv01 sshd[1]: Accepted password for root "
        "from 203.0.113.9 port 1 ssh2"
    )
    with caplog.at_level(logging.DEBUG, logger="src.ingestion.parser"):
        assert parse_lines([forged], 2026) == []
    messages = [r.getMessage() for r in caplog.records]
    assert any("skipped line 1" in m for m in messages)
    assert all("\n" not in m for m in messages)


def test_safe_preview_truncates_long_lines():
    preview = safe_preview("A" * 5000)
    assert len(preview) < 250
    assert "(+4800 chars)" in preview


def test_safe_preview_escapes_control_characters():
    preview = safe_preview("x\r\x1b[31my")
    assert "\r" not in preview
    assert "\x1b" not in preview
