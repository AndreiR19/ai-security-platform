from asyncio import events
import random
from datetime import datetime, timedelta, timezone

HOST = "srv01"
USERS = ["alice", "bob", "carol", "dave", "erin"]

def format_line(ts, outcome, username, ip, rng):
    verb = "Accepted" if outcome == "success" else "Failed"
    known = username in USERS or username == "root"
    invalid = "invalid user " if outcome == "failure" and not known else ""
    stamp = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"
    pid = rng.randint(1000, 60000)
    port = rng.randint(30000, 65000)
    return (f"{stamp} {HOST} sshd[{pid}]: {verb} password for "
            f"{invalid}{username} from {ip} port {port} ssh2")

def brute_force(rng, start, ip):
    events = []
    t = start
    for _ in range(rng.randint(30, 60)):
        t += timedelta(seconds = rng.randint(2, 4))
        events.append((t, format_line(t, "failure", "root", ip, rng)))
    label = {
        "scenario": "brute_force",
        "source_ip": ip,
        "start": events[0][0].isoformat(),
        "end": events[-1][0].isoformat(),
    }
    return events, label
