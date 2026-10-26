# from asyncio import events
from datetime import timedelta

HOST = "srv01"
USERS = ["alice", "bob", "carol", "dave", "erin"]
GUESSED = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "git", "deploy",
           "guest", "user", "support", "pi", "ftp", "mysql", "nagios"]

def format_line(ts, outcome, username, ip, rng):
    verb = "Accepted" if outcome == "success" else "Failed"
    known = username in USERS or username == "root"
    invalid = "invalid user " if outcome == "failure" and not known else ""
    stamp = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"
    pid = rng.randint(1000, 60000)
    port = rng.randint(30000, 65000)
    return (
        f"{stamp} {HOST} sshd[{pid}]: {verb} password for "
        f"{invalid}{username} from {ip} port {port} ssh2"
    )


def brute_force(rng, start, ip):
    events = []
    t = start
    for _ in range(rng.randint(30, 60)):
        t += timedelta(seconds=rng.randint(2, 4))
        events.append((t, format_line(t, "failure", "root", ip, rng)))
    label = {
        "scenario": "brute_force",
        "source_ip": ip,
        "start": events[0][0].isoformat(),
        "end": events[-1][0].isoformat(),
    }
    return events, label

def password_spraying(rng, start, ip):
    events = []
    t = start
    for username in rng.sample(GUESSED, 12):
        for _ in range(2):
            t += timedelta(seconds=rng.randint(20, 40))
            events.append((t, format_line(t, "failure", username, ip, rng)))
    label = {
        "scenario": "password_spraying",
        "source_ip": ip,
        "start": events[0][0].isoformat(),
        "end": events[-1][0].isoformat() 
    }
    return events, label

def compromise(rng, start, ip):
    events = []
    t = start
    for _ in range(rng.randint(8, 12)):
        t += timedelta(seconds=rng.randint(2, 5))
        events.append((t, format_line(t, "failure", "alice", ip, rng)))
    t += timedelta(seconds=3)
    events.append((t, format_line(t, "success", "alice", ip, rng)))
    label = {
        "scenario": "compromise_after_bruteforce",
        "source_ip": ip,
        "start": events[0][0].isoformat(),
        "end": events[-1][0].isoformat() 
    }
    return events, label