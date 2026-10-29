import argparse
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

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

def normal_traffic(rng, start, hours):
    events = []
    for user in USERS:
        ip = f"10.0.0.{rng.randint(10, 250)}"
        for _ in range(rng.randint(3, 8)):
            t = start + timedelta(seconds=rng.randint(0, hours *3600))
            if rng.random() < 0.15:
                events.append((t, format_line(t, "failure", user, ip, rng)))
                t += timedelta(seconds=rng.randint(3, 20))
            events.append((t, format_line(t, "success", user, ip, rng)))
    return events

def build_dataset(seed):
    rng = random.Random(seed)
    start = datetime(2026, 10, 1, 0, 0, 0, tzinfo=UTC)
    events = normal_traffic(rng, start, 24)
    labels = []
    scenarios = [
        (brute_force, "203.0.113.5", 3),
        (password_spraying, "198.51.100.23", 9),
        (compromise, "203.0.113.77", 15),
    ]
    for scenario, ip, hour in scenarios:
        offset = timedelta(hours=hour, minutes=rng.randint(0, 40))
        attack_events, label = scenario(rng, start + offset, ip)
        events += attack_events
        labels.append(label)
    events.sort(key=lambda e: e[0])
    return [line for _, line in events], labels

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", default="data/samples")
    args = parser.parse_args(argv)

    lines, labels = build_dataset(args.seed)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "auth.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (out / "labels.json").write_text(json.dumps(labels, indent=2), encoding="utf-8")
    print(f"{len(lines)} lines, {len(labels)} labeled attacks -> {out}")


if __name__ == "__main__":
    main()