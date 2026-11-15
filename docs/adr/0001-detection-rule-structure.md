# ADR 0001: Detection rule structure

- Status: Accepted
- Date: 2026-11-16

## Context

Stage 1 has three rule-based detections over sshd authentication events:

| Rule | Grouping key | Events used | Fires when | Severity | MITRE |
|---|---|---|---|---|---|
| `brute_force` | (source IP, username) | failures | >= 5 failures in 60 s | high | T1110.001 |
| `password_spraying` | source IP | failures | >= 5 distinct usernames in 600 s | medium | T1110.003 |
| `success_after_failures` | (source IP, username) | failures and successes | a success preceded by >= 5 failures in 300 s | critical | T1078 |

The first two rules were written as fully separate code. Before adding the third rule we had to decide how much code rules share.

## Options

- **A. Separate code per rule.** Each rule groups, sorts, scans and builds alerts by itself. Simple to read, but the grouping and alert-building code is copied into every rule, and copies drift apart.
- **B. One shared sliding-window helper (`find_bursts`).** Maximum reuse, but the rules count different things (events, distinct users, failures before a success), so the helper needs callbacks or flags and becomes hard to follow.
- **C. Shared building blocks, separate scan loops.** Shared `_group` (filter, group by key, sort), `_make_alert` (driven by a `RuleSpec`: rule ID, severity, MITRE technique) and `_validate`. Each rule keeps its own scan loop, which holds the detection logic itself.

## Decision

Option C. The parts that are the same in every rule (grouping, sorting, alert metadata, parameter checks) live in one place. The part that makes each rule different, which an analyst needs to read and reason about, stays explicit in its own scan loop.

All rules share one signature, `(events) -> list[Alert]`, and are listed in `ALL_RULES`. The engine (`run_rules`) copies the input into a tuple once and passes the same tuple to every rule, so a one-shot generator cannot be used up by the first rule.

Rule 3 design choices:
- A success resets the failure count. The next attempt series has to build up again.
- The success is part of the evidence. It is the event that turns "attack attempt" into "likely compromised account".
- Severity is critical because valid credentials were probably obtained.
- MITRE T1078 (Valid Accounts) is the outcome being detected; the failures before it are T1110.
- Threshold 5 sits inside the safe range for the synthetic data: at least 2 (normal users mistype once), at most 8 (the generator's compromise scenario has 8-12 failures).

## Consequences

- A new rule only needs a `RuleSpec`, a grouping key and a scan loop, plus adding it to `ALL_RULES`.
- Severity and MITRE IDs are defined once per rule and cannot drift between alert-building sites.
- Scan loops are still similar in shape; that duplication is accepted on purpose, for readability.
- `Alert.mitre_technique` holds one technique. Rule 3 reports T1078 only.

## Revisit when

- A rule needs state that does not fit "group, sort, scan" (for example correlation across different log sources).
- Events arrive as a live stream instead of a file, so rules must work incrementally.
- Alerts need several MITRE techniques, or evidence must be capped in size (planned for Stage 4).
