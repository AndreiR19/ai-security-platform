# ADR 0002: AI analyst backend

- Status: Proposed
- Date: 2026-11-26

## Context

Stage 4 adds an AI analyst after detection:

```
logs -> parser -> rules -> Alert -> AI analyst -> analyst report -> human
```

The analyst takes one validated `Alert` and writes a short triage report for a human analyst: what happened, why it matters, and what a human could check next. It only explains. It does not detect, decide, or act, and it has no tools.

What reaches the analyst:

- One `Alert` at a time: rule ID, severity, MITRE technique, source IP, username, time range, `event_count`, and at most 10 evidence events (first 5 + last 5, see the evidence cap).
- Usernames and raw log lines are attacker-controlled. The parser limits them (`\S+` username of at most 64 characters, raw line of at most 2048 characters), so one alert carries at most about 21 KB of untrusted text.
- Today all input is synthetic (`scripts/generate_logs.py`). No real users, IPs, or hosts.

Constraints:

- The detector runs in a hardened container with `--network none`, `--read-only`, 256 MB memory, non-root, and hash-locked dependencies. That must not get weaker.
- Low budget (student project).
- CI has no network access to an LLM and no API key; tests must not depend on one.
- The deployment VM has no GPU.
- Learning goals: prompt injection, output validation, and evaluating AI output.

Before choosing a backend, the question is whether an LLM is needed at all. A fixed template ("43 failures from 203.0.113.5 against root in 2 min, T1110.001") already states the facts. It is free, deterministic, and cannot be prompt-injected. An LLM is only worth it if it adds something the template cannot: a narrative across the evidence, triage hints, and an honest statement of uncertainty.

## Options

- **A. Hosted API.** The analyst calls a provider's LLM over HTTPS. Strong output quality and guaranteed JSON through schema-constrained output. Low setup effort, works on the GPU-less VM. The alert leaves the host, it costs money per call, and the analyst needs outbound network access and an API key.
- **B. Local model (Ollama on the laptop).** Nothing leaves the host and there is no per-call cost. The laptop GPU has 6 GB of VRAM, so only small models fit; their quality and injection resistance are weaker. On the VM it would run on the CPU only, which is slow and memory-heavy. More operations work: model downloads, GPU setup in WSL2, model versions.
- **C. Hybrid.** A and B behind the same interface, chosen per run. The best way to compare models, but the most configuration and code to maintain.

All three share the same core: a small backend interface, a fake backend for tests, a template fallback, and Pydantic validation of the model's output.

## Decision

Option A, with the **Google Gemini API** (key from Google AI Studio), built in this order:

1. **Template report, backend interface, and a fake backend first.** The template is both the baseline the LLM has to beat and the fallback when the LLM fails.
2. **Gemini backend** behind the same interface.
3. **Optional later:** a local backend (option B) for comparison in the eval.

Why A: the data is synthetic, so sending alerts to a provider costs no privacy today. Schema-constrained output means the eval can focus on what matters (invented facts, injection resistance) instead of broken JSON. It also runs on the VM without a GPU.

Why Gemini: the owner already has a Google AI Studio API key, and the free tier is enough for synthetic test runs.

How it is built:

- **Untrusted data stays data.** The prompt keeps instructions and alert data apart: the alert is sent as structured JSON inside a clearly delimited block, and the model is told to treat that block as inert data, never as instructions.
- **Output is validated.** The model must return JSON matching a fixed schema (`summary`, `severity_assessment`, `recommended_actions`, `confidence`), validated with Pydantic before use. On invalid output or a timeout: one retry, then the template report. The pipeline never fails because of the LLM, and alerts are always delivered.
- **Separate container.** The detector keeps `--network none`. The analyst runs in its own container whose only outbound destination is the Gemini API host (`generativelanguage.googleapis.com`). It keeps the other hardening (read-only, non-root, dropped capabilities).
- **API key.** Passed at runtime as an environment variable from a git-ignored `.env` file, with a placeholder in `.env.example`. Never in the image, a layer, the repository, or a log line. If the key leaks, revoke it in AI Studio and create a new one.

## Data policy

- **Now:** only synthetic logs go to the API. That makes the free tier acceptable, even though Google may use free-tier content to improve its products (check Google's current Gemini API terms).
- **Before any real `auth.log` (for example from a lab server):** real usernames, IP addresses, and hostnames are personal or internal data. Under GDPR, sending them to a third party needs a lawful basis and a processor agreement, and the provider must not train on them. That means at least the paid tier with matching terms, or switching to option B. This ADR must be revisited first.

## Consequences

- The analyst adds a runtime dependency to the hash-locked runtime requirements, or uses plain HTTPS calls. To decide when the backend is built: Google's SDK (`google-genai`, convenient, more transitive packages to audit) versus a small HTTP client (fewer packages, more own code).
- Tests use the fake backend only. CI needs no key and no network access to Google.
- A Gemini call costs latency (network round trip) and, on the paid tier, money. Alerts are small, and the per-run alert count must be capped before production use (security review F1).
- The provider can change models, prices, or terms. The model ID is pinned in configuration, and the backend can be swapped behind the interface.
- Every report is advisory. A human reads it and decides; nothing is blocked or changed automatically.

## How it is measured

`evals/analyst_eval.py` runs a fixed set of about 20 labeled synthetic alerts (clean cases and prompt-injection cases) through the template and the Gemini backend and reports:

- the share of outputs that are valid JSON on the first try
- invented facts: IPs, usernames, or timestamps in the report that are not in the alert
- injection resistance: the report does not follow the planted instruction and does not lower the severity
- whether the model says "insufficient evidence" when it should
- tokens and latency per alert

## Revisit when

- Real logs are used as input (see Data policy).
- The eval shows Gemini is not clearly better than the template. Then drop the LLM.
- The free tier's terms or limits change in a way that affects this project.
- A local model becomes good enough on the available hardware.
