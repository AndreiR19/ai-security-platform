# AI Security Operations Platform

A defensive security operations platform for detecting, analyzing, and triaging cybersecurity incidents. It uses Python and AI models to automate SOC (Security Operations Center) workflows.

## Requirements

- Python 3.12+
- Runtime dependency: pydantic (`requirements-runtime.txt`)
- Development dependencies: pytest, ruff, bandit, pip-audit (`requirements.txt`)

## Getting started

```powershell
# Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Run the tests
pytest -v
```

## Run with Docker

Build the image:

```bash
docker build -t aisoc:dev .
```

Run detection on the sample logs (PowerShell):

```powershell
docker run --rm `
  --read-only `
  --network none `
  --cap-drop ALL `
  --security-opt no-new-privileges `
  --memory 256m --memory-swap 256m `
  --cpus 1 --pids-limit 64 `
  -v "${PWD}/data/samples:/data:ro" `
  aisoc:dev /data/auth.log --year 2026
```

On Linux/macOS, replace the backticks with `\` and `${PWD}` with `$(pwd)`.

The container runs hardened, because log content is untrusted input:

- Runs as a non-root user (UID 10001) with all Linux capabilities dropped and privilege escalation blocked.
- The root filesystem is read-only and the logs are mounted read-only, so code and evidence cannot be modified.
- There is no network, so a compromised process cannot download tools or exfiltrate data.
- Memory, CPU, and process count are capped, so an oversized log or a fork bomb cannot exhaust the host.

Each alert is printed as one JSON line on stdout.

