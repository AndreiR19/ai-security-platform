# AI Security Operations Platform

A defensive security operations platform for detecting, analyzing, and triaging cybersecurity incidents. It uses Python and AI models to automate SOC (Security Operations Center) workflows.

## Requirements

- Python 3.12+
- Runtime dependency: pydantic (`requirements-runtime.in`, locked with hashes in `requirements-runtime.txt`)
- Development dependencies: pytest, ruff, bandit, pip-audit (`requirements.txt`)

### Updating the runtime lock file

`requirements-runtime.txt` is generated; do not edit it by hand. Change `requirements-runtime.in`, then regenerate the lock inside the same base image the Docker build uses (Linux, Python 3.12):

```powershell
$out = "$env:TEMP\aisop-lock"
New-Item -ItemType Directory -Force $out | Out-Null
docker run --rm --user 10001:10001 -e HOME=/tmp `
  -v "${out}:/out" `
  -v "${PWD}/requirements-runtime.in:/out/requirements-runtime.in:ro" `
  -w /out `
  python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b `
  sh -c "pip install --quiet --no-cache-dir --no-warn-script-location --user pip-tools==7.7.0 && python -m piptools compile --quiet --generate-hashes --strip-extras --no-emit-index-url -o requirements-runtime.txt requirements-runtime.in"
Copy-Item "$out\requirements-runtime.txt" requirements-runtime.txt
git diff requirements-runtime.txt
```

The container runs as a non-root user and only sees the `.in` file (read-only) and an empty output folder, never the repository or `.git/`. Review the diff before committing.

The Docker build installs it with `--require-hashes --only-binary=:all: --no-deps`, so any package whose hash does not match the lock fails the build.

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

