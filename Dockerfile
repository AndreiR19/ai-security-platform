FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade \
    zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1 \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 appgroup \
    && useradd --system --uid 10001 --gid 10001 --shell /usr/sbin/nologin \
    --no-create-home appuser

WORKDIR /app
COPY requirements-runtime.txt .
RUN pip install --no-cache-dir -r requirements-runtime.txt

COPY src/ /app/src
COPY scripts/__init__.py scripts/detect.py /app/scripts/

USER 10001:10001

ENTRYPOINT ["python", "-m", "scripts.detect"]
