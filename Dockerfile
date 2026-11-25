FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b AS builder

COPY requirements-runtime.txt /tmp/
RUN python -m venv --without-pip /opt/venv \
    && pip --python /opt/venv/bin/python install --no-cache-dir \
        -r /tmp/requirements-runtime.txt

FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade \
    zlib1g=1:1.3.dfsg+really1.3.1-1+deb13u1 \
    libzstd1=1.5.7+dfsg-1+deb13u1 \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip uninstall -y pip \
    && rm -rf /usr/local/lib/python3.12/ensurepip

RUN groupadd --system --gid 10001 appgroup \
    && useradd --system --uid 10001 --gid 10001 --shell /usr/sbin/nologin \
    --no-create-home appuser

COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app
COPY src/ /app/src
COPY scripts/__init__.py scripts/detect.py /app/scripts/

USER 10001:10001

ENTRYPOINT ["python", "-m", "scripts.detect"]
