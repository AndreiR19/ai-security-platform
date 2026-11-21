FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

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
