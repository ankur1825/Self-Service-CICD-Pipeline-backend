# syntax=docker/dockerfile:1.7
FROM python:3.11-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY requirements.txt .
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install -r requirements.txt

FROM python:3.11-slim

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_PATH=/app/data/app.db

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv
COPY main.py database.py models.py schemas.py ./
COPY alembic.ini ./
COPY alembic ./alembic
COPY enterprise ./enterprise
COPY cloud_migration ./cloud_migration
RUN useradd --create-home --uid 10001 appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/live', timeout=3).read()"]

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
