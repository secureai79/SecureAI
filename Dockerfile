FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends git nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app

COPY backend/requirements.txt backend/requirements.lock /app/backend/

# Install the pinned, audited set (requirements.lock) so every build is reproducible.
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/backend/requirements.lock

COPY backend /app/backend
COPY frontend /app/frontend
COPY demo_repo /app/demo_repo
COPY scripts /app/scripts
COPY README.md VALIDATION_REPORT.md /app/

WORKDIR /app/backend

# Disk-backed scratch space for clones and analysis output (compose mounts a volume here).
RUN mkdir -p /work && chown 10001:10001 /work

RUN npm init -y \
    && npm install --no-audit --no-fund typescript@5.9.3 \
    && chown -R root:root /app \
    && chmod -R a-w /app

# Run as an unprivileged user; the filesystem under /app is read-only for it.
USER app

# Managed hosts (Render, Railway, Fly...) tell the container which port to use through $PORT.
ENV PORT=8000
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD python -c "import os,urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:%s/ready' % os.environ.get('PORT','8000'),timeout=4).status==200 else 1)"

CMD ["sh", "-c", "exec uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
