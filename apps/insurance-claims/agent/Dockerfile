FROM python:3.12-slim AS base

WORKDIR /app

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

# Copy source
COPY packages/ packages/
COPY apps/insurance-claims/ apps/insurance-claims/

# Non-root user
RUN useradd -m -r agent && chown -R agent:agent /app
USER agent

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/ping')"

CMD ["python", "apps/insurance-claims/agent/app.py"]
