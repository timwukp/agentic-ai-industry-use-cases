# Stage 1: Builder
FROM python:3.12-slim AS builder
WORKDIR /build
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY pyproject.toml .
COPY packages/ packages/
RUN pip install --no-cache-dir .

# Stage 2: Runtime
# The package is already installed in /opt/venv/lib site-packages from the builder stage.
# No need to copy raw source again - the installed package is sufficient.
FROM python:3.12-slim AS runtime
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY apps/finance-trading/ apps/finance-trading/
RUN useradd -m -r agent && chown -R agent:agent /app
USER agent
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/ping')"
CMD ["python", "apps/finance-trading/agent/app.py"]
