# Stage 1: builder
FROM python:3.12-slim AS builder
WORKDIR /app

# Install pip deps into wheels
COPY python/verifier/requirements.txt verifier-requirements.txt
RUN pip install --upgrade pip && \
    pip wheel --no-cache-dir --wheel-dir /wheels -r verifier-requirements.txt

# Stage 2: runtime
FROM python:3.12-slim
WORKDIR /app

# Install Flask + cryptography from wheels (no pip download needed)
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir --no-index /wheels/*.whl

# Copy app code
COPY python/verifier/ /app/
COPY python/pact/ /app/pact/

# Non-root user for safety
RUN useradd -m -u 1000 verifier && chown -R verifier:verifier /app
USER verifier

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

EXPOSE 8080

ENTRYPOINT ["python3", "verifier_api.py"]
CMD ["--port", "8080", "--host", "0.0.0.0"]