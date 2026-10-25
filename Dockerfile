# Python lightweight slim base image
FROM python:3.12-slim

# Prevent Python from writing .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ENV=production \
    PORT=8000 \
    HOST=0.0.0.0 \
    DATABASE_PATH=/app/data/phishing_platform.db

WORKDIR /app

# Create unprivileged application user and group for security
RUN groupadd -r appgroup && useradd -r -g appgroup -s /sbin/nologin appuser

# Install production dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY app /app/app
COPY config /app/config
COPY database /app/database
COPY engine /app/engine
COPY services /app/services
COPY frontend /app/frontend

# Prepare persistent data volume directory and assign ownership to appuser
RUN mkdir -p /app/data && chown -R appuser:appgroup /app/data

# Switch to non-root execution
USER appuser

# Expose API & Web interface port
EXPOSE 8000

# Container liveness health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Launch production server
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
