FROM python:3.11-slim

LABEL maintainer="SurankuTech <dev@suranku.tech>"
LABEL description="SurankuTech Tenants Service - Multi-tenant management microservice for EKS"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app
ENV PORT=8000

# Install system dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        libmagic1 \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install kubectl for provisioning worker
RUN curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/arm64/kubectl" \
    && chmod +x kubectl \
    && mv kubectl /usr/local/bin/

# Create app user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set work directory
WORKDIR /app

# Copy requirements first (for better Docker layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Make database startup script executable
RUN chmod +x db-startup.sh

# Create necessary directories and set permissions
RUN mkdir -p /app/logs /app/tmp \
    && chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Health check endpoint for EKS readiness/liveness probes
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Expose port (configurable via environment)
EXPOSE ${PORT}

# Graceful shutdown signal handling for EKS
STOPSIGNAL SIGTERM

# Run the application with database initialization and production settings
CMD ["./db-startup.sh"]