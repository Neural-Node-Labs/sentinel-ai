# ============================================================================
# FILE: Dockerfile
# ============================================================================


# Multi-stage Docker build for Sentinel-AI
FROM python:3.12-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Production stage
FROM python:3.12-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 sentinel && \
    echo "sentinel ALL=(ALL) NOPASSWD: /usr/sbin/iptables" >> /etc/sudoers

WORKDIR /app

# Copy Python packages from builder
COPY --from=builder /root/.local /home/sentinel/.local

# Copy application code
COPY --chown=sentinel:sentinel . .

# Set Python path
ENV PATH=/home/sentinel/.local/bin:$PATH
ENV PYTHONPATH=/app

# Switch to non-root user
USER sentinel

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default command
CMD ["python", "main.py"]
