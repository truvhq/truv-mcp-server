# syntax=docker/dockerfile:1
FROM python:3.13-slim

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 - && \
    ln -s /root/.local/bin/poetry /usr/local/bin/poetry

# Copy project files
COPY . .

# Install Python dependencies with Poetry
RUN poetry config virtualenvs.create false && \
    poetry install --no-root --no-interaction --no-ansi

# Expose the default port (8000)
EXPOSE 8000

# The .env file should be mounted or copied at runtime if needed

# Run the server using MCP
CMD ["python", "server.py"]
