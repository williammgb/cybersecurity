FROM python:3.11-slim AS builder
WORKDIR /app
# Install build dependencies (needed for some ML libraries)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*
# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# 1. Create the user
# 2. Create the logs directory explicitly
# 3. Give the user ownership of the /app directory (-R for recursive: also subfolders) (user:group)
RUN useradd -m cyberuser && \
    mkdir -p /app/logs && \
    chown -R cyberuser:cyberuser /app

# Switch to the user
USER cyberuser

EXPOSE 8000

CMD ["python", "detector.py"]