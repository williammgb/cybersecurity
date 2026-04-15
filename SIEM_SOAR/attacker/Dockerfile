FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Non-root user for security
RUN useradd -m scriptuser
USER scriptuser

# These containers run scripts, not servers
CMD ["python", "attacker.py"]