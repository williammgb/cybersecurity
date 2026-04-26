FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create self-signed certificate for HTTPS endpoint (only for demo: lets you use HTTPS without buying a real certificate)
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /app/certs \
    && openssl req -x509 -nodes -days 365 \
       -newkey rsa:2048 \
       -keyout /app/certs/server.key \
       -out /app/certs/server.crt \
       -subj "/CN=receiver"

COPY . .

EXPOSE 8080 8443

CMD ["python", "app.py"]
