FROM python:3.12-slim

WORKDIR /app

# Install libpcap and tcpdump for packet capture.
COPY requirements.txt .
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 tcpdump \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5001

CMD ["python", "app.py"]
