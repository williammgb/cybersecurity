# cybersecurity
A collection of projects to develop and demonstrate practical cybersecurity skills.

To download only a specific project:
```bash
git clone --no-checkout https://github.com/williammgb/cybersecurity.git
cd cybersecurity
git sparse-checkout init --cone
git sparse-checkout set <ProjectName>
git checkout
```
Example
```bash
git sparse-checkout set NetworkSimulation
```

## Networking
- **NetworkSimulation (4/2026)** - Simulates a growing network of nodes and edges with a surveillance layer that detects malicious nodes via message content analysis and neighbor-based inference. Includes an interactive Dash UI.
- **SIEM_SOAR (apr 2026)** - SIEM/SOAR simulation that generates normal and attack traffic, detects threats using rule-based and ML models, and automatically enforces blocking. Deployed in a multi-container Docker environment with a real-time React event dashboard.
- **PacketSniffer (apr 2026)** - Simple Dockerized Flask application demonstrating the difference between unencrypted (HTTP) and encrypted (HTTPS) network communication by sending messages between services. A packet sniffer built with Scapy captures traffic in real time, showing that HTTP exposes message contents while HTTPS keeps them protected.
