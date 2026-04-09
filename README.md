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
- **NetworkSimulation** - Simulates a growing network of nodes and edges with a surveillance layer that detects malicious nodes via message content analysis and neighbor-based inference. Includes an interactive Dash UI.
