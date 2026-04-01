from __future__ import annotations

import random
import string
from collections import deque
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

try:
    import lorem
except ImportError:
    lorem = None  

from network import Network
from node import Node

if TYPE_CHECKING:
    pass


def _random_name(length: int = 6) -> str:
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))


@dataclass
class MessageLogEntry:
    tick: int
    origin_name: str
    destination_name: str
    content_preview: str
    suspicious: bool
    matched_triggers: tuple[str, ...]


@dataclass
class NodeTrackingState:
    """Stats per node."""
    name: str
    suspicious_sent: int = 0
    total_sent: int = 0
    is_flagged_criminal: bool = False
    recent_suspicious_snippets: deque = field(default_factory=lambda: deque(maxlen=12))

    def record_send(self, suspicious: bool, preview: str) -> None:
        self.total_sent += 1
        if suspicious:
            self.suspicious_sent += 1
            self.recent_suspicious_snippets.append(preview[:200])


@dataclass
class SimulationConfig:
    initial_nodes: int = 12
    initial_edges: int = 16
    suspicious_threshold: int = 3
    prob_add_node: float = 0.20
    prob_add_edge: float = 0.35
    prob_send_message: float = 0.4
    malicious_node_fraction: float = 0.25
    malicious_send_suspicious_prob: float = 0.35
    prob_new_node_is_malicious: float = 0.15
    max_edge_distance: int = 25
    message_log_max: int = 500
    trigger_words: tuple[str, ...] = (
        "dead drop",
        "burner",
        "wire transfer",
        "payload",
        "no witnesses",
        "clean the account",
    )


@dataclass
class NeighborIntel:
    """Analysis of a node's neighbors."""
    node_name: str
    is_criminal: bool
    suspicious_count: int
    total_messages_sent: int
    closest_friends: list[tuple[str, int]]  # (neighbor_name, edge_distance)
    neighbors_flagged: list[str]
    neighbors_with_suspicious_activity: list[tuple[str, int]]  # name, suspicious_sent


class CyberNetworkSimulation:
    """Runs the network simulation."""

    def __init__(self, network_name: str = "CyberSim", config: SimulationConfig | None = None):
        self.config = config or SimulationConfig()
        self.network = Network(network_name, verbose=False)
        self.tick_index = 0
        self._nodes: list[Node] = []
        self._malicious: set[str] = set()
        self._tracking: dict[str, NodeTrackingState] = {}
        self.message_log: deque[MessageLogEntry] = deque(maxlen=self.config.message_log_max)

        self._seed()

    def _ensure_tracking(self, node: Node) -> NodeTrackingState:
        if node.name not in self._tracking:
            self._tracking[node.name] = NodeTrackingState(name=node.name)
        return self._tracking[node.name]

    def _seed(self) -> None:
        """Initializes a random network with initial nodes and edges."""
        cfg = self.config
        for _ in range(cfg.initial_nodes):
            name = _random_name()
            while name in self.network.nodes:
                name = _random_name()
            self._nodes.append(self.network.add_node(name))

        # Random edges between distinct nodes
        attempts = 0
        added = 0
        while added < cfg.initial_edges and attempts < cfg.initial_edges * 20:
            attempts += 1
            if len(self._nodes) < 2:
                break
            a, b = random.sample(self._nodes, 2)
            if b in a.neighbors:
                continue
            d = random.randint(1, cfg.max_edge_distance)
            self.network.add_twoway_connection(a, b, d)
            added += 1

        k = max(1, int(len(self._nodes) * cfg.malicious_node_fraction))
        sample = random.sample([n.name for n in self._nodes], k=min(k, len(self._nodes)))
        self._malicious = set(sample)

    def _random_plaintext(self, sender: Node) -> str:
        if lorem is None:
            base = "Routine ping from node. Status nominal. Sequence "
            return base + str(random.randint(1000, 9999))
        if sender.name in self._malicious and random.random() < self.config.malicious_send_suspicious_prob:
            trigger = random.choice(self.config.trigger_words)
            return f"Confirm {trigger} tonight. {lorem.sentence()}"
        return lorem.sentence()

    def _is_suspicious(self, text: str) -> tuple[bool, tuple[str, ...]]:
        lower = text.lower()
        matched = [w for w in self.config.trigger_words if w.lower() in lower]
        return (len(matched) > 0, tuple(matched))

    def send_tracked(self, origin: Node, destination: Node, plaintext: str | None = None) -> None:
        """Send a message and update surveillance stats before encryption."""
        if plaintext is None:
            plaintext = self._random_plaintext(origin)
        suspicious, triggers = self._is_suspicious(plaintext)
        st = self._ensure_tracking(origin)
        st.record_send(suspicious, plaintext)
        if suspicious and st.suspicious_sent >= self.config.suspicious_threshold and not st.is_flagged_criminal:
            st.is_flagged_criminal = True

        preview = plaintext if len(plaintext) <= 120 else plaintext[:117] + "..."
        self.message_log.append(
            MessageLogEntry(
                tick=self.tick_index,
                origin_name=origin.name,
                destination_name=destination.name,
                content_preview=preview,
                suspicious=suspicious,
                matched_triggers=triggers,
            )
        )
        origin.send(destination, plaintext)

    def _try_add_node(self) -> None:
        name = _random_name()
        while name in self.network.nodes:
            name = _random_name()
        self._nodes.append(self.network.add_node(name))
        if random.random() < self.config.prob_new_node_is_malicious:
            self._malicious.add(name)

    def _try_add_edge(self) -> None:
        if len(self._nodes) < 2:
            return
        a, b = random.sample(self._nodes, 2)
        if b in a.neighbors:
            return
        d = random.randint(1, self.config.max_edge_distance)
        self.network.add_twoway_connection(a, b, d)

    def _try_random_message(self) -> None:
        conns = self.network.connections
        if not conns:
            return
        conn = random.choice(conns)
        forward = random.random() < 0.5
        origin, dest = (conn.node1, conn.node2) if forward else (conn.node2, conn.node1)
        if not self.network._is_connected(origin, dest):
            return
        self.send_tracked(origin, dest, None)

    def step(self) -> None:
        """One simulation step: network growth + message + network tick."""
        cfg = self.config
        if random.random() < cfg.prob_add_node:
            self._try_add_node()
        if random.random() < cfg.prob_add_edge:
            self._try_add_edge()
        if random.random() < cfg.prob_send_message:
            self._try_random_message()
        self.network.tick()
        self.tick_index += 1

    def run(self, steps: int) -> None:
        for _ in range(steps):
            self.step()

    def get_node(self, name: str) -> Node | None:
        return self.network.nodes.get(name)

    def neighbor_intel(self, node_name: str) -> NeighborIntel | None:
        node = self.network.nodes.get(node_name)
        if node is None:
            return None
        st = self._ensure_tracking(node)

        friends: list[tuple[str, int]] = []
        for nbor, info in node.neighbors.items():
            friends.append((nbor.name, int(info["distance"])))
        friends.sort(key=lambda x: x[1])

        flagged: list[str] = []
        suspicious_neighbors: list[tuple[str, int]] = []
        for nbor in node.neighbors:
            nt = self._tracking.get(nbor.name)
            if nt:
                if nt.is_flagged_criminal:
                    flagged.append(nbor.name)
                if nt.suspicious_sent > 0:
                    suspicious_neighbors.append((nbor.name, nt.suspicious_sent))
        suspicious_neighbors.sort(key=lambda x: -x[1])

        return NeighborIntel(
            node_name=node_name,
            is_criminal=st.is_flagged_criminal,
            suspicious_count=st.suspicious_sent,
            total_messages_sent=st.total_sent,
            closest_friends=friends[:8],
            neighbors_flagged=sorted(flagged),
            neighbors_with_suspicious_activity=suspicious_neighbors[:12],
        )

    def flagged_criminal_names(self) -> list[str]:
        return sorted(n for n, t in self._tracking.items() if t.is_flagged_criminal)

    def is_flagged_criminal(self, node_name: str) -> bool:
        st = self._tracking.get(node_name)
        return bool(st and st.is_flagged_criminal)

    def recent_messages(self, n: int = 80) -> list[MessageLogEntry]:
        return list(self.message_log)[-n:]

    def edges_for_graph(self) -> list[tuple[str, str, int]]:
        """Endpoints and distance for drawing edges (undirected)."""
        out: list[tuple[str, str, int]] = []
        seen: set[tuple[str, str]] = set()
        for c in self.network.connections:
            if c.oneway:
                out.append((c.node1.name, c.node2.name, c.distance))
            else:
                a, b = c.node1.name, c.node2.name
                key = (a, b) if a < b else (b, a)
                if key in seen:
                    continue
                seen.add(key)
                out.append((a, b, c.distance))
        return out

    def summary(self) -> str:
        lines = [
            f"tick={self.tick_index} nodes={len(self.network.nodes)} "
            f"edges={len(self.network.connections)}",
            f"flagged criminals ({len(self.flagged_criminal_names())}): {self.flagged_criminal_names()}",
        ]
        return "\n".join(lines)
