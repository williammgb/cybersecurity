from __future__ import annotations
import heapq
from dataclasses import dataclass
# Local imports
from node import Node
from message import Message
#============================ DATATYPE CLASSES ============================    
@dataclass
class Connection:
    node1: Node
    node2: Node
    distance: int = 10
    oneway: bool = False

    def __repr__(self):
        arrow = "-->" if self.oneway else "<-->"
        return f"[{self.node1} {arrow} {self.node2}] (dist={self.distance})"

#============================ NETWORK CLASSES ============================    
class Network:
    def __init__(self, name: str, verbose: bool = True):
        self.name = name
        self.verbose = verbose
        self.age = 0
        self.nodes: dict[str, Node] = {} # {name1: Node(1), name2: Node(2)}
        self.connections: list[Connection] = []
        self.buffers: dict[str, list] = {} # {node1: [], node2: []}; in real life, there is a buffer per interface (==connection port)
        self.routing_table: dict[Node, dict] = {} # {node1: {}, node2: {}}
        self.update_routing = False
        self.id_counter = 1
        if self.verbose:
            print(f"Network({name}) is initialised.")
    
    # Modifying network
    def add_node(self, name: str):
        node_names = [name for name in self.nodes.keys()]
        if name in node_names:
            if self.verbose:
                print(f"Node({name}) already exists.")
            return self.nodes[name]
        else:
            node = Node(name=name, network=self)
            self.nodes[name] = node 
            self.buffers[node] = [] 
            self.routing_table[node] = {}
            self.update_routing = True
            self.id_counter += 1
            if self.verbose:
                print(f"Node({name}) added.")
            return node
    
    def delete_node(self):
        # if node has not made connection after x timesteps, remove
        # later: if node inactive (no new connections, no messages in x timesteps), remove
        pass

    def add_oneway_connection(self, from_node: Node, to_node: Node, distance: int = 10):
        if isinstance(from_node, Node) and isinstance(to_node, Node):
            if to_node not in from_node.neighbors:
                from_node.neighbors[to_node] = {'distance': distance}
                conn = Connection(from_node, to_node, distance, oneway=True)
                self.connections.append(conn)
                self.update_routing = True
                if self.verbose:
                    print(conn)
            else:
                if self.verbose:
                    print(f"[{from_node} --> {to_node}] already exists...)")

    def add_twoway_connection(self, left_node: Node, right_node: Node, distance: int = 10):
        if isinstance(left_node, Node) and isinstance(right_node, Node) and \
            left_node not in right_node.neighbors and \
            right_node not in left_node.neighbors:
            left_node.neighbors[right_node] = {'distance': distance}
            right_node.neighbors[left_node] = {'distance': distance}
            conn = Connection(left_node, right_node, distance, oneway=False)
            self.connections.append(conn)
            self.update_routing = True
            if self.verbose:
                print(conn)
        else:
            if self.verbose:
                print(f"[{left_node} <--> {right_node}] already exists")

    def delete_connection(self, left_node: Node, right_node: Node):
        if isinstance(left_node, Node) and isinstance(right_node, Node) and \
            left_node in right_node.neighbors and \
            right_node in left_node.neighbors:            
            del right_node.neighbors[left_node]
            del left_node.neighbors[right_node]
            self.connections = [
                c for c in self.connections
                if not ((c.node1 == left_node and c.node2 == right_node) or
                        (c.node1 == right_node and c.node2 == left_node))
            ]
            self.update_routing = True
            if self.verbose:
                print(f"[{left_node} <--> {right_node}] removed")

    def build_routing_table(self):
        """
        For each node in the network, compute shortest paths to all destinations
        and store next-hop in routing table.
        """
        for node in self.nodes.values():
            self.routing_table[node] = {}
            for dest in self.nodes.values():
                if node == dest:
                    continue
                if not self._is_connected(node, dest):
                    continue  # unreachable
                _, path = self._shortest_path(node, dest)  # returns [node, next_node, ..., dest]
                next_hop = path[1]  # first step after current node
                self.routing_table[node][dest] = next_hop
    
    # Simulating timesteps
    def tick(self):
        """One timestep in the network."""
        if self.update_routing:
            self.build_routing_table()
            self.update_routing = False
        # 1. Go through all queues to see if there are outgoing messages
        for node, queue in self.buffers.items():
            if queue:
                msg = queue.pop(0) 
                self.forward(msg) # if next node gets inbox, will it send in the same tick?
        self.age += 1
        
    # Sending messages
    def broadcast(self, content: str):
        for node in self.nodes.values():
            msg = Message(origin=node, destination=node, content=content)
            self.submit(msg)

    def submit(self, msg: Message):
        """Place message in origin node's outgoing buffer (outbox)."""
        msg.current = msg.origin # double assignment, remove?
        self.buffers[msg.origin].append(msg)
    
    def forward(self, message: Message):
        current = message.current
        if current == message.destination:
            current.inbox.append(message)
            if self.verbose:
                print(f'[{message.origin} -> {message.destination}] Message delivered...')
            return
        next_node = self.routing_table[current][message.destination]
        if self.verbose:
            print(f"[{current} -> {next_node}] Forwarding message... ")
        self.buffers[next_node].append(message)
        message.current = next_node


    def visualize_network(self):
        pass

    def describe_network(self):
        print('=' * 30)
        print(f"Network name: {self.name}")
        print(f"Node count: {len(self.nodes)}")
        print(f"Connection count: {len(self.connections)}")
        print('=' * 30)
    
    ######################### HELPER FUNCTIONS #########################
    def _is_connected(self, sender: Node, receiver: Node):
        """Checks if there is a connection from sender to receiver (DFS)."""
        visited = set()
        stack = [sender]
        while stack:
            node = stack.pop()
            if node == receiver:
                return True
            if node in visited:
                continue
            visited.add(node)
            for nbor in node.neighbors.keys():
                if nbor not in visited:
                    stack.append(nbor)
        return False
    
    def _shortest_path(self, sender: Node, receiver: Node) -> tuple[int | None, list[Node]]:
        """Returns shorestest path using Dijkstra."""
        # 1. Initialise distances
        distances = {node: float('inf') for node in self.nodes.values()}
        distances[sender] = 0
        previous = {}
        queue = [(0, sender.id, sender)]
        # 2. Find shortest path
        while queue:
            current_dist, _, node = heapq.heappop(queue)
            if node == receiver:
                break # shortest path found
            if current_dist > distances[node]:
                continue # found better path to this node
            for nbor, info in node.neighbors.items():
                weight = info['distance']
                new_dist = current_dist + weight
                if new_dist < distances[nbor]:
                    distances[nbor] = new_dist
                    previous[nbor] = node
                    heapq.heappush(queue, (new_dist, nbor.id, nbor)) # smallest distance comes first in queue
        if distances[receiver] == float('inf'): # receiver not reached
            return None, []
        # 3. Reconstruct path
        path = []
        cur = receiver
        while cur != sender:
            path.append(cur)
            cur = previous[cur]
        path.append(sender)
        path.reverse()
        return distances[receiver], path


if __name__ == "__main__":
    network = Network(name="TestWork")
    a = network.add_node('A')
    b = network.add_node('B')
    c = network.add_node('C')

    network.add_twoway_connection(a, b, 10)
    network.add_twoway_connection(b, c, 10)

    network.tick()

    a.send(destination=c, content="Hello C. This is A.")
    print("\n--- Running network ticks ---")
    for i in range(5):
        print(f"Tick {i}")
        network.tick()

    # --- Check C's inbox ---
    print("\n--- C inbox ---")
    for msg in c.inbox:
        decrypted = c.encryption.decrypt_message(msg.content)
        print("Decrypted content:", decrypted)


