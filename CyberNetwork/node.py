from __future__ import annotations # for annotating parameter same type as class it belongs to. Delays type evaluation
from typing import TYPE_CHECKING
from datetime import datetime
# local imports
from message import Message
from encryption import Encryption
if TYPE_CHECKING:
    from network import Network # ensures i can annotate with Network, but no circular imports


class Neighbours(dict):
    def __contains__(self, node):
        if hasattr(node, "name"):
            for k in self.keys():
                if k is node or getattr(k, "name", None) == node.name:
                    return True
            return False
        return super().__contains__(node)
    
class Node:
    def __init__(self, name: str, network: Network):
        self.created_at = datetime.now().strftime("%H:%M:%S")
        self.network = network
        self.name = name
        self.id = network.id_counter
        self.score = 10
        self.encryption = Encryption()
        self.neighbors = Neighbours()
        self.inbox = []
    
    def neighbor_count(self):
        return len(self.neighbors)

    def send(self, destination: Node, content: str):
        if isinstance(destination, Node) and self.network._is_connected(self, destination):
            enc_content = Encryption.encrypt_message(destination.encryption, content)
            msg = Message(origin=self, destination=destination, content=enc_content)
            self.network.submit(msg)
        else:
            print("Not connected")

    def read_inbox(self):
        pass
    
    def filter_msg(self):
        pass # if not from any in trusted, do not open

    def __repr__(self):
        """Shows name when node is printed."""
        return f"Node({self.name})"

    def __hash__(self):
        """Makes Node object hashable and usable as keys in dicts."""
        return hash(self.name)

    def __eq__(self, other):
        return isinstance(other, Node) and self.name == other.name
    

