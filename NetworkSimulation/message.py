class Message:
    def __init__(self, origin, destination, content: str):
        self.origin = origin
        self.destination = destination
        self.current = origin
        self.content = content

    def __repr__(self):
        return f"Message([{self.origin}] -> [{self.destination}]: {self.content}"
        
        