import time


class Peer:
    def __init__(self, peer_name, ip_address, ed25519_public_key, x25519_public_key_bytes, port=None):
        self.peer_name = peer_name
        self.ip_address = ip_address
        self.ed25519_public_key = ed25519_public_key
        self.x25519_public_key_bytes = x25519_public_key_bytes
        self.port = port
        self.last_seen = time.time()
        self.unread_messages = 0

    def __hash__(self):
        return hash(self.ip_address)

    def __eq__(self, other):
        return isinstance(other, Peer) and self.ip_address == other.ip_address

    def __str__(self):
        return f"{self.peer_name}@{self.ip_address}"
