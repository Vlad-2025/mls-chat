from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


class ClientState:
    def __init__(self):
        self.username: str = ""
        self.current_group: str = ""

        # Crypto

        # generated on startup - never shared
        self.x25519_priv    = X25519PrivateKey.generate()
        self.ed25519_priv   = Ed25519PrivateKey.generate()

        # public keys - safe to share
        self.x25519_pub     = self.x25519_priv.public_key()
        self.ed25519_pub    = self.ed25519_priv.public_key()

        # just for two people
        # group_name -> shared AES key (derived after both members are known
        self.group_keys: dict[str, bytes] = {}

        # username -> their x25519 public key bytes (fetched from server
        self.known_peers: dict[str, bytes] = {}


    def set_username(self, username):
        self.username = username

    def switch_group(self, group_name):
        self.current_group = group_name