from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def derive_message_key(root_secret: bytes, group: str, epoch: int) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"msg-key:{group}:{epoch}".encode()
    ).derive(root_secret)

class GroupState:
    def __init__(self, group_name, member, epoch=0):
        self.group_name = group_name
        self.member = member
        self.epoch = epoch

        self.slot_map = {}      # slot_index -> username
        self.user_slots = {}    # username -> slot_index

        self._next_slot = 0

    def assign_slot(self, username):
        slot = self._next_slot

        self._next_slot += 1

        self.slot_map[slot] = username

        self.user_slots[username] = slot

        return slot

    @property
    def message_key(self):
        return derive_message_key(self.member.root, self.group_name, self.epoch)

    def advance_epoch(self):
        self.epoch += 1

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