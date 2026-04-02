from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from treekem import Member, generate_keypair, pub_bytes, pub_from_bytes

MAX_GROUP_SIZE = 16

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
        self._freed_slots = []

    def assign_slot(self, username):
        if self._freed_slots:
            slot = self._freed_slots.pop(0)
        else:
            slot = self._next_slot
            self._next_slot += 1

        self.slot_map[slot] = username
        self.user_slots[username] = slot

        return slot

    def free_slot(self, username):
        slot = self.user_slots.pop(username, None)

        if slot is not None:
            self.slot_map.pop(slot, None)
            self._freed_slots.append(slot)

        return slot

    def slot_of(self, username: str) -> int | None:
        return self.user_slots.get(username)

    def user_at(self, slot: int) -> str | None:
        return self.slot_map.get(slot)

    @property
    def message_key(self):
        if self.member.root is None:
            return None
        return derive_message_key(self.member.root, self.group_name, self.epoch)

    def advance_epoch(self):
        self.epoch += 1

    @property
    def next_slot(self):
        return self._next_slot


class ClientState:
    def __init__(self):
        self.username: str      = ""
        self.current_group: str = ""

        # groups we created ourselves (so history handler knows to bootstrap
        # a creator tree rather than waiting for a Welcome)
        self._created_groups: set = set()

        # group -> list of messages
        self.pending_messages: dict[str, list] = {}

        # Crypto

        # Long-term identity keypair:
        '''
        x25519 -> used for Welcome message encrpytion (they need a key the committer can encrypt to before they
                are part of the tree
        ed25519 -> going to be added in the future (maybe) for signing / authentication
        '''

        # generated on startup - never shared
        self.x25519_priv    = X25519PrivateKey.generate()
        self.ed25519_priv   = Ed25519PrivateKey.generate()

        # public keys - safe to share
        self.x25519_pub     = self.x25519_priv.public_key()
        self.ed25519_pub    = self.ed25519_priv.public_key()

        # group_name -> GroupState
        self.groups: dict[str, GroupState] = {}

        # username -> their x25519 public key bytes (fetched from server
        self.known_peers: dict[str, bytes] = {}


    def set_username(self, username):
        self.username = username

    def switch_group(self, group_name):
        self.current_group = group_name

    def in_group(self, group_name: str) -> bool:
        return group_name in self.groups

    def current_group_state(self) -> GroupState | None:
        return self.groups.get(self.current_group)

    def create_group_state(self, group_name):
        member = Member(self.username, idx=0, n=MAX_GROUP_SIZE)
        # long term identity for decrpyting 'welcome' messages
        member.id_priv  = self.x25519_priv
        member.id_pub   = self.x25519_pub
        member.init_leaf()

        gs = GroupState(group_name, member, epoch=0)
        gs.assign_slot(self.username)   # creator is always slot 0

        self.groups[group_name] = gs
        self._created_groups.add(group_name)    # mark as creator

        return gs

    def is_creator_of(self, group_name: str) -> bool:
        return group_name in self._created_groups

    def join_from_welcome(self, group_name, welcome_payload):
        member = Member.from_welcome(
            name    = self.username,
            idx     = welcome_payload["slot"],
            id_priv = self.x25519_priv,
            welcome = welcome_payload["welcome"],
            n       = MAX_GROUP_SIZE,
        )
        gs = GroupState(group_name, member, epoch=welcome_payload["epoch"])

        for username, slot in welcome_payload["slot_map"].items():
            gs.slot_map[slot] = username
            gs.user_slots[username] = slot

        gs._next_slot = welcome_payload["next_slot"]

        self.groups[group_name] = gs

        return gs

    def message_key_for(self, group_name):
        gs = self.groups.get(group_name)

        return gs.message_key if gs else None

    def epoch_for(self, group_name):
        gs = self.groups.get(group_name)

        return gs.epoch if gs else 0

    @property
    def created_groups(self):
        return self._created_groups