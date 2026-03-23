class ServerState:

    def __init__(self):
        # username -> websocket
        self.clients: dict[str, any] = {}

        # group_name -> set of usernames
        self.groups: dict[str, set[str]] = {}

        # group_name -> list of {"username": str, "text": str}
        self.history: dict[str, list] = {}

        # group_name -> set of usernames waiting to accept invite
        self.pending: dict[str, set[str]] = {}

        # username -> {"x_pub": str, "ed_pub": str}
        self.key_packages: dict[str, dict] = {}

    def register_client(self, username, websocket, x25519_pub, ed25519_pub):
        self.clients[username] = websocket

        self.key_packages[username] = {
            "x25519_pub": x25519_pub,
            "ed25519_pub": ed25519_pub
        }

    def unregister_client(self, username):
        self.clients.pop(username, None)

        for members in self.groups.values():
            members.discard(username)

    def create_group(self, group_name):
        if group_name in self.groups:
            return "Group already exists"

        self.groups[group_name] = set()
        self.history[group_name] = []
        self.pending[group_name] = set()

        return f"Group '{group_name}' created"

    def delete_group(self, group_name):
        if group_name not in self.groups:
            return "Group not found"

        del self.groups[group_name]
        del self.history[group_name]
        del self.pending[group_name]

        return f"Group '{group_name}' deleted"

    def join_group(self, username, group_name):
        if group_name not in self.groups:
            return "Group not found"

        self.groups[group_name].add(username)

        return f"Joined '{group_name}' as '{username}'"

    def leave_group(self, username, group_name):
        if group_name not in self.groups:
            return "Group not found"

        self.groups[group_name].discard(username)

        return f"Left '{group_name}' as '{username}'"

    def kick_member(self, group_name, username, reason="unspecified"):
        if group_name not in self.groups:
            return "Group not found"

        if username not in self.groups[group_name]:
            return f"User '{username}' not found in '{group_name}'"

        self.groups[group_name].discard(username)

        return f"Kicked '{username}' from '{group_name}' for '{reason}'"

    def add_message(self, group_name, username, nonce, ciphertext, epoch=0):
        self.history[group_name].append({
            "username": username,
            "nonce":    nonce,
            "text":     ciphertext, # keeping it 'text' because i dont want to change the rest :P
            "epoch":    epoch
        })

    def get_history(self, group_name):
        return self.history.get(group_name, [])

    def get_members(self, group_name):
        return list(self.groups.get(group_name, []))

    def list_groups(self):
        return list(self.groups.keys())

    # inviting users

    def invite_user(self, inviter, username, group_name):
        if group_name not in self.groups:
            return "Group not found"

        if inviter not in self.groups[group_name]:
            return "You are not a member of this group"

        if username not in self.clients:
            return "User not online"

        if username in self.groups[group_name]:
            return "User is already in the group"

        self.pending[group_name].add(username)

        return f"Invited '{username}' to '{group_name}'"

    def accept_invite(self, username, group_name):
        if group_name not in self.groups:
            return "Group not found"

        if username not in self.pending.get(group_name, set()):
            return "No pending invite for this group"

        self.pending[group_name].discard(username)
        self.groups[group_name].add(username)
        print(self.groups[group_name])

        return f"Joined '{group_name}'"

    def get_pending(self, username, group_name):
        if group_name not in self.groups:
            return "Group not found"

        return list(self.pending.get(group_name, set()))
