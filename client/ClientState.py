class ClientState:
    def __init__(self):
        self.username: str = ""
        self.current_group: str = ""

    def set_username(self, username):
        self.username = username

    def switch_group(self, group_name):
        self.current_group = group_name
