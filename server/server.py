import json
from http.client import responses

import websockets as ws
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

HOST = "127.0.0.1"  # loopback
PORT = 4444
BUFFER_SIZE = 1024

class ServerState:

    def __init__(self):
        # username -> websocket
        self.clients: dict[str, any] = {}

        # group_name -> set of usernames
        self.groups: dict[str, set[str]] = {}

        # group_name -> list of {"username": str, "text": str}
        self.history: dict[str, list] = {}

    def register_client(self, username, websocket):
        self.clients[username] = websocket

    def unregister_client(self, username):
        self.clients.pop(username, None)

        for members in self.groups.values():
            members.discard(username)

    def create_group(self, group_name):
        if group_name in self.groups:
            return "Group already exists"

        self.groups[group_name] = set()
        self.history[group_name] = []

        return f"Group '{group_name}' created"

    def delete_group(self, group_name):
        if group_name not in self.groups:
            return "Group not found"

        del self.groups[group_name]
        del self.history[group_name]

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

    def add_message(self, group_name, username, text):
        self.history[group_name].append({"username": username, "text": text})

    def get_history(self, group_name):
        return self.history.get(group_name, [])

    def get_members(self, websocket, group_name):
        return list(self.groups.get(group_name, []))

    def list_groups(self):
        return list(self.groups.keys())


state = ServerState()

async def process_command(websocket, username, cmd, args):
    if cmd == "create_group":
        return {"type": "response", "text": state.create_group(args[0])}

    elif cmd == "delete_group":
        # kick everyone out first
        members = list(state.groups.get(args[0], set()))
        result = state.delete_group(args[0])

        # notify members
        for member in members:
            if member in state.clients:
                await state.clients[member].send(json.dumps({
                    "type": "kicked_from_group",
                    "group": args[0],
                    "text": f"Group '{args[0]}' was deleted"
                }))

        return {"type": "response", "text": result}

    elif cmd == "join_group":
        result = state.join_group(username, args[0])

        if result == "Group not found":
            return {"type": "error", "text": result}

        history = state.get_history(args[0])
        return {"type": "history", "group": args[0], "messages": history}

    elif cmd == "leave_group":
        return {"type": "response", "text": state.leave_group(username, args[0])}

    elif cmd == "list_groups":
        return {"type": "response", "text": str(state.list_groups())}

    elif cmd == "get_members":
        return {"type": "response", "text": str(state.get_members(websocket, args[0]))}

    return {"type": "error", "text": "Unknown command"}

async def handle_client(websocket):

    addr = websocket.remote_address

    print(f"[SERVER] Connection from {addr}")

    username = None

    try:
        async for raw in websocket:
            data = json.loads(raw)
            msg_type = data.get("type")

            if msg_type == "register":
                username = data["username"]
                state.register_client(username, websocket)
                print(f"[SERVER] '{username}' registered from {addr}")

                await websocket.send(json.dumps({"type": "response", "text": f"Welcome, {username}!"}))

            elif msg_type == "cmd":
                if not username:
                    await websocket.send(json.dumps({"type":"error", "text":"Not registered!"}))
                    continue
                response = await process_command(websocket, username, data["cmd"], data.get("args", []))
                await websocket.send(json.dumps(response))

            elif msg_type == "message":
                group = data["group"]
                text = data["text"]

                if group not in state.groups:
                    await websocket.send(json.dumps({
                        "type": "error",
                        "text": f"Group '{group}' no longer exists!"
                    }))
                    continue

                state.add_message(group, username, text)

                # broadcast to everyone, except the sender
                for member in state.groups.get(group, set()):
                    if member != username and member in state.clients:
                        await state.clients[member].send(json.dumps({
                            "type": "message",
                            "group": group,
                            "username": username,
                            "text": text
                        }))
    except Exception as e:
        print(f"[SERVER] error: {str(e)}")
        websocket.send(json.dumps({
            "type": "error",
            "text": f"Server error: {str(e)}"
        }))

    finally:
        if username:
            state.unregister_client(username)
            print(f"[SERVER] '{username}' disconnected")

async def main():

    async with ws.serve(handle_client, HOST, PORT):
        print(f"[SERVER] Listening on {HOST}:{PORT}")

        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())