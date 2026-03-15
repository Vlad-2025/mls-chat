import json
import os
import websockets as ws
import sys
import asyncio
from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

HOST = "127.0.0.1"
PORT = 4444
BUFFER_SIZE = 1024

session = PromptSession()

class ClientState:
    def __init__(self):
        self.username: str = ""
        self.current_group: str = ""

    def set_username(self, username):
        self.username = username

    def switch_group(self, group_name):
        self.current_group = group_name

state = ClientState()

async def process_command(websocket, text):
    parts = text.lstrip("/").split()
    cmd = parts[0]
    args = parts[1:]

    if cmd == "join" and args:
        state.switch_group(args[0])
        await websocket.send(json.dumps({"type": "cmd", "cmd": "join_group", "args": args}))

    elif cmd == "switch" and args:
        state.switch_group(args[0])
        os.system('cls')
        await websocket.send(json.dumps({"type": "cmd", "cmd": "join_group", "args": args}))

    elif cmd == "leave":
        await websocket.send(json.dumps({"type": "cmd", "cmd": "leave_group", "args": [state.current_group]}))
        state.switch_group("")

    elif cmd == "create" and args:
        await websocket.send(json.dumps({"type": "cmd", "cmd": "create_group", "args": args}))

    elif cmd == "delete" and args:
        await websocket.send(json.dumps({"type": "cmd", "cmd": "delete_group", "args": args}))

    elif cmd == "groups":
        await websocket.send(json.dumps({"type": "cmd", "cmd": "list_groups", "args": []}))

    elif cmd == "members":
        await websocket.send(json.dumps({"type": "cmd", "cmd": "get_members", "args": [state.current_group]}))

    else:
        print(f"Unknown command: {cmd}")

async def receive_loop(websocket):

    async for raw in websocket:
        data = json.loads(raw)

        if data["type"] == "message":
            print(f"\n{data['group']}>{data['username']}: {data['text']}")

        elif data["type"] == "history":
            for msg in data["messages"]:
                print(f"{data['group']}>{msg['username']}: {msg['text']}")

        elif data["type"] in ("response", "error"):
            print(f"[{data['type'].upper()}] {data['text']}")

async def input_loop(websocket):

    while True:
        message = await session.prompt_async(f"{state.username}@{state.current_group}> ")

        # skip loop if message is empty
        if not message.strip():
            continue

        if message == "exit":
            await websocket.close()
            break

        # check if it's a command
        if message.startswith("/"):
            await process_command(websocket, message)

        else:
            if not state.current_group:
                print("You are not currently in a group. Use '/join <group_name>' first")
                continue

            await websocket.send(json.dumps({
                "type": "message",
                "group": state.current_group,
                "username": state.username,
                "text": message
            }))


async def main():
    async with ws.connect(f"ws://{HOST}:{PORT}") as websocket:

        # register username on connect
        username = input("Enter username: ").strip() or "guest"
        state.set_username(username)

        await websocket.send(json.dumps({"type": "register", "username":username}))

        with patch_stdout():    # for syncing received messages with text thats being written
            await asyncio.gather(
                receive_loop(websocket),
                input_loop(websocket),
            )

if __name__ == "__main__":
    asyncio.run(main())