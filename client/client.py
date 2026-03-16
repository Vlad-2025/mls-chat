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

    '''
    DEPRECATED
    
    if cmd == "join" and args:
    await websocket.send(json.dumps({"type": "cmd", "cmd": "join_group", "args": args}))

    '''

    if cmd == "switch" and args:
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

    elif cmd == "invite" and args:
        if not state.current_group:
            print("You are not currently in a group")
            return

        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "invite_user",
            "args": [state.current_group, args[0]]
        }))

    elif cmd == "accept" and args:
        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "accept_invite",
            "args": [args[0]]
        }))

    elif cmd == "pending":
        if not state.current_group:
            print("You are not currently in a group")
            return

        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "get_pending",
            "args": [state.current_group]
        }))

    else:
        print(f"Unknown command: {cmd}")

async def receive_loop(websocket):

    async for raw in websocket:
        data = json.loads(raw)

        if data["type"] == "message":
            print(f"{data['group']}>{data['username']}: {data['text']}")

        elif data["type"] == "history":
            # only switch group on successful join
            state.switch_group(data["group"])
            for msg in data["messages"]:
                print(f"{data['group']}>{msg['username']}: {msg['text']}")

        elif data["type"] in ("response", "error"):
            print(f"[{data['type'].upper()}] {data['text']}")

        elif data["type"] == "kicked_from_group":
            print(f"[{data['type'].upper()}] {data['text']}")
            if state.current_group == data["group"]:
                state.switch_group("")

        elif data["type"] == "invite":
            print(f"[INVITE] {data['text']}")

async def input_loop(websocket, session):

    while True:
        # problem: prompt_async gets the current_group before /leave or /join work
        # message = await session.prompt_async(f"{state.current_group}>{state.username}> ")

        # solution: lambda re-evaluates state.current_group every render
        message = await session.prompt_async(
            lambda: f"{state.current_group}>{state.username}> "
        )

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
            session = PromptSession()
            await asyncio.gather(
                receive_loop(websocket),
                input_loop(websocket, session),
            )

if __name__ == "__main__":
    asyncio.run(main())