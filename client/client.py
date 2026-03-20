import ast
import base64
import json
import os

import websockets as ws
import sys
import asyncio

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from  ClientState import ClientState

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from cryptography.hazmat.primitives import hashes, serialization

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

HOST = "127.0.0.1"
PORT = 4444
BUFFER_SIZE = 1024

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
        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "join_group",
            "args": args
            }))

    elif cmd == "leave":
        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "leave_group",
            "args": [state.current_group]
        }))
        state.switch_group("")

    elif cmd == "create" and args:
        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "create_group",
            "args": args
        }))

    elif cmd == "delete" and args:
        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "delete_group",
            "args": args
        }))

    elif cmd == "groups":
        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "list_groups",
            "args": []
        }))

    elif cmd == "members":
        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "get_members",
            "args": [state.current_group]
        }))

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
            key = state.group_keys.get(data["group"])
            if not key:
                print(f"{data['group']}>{data['username']}: [encrypted, no key :P]")
                continue

            plaintext = decrypt_message(key, data["nonce"], data["ciphertext"], data["group"], data["username"])
            print(f"{data['group']}>{data['username']}: {plaintext}")

        elif data["type"] == "history":
            # only switch group on successful join
            state.switch_group(data["group"])
            for msg in data["messages"]:
                print(f"{data['group']}>{msg['username']}: {msg['text']}")

            await websocket.send(json.dumps({
                "type": "cmd",
                "cmd": "get_members",
                "args": [data["group"]]
            }))

        elif data["type"] == "members":
            for member in data["members"]:
                if member != state.username:
                    await websocket.send(json.dumps({
                        "type": "cmd",
                        "cmd": "get_key_package",
                        "args": [member]
                    }))

        elif data["type"] == "user_joined":
            print(f"[INFO] '{data["username"]}' joined '{data["group"]}'")

            await websocket.send(json.dumps({
                "type": "cmd",
                "cmd": "get_key_package",
                "args": [data["username"]]
            }))

        elif data["type"] in ("response", "error"):
            print(f"[{data['type'].upper()}] {data['text']}")

        elif data["type"] == "kicked_from_group":
            print(f"[{data['type'].upper()}] {data['text']}")
            if state.current_group == data["group"]:
                state.switch_group("")

        elif data["type"] == "key_package":
            pub_bytes = base64.b64decode(data["x25519_pub"])
            state.known_peers[data["username"]] = pub_bytes

            # derive the group key
            group_key = derive_group_key(state.x25519_priv, pub_bytes, state.current_group)
            state.group_keys[state.current_group] = group_key
            print(f"[CRYPTO] Group key established for: '{state.current_group}'")

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

            key = state.group_keys.get(state.current_group)
            if not key:
                print("[CRYPTO] No key for this group")
                continue

            encrypted = encrypt_message(key, message, state.current_group, state.username)

            await websocket.send(json.dumps({
                "type": "message",
                "group": state.current_group,
                "username": state.username,
                "nonce": encrypted["nonce"],
                "ciphertext": encrypted["ciphertext"]
            }))

# Crypto

def serialize_pub(key):
    raw = key.public_bytes(
        encoding = serialization.Encoding.Raw,
        format = serialization.PublicFormat.Raw
    )

    return base64.b64encode(raw).decode()   # ?

def derive_group_key(my_priv: X25519PrivateKey, their_pub_bytes: bytes, group_name: str) -> bytes:
    their_pub = X25519PublicKey.from_public_bytes(their_pub_bytes)
    shared_secret = my_priv.exchange(their_pub)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=f"mls-chat-group-{group_name}".encode()
    ).derive(shared_secret)

def encrypt_message(key: bytes, plain_text: str, group: str, username: str) -> dict:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    aad = f"{group}:{username}".encode()
    ciphertext = aesgcm.encrypt(nonce, plain_text.encode(), aad)

    return {
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode()
    }

def decrypt_message(key:bytes, nonce_b64: str, ciphertext_b64: str, group: str, username: str) -> str:
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(nonce_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    aad = f"{group}:{username}".encode()

    return aesgcm.decrypt(nonce, ciphertext, aad).decode()

# Main

async def main():
    async with ws.connect(f"ws://{HOST}:{PORT}") as websocket:

        # register username on connect
        username = input("Enter username: ").strip() or "guest"
        state.set_username(username)

        await websocket.send(json.dumps({
            "type": "register",
            "username":username,
            "x25519_pub": serialize_pub(state.x25519_pub),
            "ed25519_pub": serialize_pub(state.ed25519_pub)
        }))

        with patch_stdout():    # for syncing received messages with text thats being written
            session = PromptSession()
            await asyncio.gather(
                receive_loop(websocket),
                input_loop(websocket, session),
            )

if __name__ == "__main__":
    asyncio.run(main())