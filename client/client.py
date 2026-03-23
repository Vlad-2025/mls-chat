import base64
import json
import os

import websockets as ws
import sys
import asyncio

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ClientState import ClientState
from treekem import pub_bytes as treekem_pub_bytes, pub_from_bytes as treekem_pub_from_bytes

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
        os.system('cls' if sys.platform == "win32" else "clear")
        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "join_group",
            "args": args
        }))

    elif cmd == "leave":

        if not state.current_group:
            print("You are not part of a group")
            return

        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "leave_group",
            "args": [state.current_group]
        }))
        state.switch_group("")

    elif cmd == "create" and args:
        # mark as creator now, before the history response arrives asynchronously
        state.created_groups.add(args[0])
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

        #print(f"Hello {state.current_group}")

        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "list_members",
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

        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "get_pending",
            "args": [state.current_group]
        }))

    # /kick username reason -> group is inferred
    elif cmd == "kick" and len(args) >= 1:
        if not state.current_group:
            print("You are not currently in a group")
            return

        username = args[0]
        reason = args[1] if len(args) == 2 else None

        await websocket.send(json.dumps({
            "type": "cmd",
            "cmd": "kick_member",
            "args": [state.current_group, username, reason]
        }))

    else:
        print(f"Unknown command: '{cmd}'")


async def receive_loop(websocket):
    async for raw in websocket:
        data = json.loads(raw)

        if data["type"] == "message":

            group = data["group"]
            key = state.message_key_for(group)
            msg_epoch = data.get("epoch", 0)
            nonce = data["nonce"]
            our_epoch = state.epoch_for(group)
            username = data["username"]

            if not key:
                print(f"{group}>{username}: [encrypted, no key]")
                continue

            # If epochs differ we try to decrypt anyway — commits and messages
            # can arrive out of order so a mismatch doesn't always mean failure.
            # Only print a warning if decryption actually fails.
            try:
                plaintext = decrypt_message(key, nonce, data["ciphertext"], group, username)
                if msg_epoch != our_epoch:
                    print(f"[WARN] {group}: decrypted message from epoch {msg_epoch} (ours: {our_epoch})")
                print(f"{group}>{username}: {plaintext}")
            except Exception:
                print(f"{group}>{username}: [decrypt failed, epoch {msg_epoch} vs {our_epoch}]")

        elif data["type"] == "history":
            group = data["group"]
            state.switch_group(group)

            # Only bootstrap a creator tree if WE created this group.
            # If we are a joiner, our tree comes from the Welcome message —
            # calling create_group_state here would give us the wrong idx
            # and wrong keys, and the Welcome guard would skip join_from_welcome.
            if not state.in_group(group) and state.is_creator_of(group):
                state.create_group_state(group)
                print(f"[CRYPTO] Initialized tree for '{group}'")

            for msg in data["messages"]:
                '''
                need to fix the epoch stuff, it needs to be communicated per message
                '''
                key = state.message_key_for(group)
                if key:
                    try:
                        plaintext = decrypt_message(
                            key,
                            msg["nonce"],
                            msg["text"],
                            group,
                            msg["username"]
                        )
                        print(f"{group}>{msg['username']}: {plaintext}")

                    except Exception:
                        print(f"{group}>{msg['username']}: [undecryptable history]")
                else:
                    print(f"{group}>{msg['username']}: [no key for history]")

            await websocket.send(json.dumps({
                "type": "cmd",
                "cmd": "get_members",
                "args": [group]
            }))

        elif data["type"] == "members_list":
            members_str = ", ".join(data["members"])
            print(f"[INFO] Members in '{data['group']}': {members_str}")

        elif data["type"] == "members":
            #print(f"[INFO] Members of '{data['group']}': {', '.join(data['members'])}")
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


        elif data["type"] == "key_package":
            new_user = data["username"]
            pub_bytes = base64.b64decode(data["x25519_pub"])
            state.known_peers[new_user] = pub_bytes

            # derive the group key

            group = state.current_group
            gs = state.current_group_state()

            if not gs:
                # not in a group
                continue

            if gs.slot_of(new_user) is not None:
                # already have a slot for this person
                continue

            # only the group creator (slot 0) runs Add commits
            # the new joiner will get a Welcome message instead
            if gs.member.idx != 0:
                continue

            new_slot = gs.assign_slot(new_user)
            new_id_pub = treekem_pub_from_bytes(pub_bytes)

            print(f"[CRYPTO] Adding '{new_user}' to tree slot at: '{new_slot}'")

            commit_dict, welcome_dict = gs.member.add(
                new_idx=new_slot,
                new_id_pub=new_id_pub
            )
            gs.advance_epoch()

            await websocket.send(json.dumps({
                "type": "treekem_commit",
                "group": group,
                "epoch": gs.epoch,
                "commit": commit_dict,
                "added_user": new_user,
                "added_slot": new_slot
            }))

            # send the Welcome message only to the new member
            await websocket.send(json.dumps({
                "type": "treekem_welcome",
                "to": new_user,
                "group": group,
                "epoch": gs.epoch,
                "slot": new_slot,
                "welcome": welcome_dict,
                "slot_map": {u: s for u, s in gs.user_slots.items()},
                "next_slot": gs.next_slot
            }))

            print(f"[CRYPTO] Epoch advanced to {gs.epoch} after adding '{new_user}'")

        elif data["type"] == "treekem_commit":
            group = data["group"]
            gs = state.groups.get(group)
            if not gs:
                continue

            # skip commits we sent ourselves — we already applied them
            if data["commit"].get("from") == gs.member.idx:
                continue

            added_user = data.get("added_user")
            added_slot = data.get("added_slot")
            removed_slot = data.get("removed_slot")

            # update slot map if the commit added someone
            if added_user and added_slot is not None:
                gs.slot_map[added_slot] = added_user
                gs.user_slots[added_user] = added_slot
                if added_slot >= gs.next_slot:
                    gs._next_slot = added_slot + 1

            try:
                gs.member.recv(
                    data["commit"],
                    removed_idx=removed_slot
                )
                gs.epoch = data["epoch"]

                print(f"[CRYPTO] Processed commit, current epoch: {gs.epoch}")
            except Exception as e:
                print(f"[CRYPTO] Failed to process commit: {e}")

        elif data["type"] == "treekem_welcome":
            group = data["group"]
            if state.in_group(group):
                # already in group -> ignore duplicate welcome
                continue

            gs = state.join_from_welcome(group, data)
            print(f"[CRYPTO] Joined '{group}' via Welcome, epoch {gs.epoch}")

            # set group as active if we are switching to it
            if not state.current_group:
                state.switch_group(group)

        elif data["type"] == "invite":
            print(f"[INVITE] {data['text']}")

        elif data["type"] == "kicked_from_group":
            print(f"[{data['type'].upper()}] {data['text']}")
            if state.current_group == data["group"]:
                state.switch_group("")
            state.groups.pop(data["group"], None)

        elif data["type"] in ("response", "error"):
            print(f"[{data['type'].upper()}] {data['text']}")


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
            continue

        if not state.current_group:
            print("You are not in a group. Use /create '<name>' or /switch '<name>'")
            continue

        key = state.message_key_for(state.current_group)
        epoch = state.epoch_for(state.current_group)

        if not key:
            print("[CRYPTO] No key for this group yet - waiting for tree setup")
            continue

        encrypted = encrypt_message(
            key,
            message,
            state.current_group,
            state.username
        )

        await websocket.send(json.dumps({
            "type": "message",
            "group": state.current_group,
            "username": state.username,
            "epoch": epoch,
            "nonce": encrypted["nonce"],
            "ciphertext": encrypted["ciphertext"]
        }))


# Crypto

def serialize_pub(key):
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

    return base64.b64encode(raw).decode()  # ?


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


def decrypt_message(key: bytes, nonce_b64: str, ciphertext_b64: str, group: str, username: str) -> str:
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
            "username": username,
            "x25519_pub": serialize_pub(state.x25519_pub),
            "ed25519_pub": serialize_pub(state.ed25519_pub)
        }))

        with patch_stdout():  # for syncing received messages with text thats being written
            session = PromptSession()
            await asyncio.gather(
                receive_loop(websocket),
                input_loop(websocket, session),
            )


if __name__ == "__main__":
    asyncio.run(main())