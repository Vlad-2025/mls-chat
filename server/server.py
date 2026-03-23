import json
import websockets as ws
import sys
import asyncio

from ServerState import ServerState

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

HOST = "127.0.0.1"  # loopback
PORT = 4444
BUFFER_SIZE = 1024


state = ServerState()

async def process_command(websocket, username, cmd, args):
    if cmd == "create_group":

        result = state.create_group(args[0])
        if result.startswith("Group '"):

            state.join_group(username, args[0])
            history = state.get_history(args[0])

            return {
                "type": "history",
                "group": args[0],
                "messages": history
            }

        return {
            "type": "response",
            "text": result
        }

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

        return {
            "type": "response",
            "text": result
        }

    elif cmd == "join_group":
        result = state.join_group(username, args[0])

        if result == "Group not found":
            return {
                "type": "error",
                "text": result
            }

        history = state.get_history(args[0])
        return {
            "type": "history",
            "group": args[0],
            "messages": history
        }

    elif cmd == "invite_user":

        invitee = args[1] if len(args) > 1 else None
        group = args[0] if args else None

        if not group or not invitee:
            return {
                "type": "error",
                "text": "Usage: /invite <user> (while in a group)"
            }

        result = state.invite_user(username, invitee, group)
        if result.startswith("Invited"):
            # notify the person being invited
            if invitee in state.clients:
                await state.clients[invitee].send(json.dumps({
                    "type": "invite",
                    "group": group,
                    "from": username,
                    "text": f"'{username}' invited you to join '{group}'. Do /accept <group> to become a member"
                }))
        return {
            "type": "response",
            "text": result
        }

    elif cmd == "accept_invite":

        group = args[0] if args else None
        if not group:
            return {
                "type": "error",
                "text": "Usage: /accept <group>"
            }

        result = state.accept_invite(username, group)
        if result.startswith("Joined"):
            # notify members
            for member in state.groups[group]:
                if member != username and member in state.clients:
                    await state.clients[member].send(json.dumps({
                        "type": "user_joined",
                        "username": username,
                        "group": group
                    }))
            history = state.get_history(group)
            return {
                "type": "history",
                "group": group, "messages": history
            }

        return {
            "type": "error",
            "text": result
        }

    elif cmd == "get_pending":

        group = args[0] if args else None
        if not group:
            return {
                "type": "error",
                "text": "Usage: /pending (while in a group)"
            }

        result = state.get_pending(username, group)
        if isinstance(result, str):
            return {
                "type": "error",
                "text": result
            }

        return {
            "type": "response",
            "text": f"Pending: {result}" if result else "No pending invites"
        }


    elif cmd == "leave_group":
        return {
            "type": "response",
            "text": state.leave_group(username, args[0])
        }

    elif cmd == "kick_member":

        # /kick username reason -> returns args: [group, username, reason]

        group       = args[0]   if args else None
        username    = args[1]   if args[1] else None
        reason      = args[2]   if args[2] else None

        if not group or not username:
            return{
                "type": "error",
                "text": "Usage: /kick <user> ...reason (while in a group)"
            }

        result = state.kick_member(group, username, reason)
        if result.startswith("Kicked"):
            # notify the person being kicked
            if username in state.clients:
                await state.clients[username].send(json.dumps({
                    "type": "kicked_from_group",
                    "group": group,
                    "text": f"You have been kicked from '{group}' for '{reason}'"
                }))

        return {
            "type": "response",
            "text": result
        }

    elif cmd == "list_groups":
        return {
            "type": "response",
            "text": str(state.list_groups())
        }

    elif cmd == "get_members":
        members = state.get_members(args[0])
        return {
            "type": "members",
            "group": args[0],
            "members": members
        }

    elif cmd == "get_key_package":
        target = args[0] if args else None
        if not target or target not in state.key_packages:
            return {
                "type": "error",
                "text": "User not found"
            }
        return {
            "type": "key_package",
            "username": target,
            **state.key_packages[target]    # dictionary unpacking
        }

    return {
        "type": "error",
        "text": "Unknown command"
    }

async def handle_client(websocket):

    addr = websocket.remote_address

    print(f"[SERVER] Connection from {addr}")

    username = None

    try:
        async for raw in websocket:
            try:
                data = json.loads(raw)
                msg_type = data.get("type")

                if msg_type == "register":
                    username = data["username"]
                    x25519_pub = data["x25519_pub"]
                    ed25519_pub = data["ed25519_pub"]
                    state.register_client(username, websocket, x25519_pub, ed25519_pub)
                    print(f"[SERVER] '{username}' registered from {addr}")

                    await websocket.send(json.dumps({
                        "type": "response",
                        "text": f"Welcome, {username}!"
                    }))

                elif msg_type == "cmd":
                    if not username:
                        await websocket.send(json.dumps({"type":"error", "text":"Not registered!"}))
                        continue
                    response = await process_command(websocket, username, data["cmd"], data.get("args", []))
                    await websocket.send(json.dumps(response))

                elif msg_type == "message":
                    group = data["group"]
                    ciphertext = data.get("ciphertext", "")
                    nonce = data["nonce"]
                    epoch = data.get("epoch", 0)

                    print(f"[CIPHERED] {ciphertext}")

                    if group not in state.groups:
                        await websocket.send(json.dumps({
                            "type": "error",
                            "text": f"Group '{group}' no longer exists!"
                        }))
                        continue

                    state.add_message(group, username, nonce, ciphertext, epoch)

                    # broadcast to everyone, except the sender
                    for member in state.groups.get(group, set()):
                        if member != username and member in state.clients:
                            await state.clients[member].send(json.dumps({
                                "type": "message",
                                "group": group,
                                "username": username,
                                "nonce": data["nonce"],
                                "ciphertext": ciphertext
                            }))

                # the server forwards the data without looking at it, because it cant

                elif msg_type == "treekem_commit":
                    group = data.get("group")
                    if not group:
                        continue

                    for member in state.groups.get(group, set()):
                        if member != username and member in state.clients:  # notify members
                            await state.clients[member].send(json.dumps(data))

                elif msg_type == "treekem_welcome":
                    target = data.get("to")
                    if target and target in state.clients:  # send welcome package to new member
                        await state.clients[target].send(json.dumps(data))

            except Exception as e:
                print(f"[SERVER] error: {str(e)}")
                await websocket.send(json.dumps({
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