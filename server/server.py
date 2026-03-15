import websockets as ws
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

HOST = "127.0.0.1"  # loopback
PORT = 4444
BUFFER_SIZE = 1024

async def handle_client(websocket):

    addr = websocket.remote_address

    print(f"[SERVER] Connection from {addr}")

    async for message in websocket:
        print(f"{addr}: {message}")

        await websocket.send(message)   # echo

async def main():

    async with ws.serve(handle_client, HOST, PORT):
        print(f"[SERVER] Listening on {HOST}:{PORT}")

        await asyncio.Future()  # Run forever

if __name__ == "__main__":
    asyncio.run(main())