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

async def receive_loop(websocket):

    async for message in websocket:
        print(f"Server response: {message}")

async def input_loop(websocket):

    while True:
        message = await session.prompt_async("client> ")
        message = message.strip()

        if message == "exit":
            await websocket.close()
            break

        await websocket.send(message)

async def main():
    async with ws.connect(f"ws://{HOST}:{PORT}") as websocket:
        with patch_stdout():
            await asyncio.gather(
                receive_loop(websocket),
                input_loop(websocket),
            )

if __name__ == "__main__":
    asyncio.run(main())