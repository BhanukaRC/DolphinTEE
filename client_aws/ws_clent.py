import asyncio
import websockets

async def handler(websocket, path):
    print("Client connected")
    try:
        async for message in websocket:
            print(f"Received: {message}")
            await websocket.send(f"You sent: {message}")
    except websockets.ConnectionClosed as e:
        print(f"Client disconnected: {e}")

async def main():
    server = await websockets.serve(handler, "0.0.0.0", 8080)
    print("WebSocket server is running on ws://0.0.0.0:8080")
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())

~                                           