import asyncio
import websockets
import json

async def main():
    uri = "ws://44.220.136.188:8080"
    async with websockets.connect(uri) as websocket:
        print("Connected to the server")

        # Send a message for action1
        message1 = json.dumps(["action1", "param1", "param2"])
        await websocket.send(message1)
        response1 = await websocket.recv()
        print(f"Received from server: {response1}")

        # Send a message for action2
        message2 = json.dumps(["action2", "param1", "param2"])
        await websocket.send(message2)
        response2 = await websocket.recv()
        print(f"Received from server: {response2}")

if __name__ == "__main__":
    asyncio.run(main())
