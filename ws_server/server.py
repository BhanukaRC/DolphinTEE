import asyncio
import websockets
import json

async def handler(websocket, path):
    print("Dolphin Client connected")
    try:
        async for message in websocket:
            print(f"Received: {message}")
            data = json.loads(message)
            if isinstance(data, list) and len(data) > 0:
                if data[0] == "generate_dh_key":
                    response = handle_generate_dh_key(data[1:])
                elif data[0] == "action2":
                    response = handle_action2(data[1:])
                else:
                    response = "Unknown action"
            else:
                response = "Invalid message format"
            await websocket.send(response)
    except websockets.ConnectionClosed as e:
        print(f"Client disconnected: {e}")

def handle_generate_dh_key(params):
    # Implement your logic for action1
    return f"Handled action1 with params: {params}"

def handle_action2(params):
    # Implement your logic for action2
    return f"Handled action2 with params: {params}"

async def main():
    server = await websockets.serve(handler, "0.0.0.0", 8080)
    print("Dolphin WebSocket server is running on ws://0.0.0.0:8080")
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
