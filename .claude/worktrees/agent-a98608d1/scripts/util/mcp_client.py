import requests
import sseclient
import json
import threading
import time

def listen_sse():
    response = requests.get('http://localhost:8000/mcp/sse', stream=True)
    client = sseclient.SSEClient(response)
    for event in client.events():
        print(f"[{event.event}] {event.data}")
        if event.event == 'message':
            data = json.loads(event.data)
            if 'result' in data or 'error' in data:
                print("Compilation Response received!")
                print(json.dumps(data, indent=2))
                import sys
                sys.stdout.flush()
                sys.exit(0)

threading.Thread(target=listen_sse, daemon=True).start()

# Give SSE connection a moment to establish
time.sleep(1)

with open('mcp_invoke_tool.json', 'r') as f:
    payload = json.load(f)

print("Sending invocation request...")
res = requests.post('http://localhost:8000/mcp/message', json=payload)
print(f"POST returned {res.status_code}")
try:
    print(json.dumps(res.json(), indent=2))
except Exception as e:
    print("Could not parse response JSON:", res.text)
# Keep main thread alive until SSE response is received or timeout
time.sleep(45)
print("Timeout waiting for SSE response")
