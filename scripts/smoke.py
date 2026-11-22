"""Exercise the local Compose gateway as a stateless Streamable HTTP client."""

import json
import os
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

url = f"http://127.0.0.1:{int(os.environ.get('GATEWAY_PORT', 8080))}/mcp/"
protocol = "2025-11-25"


def send(method, params, request_id=None):
    payload = {"jsonrpc": "2.0", "method": method, "params": params}
    if request_id is not None:
        payload["id"] = request_id
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    if method != "initialize":
        headers["MCP-Protocol-Version"] = protocol
    request = Request(url, data=json.dumps(payload).encode(), headers=headers)
    with urlopen(request, timeout=5) as response:
        if request_id is None:
            assert response.status == 202, response.status
            return
        reply = json.load(response)
        assert reply["id"] == request_id, reply
        return reply["result"]


deadline = time.monotonic() + 60
while True:
    try:
        init = send("initialize", {
            "protocolVersion": protocol, "capabilities": {},
            "clientInfo": {"name": "bootstrap-smoke", "version": "1"},
        }, 1)
        break
    except (URLError, ConnectionResetError, TimeoutError):
        if time.monotonic() >= deadline:
            raise
        time.sleep(1)

assert init["protocolVersion"] == protocol, init
send("notifications/initialized", {})
tools = send("tools/list", {}, 2)["tools"]
assert any(tool["name"] == "echo" for tool in tools), tools
result = send("tools/call", {"name": "echo", "arguments": {"message": "bootstrap-ok"}}, 3)
assert not result.get("isError") and {"type": "text", "text": "bootstrap-ok"} in result["content"], result
print("Passed MCP initialization, tool discovery, and echo through Tyk.")
