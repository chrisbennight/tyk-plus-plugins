"""Exercise the local Compose gateway as a stateless Streamable HTTP client."""

import json
import subprocess
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

published = subprocess.check_output(["docker", "compose", "port", "gateway", "8080"], text=True).strip()
url = f"http://{published}/mcp/"
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
try:
    send("tools/call", {"name": "unlisted", "arguments": {}}, 4)
except HTTPError as error:
    assert error.code == 403 and json.load(error)["error"]["code"] == -32002
else:
    raise AssertionError("Tyk allowed an unlisted tool")
print("Passed MCP initialization, discovery, echo, and gateway denial of an unlisted tool.")
