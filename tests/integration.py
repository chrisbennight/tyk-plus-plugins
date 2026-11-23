"""Exercise authorization through Tyk and count the actual upstream dispatches."""

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

received = []


class Upstream(BaseHTTPRequestHandler):
    def do_POST(self):
        received.append(None)
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        received[-1] = (body["params"], self.headers.get("Authorization"))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"jsonrpc": "2.0", "id": body["id"],
                                     "result": {"content": []}}).encode())

    def log_message(self, *_):
        pass


def post(url, headers, data):
    request = Request(url, data=json.dumps(data).encode(),
                      headers={"Content-Type": "application/json", **headers})
    try:
        with urlopen(request, timeout=5) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        return error.code, json.load(error)


def key(role):
    status, response = post("http://gateway:9696/tyk/keys/create",
        {"X-Tyk-Authorization": os.environ["TYK_GW_SECRET"]},
        {"org_id": "default", "access_rights": {"governed": {"api_id": "governed", "versions": ["Default"]}},
         "quota_max": -1, "rate": 100, "per": 1, "meta_data": {"cedar": {
             "issuer": "integration", "subject": role, "roles": [role]}}})
    assert status == 200, status
    return response["key"]


def call(token, name, arguments, allowed):
    before = len(received)
    status, response = post("http://gateway:8080/mcp/",
        {"Authorization": token, "Accept": "application/json, text/event-stream",
         "MCP-Protocol-Version": "2025-11-25"},
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": name, "arguments": arguments}})
    if allowed:
        assert status == 200 and "result" in response, (status, response)
        assert len(received) == before + 1
        params, auth = received[-1]
        assert params["name"] == name and params["arguments"] == arguments and auth is None
    else:
        assert status == 403 and len(received) == before, (status, response, len(received))
    return response


def publish_inventory(tools):
    replace(Path("/policy/tools.json"), json.dumps({"governed": {"upstream": "http://probe:8000/mcp", "tools": tools}}))


def replace(path, text):
    candidate = path.with_suffix(".next")
    candidate.write_text(text)
    candidate.replace(path)


server = HTTPServer(("", 8000), Upstream)
threading.Thread(target=server.serve_forever, daemon=True).start()
for attempt in range(30):
    try:
        with urlopen("http://gateway:9696/hello", timeout=2) as health:
            if json.load(health)["status"] == "pass":
                break
    except (URLError, ConnectionError):
        pass
    time.sleep(1)

support, operator = key("support"), key("operator")
rules = Path("/policy/rules.cedar")
initial = rules.read_text()
inventory = {"lookup": {"readOnly": True},
             "change": {"readOnly": False, "arguments": {"count": "long"}}}
publish_inventory(inventory)

# Without a usable policy, the gateway must not dispatch even an operator's call.
replace(rules, "invalid")
call(operator, "change", {"count": 2}, False)
replace(rules, initial)
call(support, "lookup", {}, True)
call(support, "change", {}, False)
call(operator, "change", {"count": 2}, True)

# The operator's classification holds even when the upstream advertises read-only.
inventory["change"]["definition"] = {"name": "change", "annotations": {"readOnlyHint": True}}
publish_inventory(inventory)
call(support, "change", {}, False)
hidden = call(support, "change", {"count": "wrong"}, False)
assert call(support, "unknown", {"count": "wrong"}, False) == hidden

# A live policy change restricts the same operator call and keeps new mutations
# operator-only even with a broad permit. A rejected edit preserves both decisions.
replace(rules, initial + """
permit (principal, action, resource);
forbid (principal, action, resource)
when { context.numbers.contains({name: "count", value: 2}) };
""")
inventory["new-tool"] = {"readOnly": False}
publish_inventory(inventory)
call(support, "new-tool", {}, False)
call(operator, "new-tool", {}, True)
call(operator, "change", {"count": 2}, False)
replace(rules, initial + 'permit(principal, action, resource) when {principal.missing == "yes"};')
call(operator, "change", {"count": 2}, False)
call(operator, "change", {"count": 3}, True)

# A forbid that errors during evaluation must override the matching operator permit.
replace(rules, initial + """
forbid (principal, action, resource)
when { resource.name == "change" && (9223372036854775807 + 1 > 0) };
""")
call(operator, "change", {"count": 3}, False)
print("Cedar decisions, live policy changes, and upstream dispatch verified.")
