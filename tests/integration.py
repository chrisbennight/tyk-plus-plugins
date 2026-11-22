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
inventory = {"lookup": {"readOnly": True}, "change": {"readOnly": False, "arguments": {"count": "long"}}}
replace(Path("/policy/tools.json"), json.dumps({"governed": inventory}))
replace(rules, "invalid")
call(operator, "change", {}, False)
replace(rules, initial)
call(support, "lookup", {}, True)
replace(rules, "forbid(principal, action, resource);")
call(support, "lookup", {}, True)
replace(rules, initial)
replace(Path("/policy/tools.json"), "null")
call(support, "lookup", {}, True)
for hint in ({}, {"readOnlyHint": True}):
    inventory["change"]["definition"] = {"name": "change", "annotations": hint}
    replace(Path("/policy/tools.json"), json.dumps({"governed": inventory}))
    hidden = call(support, "change", {}, False)
    assert call(support, "change", {"count": "wrong"}, False) == hidden
    assert call(support, "new-tool", {"count": "wrong"}, False) == hidden
call(operator, "change", {"count": 2}, True)
call(operator, "new-tool", {}, False)
replace(Path("/policy/tools.json"), '{"governed":{"change":{"readOnly":false,"readOnly":true}}}')
call(support, "change", {}, False)
call(support, "lookup", {}, True)
replace(Path("/policy/tools.json"), json.dumps({"governed": inventory}))

replace(rules, initial + """
permit (principal, action, resource) when {
  context.numbers.contains({name: "count", value: 5}) ||
  (resource.upstreamAnnotations has readOnlyHint && resource.upstreamAnnotations.readOnlyHint)
};
""")
call(support, "change", {"count": 5}, True)
call(support, "change", {}, False)

replace(rules, initial + """
forbid (principal, action, resource) when {
  resource.upstreamAnnotations has readOnlyHint && resource.upstreamAnnotations.readOnlyHint
};
""")
call(operator, "change", {}, False)
inventory["change"]["definition"]["annotations"] = {}
replace(Path("/policy/tools.json"), json.dumps({"governed": inventory}))
call(operator, "change", {}, True)

restriction = """
@id("restricted-count")
forbid (principal, action, resource)
when { context.numbers.contains({name: "count", value: 2}) };
"""
replace(rules, initial + restriction)
call(operator, "change", {"count": 2}, False)
call(operator, "change", {"count": 3}, True)
replace(rules, initial + 'forbid(principal, action, resource) when {principal.missing};')
call(operator, "change", {"count": 2}, False)
call(operator, "change", {"count": 3}, True)

# A well-typed arithmetic expression may still overflow at evaluation time.
replace(rules, initial + """
@id("overflow")
forbid (principal, action, resource)
when { resource.name == "change" && (9223372036854775807 + 1 > 0) };
""")
call(operator, "change", {}, False)
print("Cedar decisions, live policy changes, and upstream dispatch verified.")
