"""Exercise authorization through Tyk and count the actual upstream dispatches."""

import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

UPSTREAM = "http://upstream:8000/mcp"


def observed():
    with urlopen("http://upstream:8000/requests", timeout=5) as response:
        return json.load(response)


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


def rpc(token, method, params):
    return post("http://gateway:8080/mcp/",
                {"Authorization": token, "Accept": "application/json, text/event-stream",
                 "MCP-Protocol-Version": "2025-11-25"},
                {"jsonrpc": "2.0", "id": 1, "method": method, "params": params})


def call(token, name, arguments, expected=None):
    before = observed()["requests"]
    status, response = rpc(token, "tools/call", {"name": name, "arguments": arguments})
    after = observed()
    if expected is None:
        assert status == 403 and after["requests"] == before, (name, status, response)
    else:
        assert status == 200 and response["result"]["content"] == [{"type": "text", "text": expected}], response
        assert after == {"requests": before + 1, "arguments": arguments}, after
    return response


def publish_inventory(tools, upstream=UPSTREAM):
    replace(Path("/policy/tools.json"), json.dumps({"governed": {"upstream": upstream, "tools": tools}}))


def replace(path, text):
    candidate = path.with_suffix(".next")
    candidate.write_text(text)
    candidate.replace(path)


for attempt in range(30):
    try:
        with urlopen("http://gateway:9696/hello", timeout=2) as health:
            if json.load(health)["status"] == "pass" and observed()["requests"] >= 0:
                break
    except (URLError, ConnectionError):
        pass
    time.sleep(1)

support, operator, guest = key("support"), key("operator"), key("guest")
status, init = rpc(operator, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                                           "clientInfo": {"name": "integration", "version": "1"}})
assert status == 200 and init["result"]["serverInfo"]["name"] == "test-upstream", init
status, listing = rpc(operator, "tools/list", {})
assert status == 200, listing
catalog = {tool["name"]: tool for tool in listing["result"]["tools"]}
assert catalog["change"]["annotations"]["readOnlyHint"] is True

rules = Path("/policy/rules.cedar")
initial = rules.read_text()
inventory = {"lookup": {"readOnly": True, "definition": catalog["lookup"], "arguments": {"count": "long"}}}
publish_inventory(inventory)
replace(rules, "invalid")
call(operator, "lookup", {})
replace(rules, initial)
call(support, "lookup", {}, "found")

# The guest permit applies across tools for count=3. An upstream hint alone cannot
# grant the same guest access, and an operator still cannot call an unreviewed tool.
updated = initial + """
permit (principal, action, resource) when {
  context.numbers.contains({name: "count", value: 3}) ||
  (resource.upstreamAnnotations has readOnlyHint && resource.upstreamAnnotations.readOnlyHint)
};
forbid (principal, action, resource) when {
  resource.upstreamAnnotations.flags.contains({name: "vendor.batchSafe", value: false}) &&
  context.numbers.contains({name: "count", value: 2})
};
"""
replace(rules, updated)
call(guest, "lookup", {"count": 3}, "found")
call(guest, "lookup", {})
call(operator, "change", {"count": 3})

# Onboard the real tool as state-changing. The reviewed classification wins,
# and the upstream declaration can further restrict the operator's call.
inventory["change"] = {"readOnly": False, "arguments": {"count": "long"}}
publish_inventory(inventory)
call(operator, "change", {"count": 2}, "updated")
denied = call(support, "change", {"count": 3})
# Include a custom upstream annotation in the copied definition.
catalog["change"]["annotations"]["vendor.batchSafe"] = False
inventory["change"]["definition"] = catalog["change"]
publish_inventory(inventory)
call(guest, "change", {"count": 3})
call(operator, "change", {"count": 2})
call(operator, "change", {"count": 3}, "updated")
hidden = call(support, "change", {"count": "wrong"})
assert call(support, "unknown", {"count": "wrong"}) == hidden == denied

# Retargeting requires a fresh review. A rejected inventory or policy edit keeps
# the working decisions. A forbid that errors during execution blocks dispatch.
publish_inventory(inventory, "http://replacement.invalid/mcp")
call(operator, "lookup", {})
publish_inventory(inventory)
call(operator, "lookup", {}, "found")
publish_inventory(dict(inventory, change={"readOnly": False, "argumants": {"count": "long"}}))
call(operator, "change", {"count": 2})
publish_inventory(inventory)
replace(rules, "forbid(principal, action, resource);")
call(guest, "lookup", {"count": 3}, "found")
replace(rules, initial + 'permit(principal, action, resource) when {principal.missing == "yes"};')
call(operator, "change", {"count": 2})
# The operator can delegate a reviewed mutation to the same guest denied above.
delegated = """
permit (principal, action, resource) when {
  (principal.roles.contains("support") && resource.reviewed.readOnly) ||
  (principal.roles.contains("guest") && resource.name == "change" &&
   context.numbers.contains({name: "count", value: 3}))
};
"""
replace(rules, delegated)
call(guest, "change", {"count": 3}, "updated")
replace(rules, delegated + """
forbid (principal, action, resource)
when { resource.name == "change" && (9223372036854775807 + 1 > 0) };
""")
call(guest, "change", {"count": 3})
print("Verified Cedar access and upstream dispatch with a Go MCP server.")
