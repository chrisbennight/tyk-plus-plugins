"""Exercise authorization through Tyk and count the actual upstream dispatches."""

import hashlib
import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

UPSTREAM = "http://upstream:8000/mcp"

# Example rules for one convention: callers with the support role may call tools
# the operator marked read-only, and only operators may call anything else.
# The gateway ships none of these; the test installs them.
EXAMPLE_RULES = """
@id("support-read")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("support") && resource.reviewed.flags.contains({name: "readOnly", value: true}) };

@id("operator-call")
permit (principal, action == Action::"tools/call", resource)
when { principal.roles.contains("operator") };

@id("operator-required-for-changes")
forbid (principal, action == Action::"tools/call", resource)
when { !resource.reviewed.flags.contains({name: "readOnly", value: true}) && !principal.roles.contains("operator") };
"""
EXAMPLE_CHECKS = [
    {"caller": {"issuer": "local", "subject": "support", "roles": ["support"]},
     "proxy": "governed", "upstream": "http://upstream.invalid/mcp", "tool": "lookup",
     "hypotheticalTool": {"facts": {"readOnly": True}}, "expect": "permitted"},
    {"caller": {"issuer": "local", "subject": "support", "roles": ["support"]},
     "proxy": "governed", "upstream": "http://upstream.invalid/mcp", "tool": "update",
     "hypotheticalTool": {}, "expect": "policy_denied"},
]


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


# The policy store holds immutable sets and an active pointer, and the gateway
# reports the set it enforces. The probe publishes sets in the documented store
# format and waits for that report, so every outcome is observed, not assumed.
POLICY = Path("/policy")
STATUS = Path("/status/status.json")
FILES = ("rules.cedar", "tools.json", "checks.json")
rules, tools, checks = (Path(name) for name in FILES)
staged = {}


def digest(data):
    return hashlib.sha256(data.encode()).hexdigest()


def write_set(contents, manifest_files=None):
    hashes = {name: digest(contents[name]) for name in FILES}
    set_id = digest("".join(f"{name}\n{hashes[name]}\n" for name in FILES))
    final = POLICY / "sets" / set_id
    if not final.exists():
        staging = POLICY / "sets" / f".staging-{set_id}"
        staging.mkdir()
        for name in FILES:
            (staging / name).write_text(contents[name])
        manifest = {"format": 1, "files": manifest_files or hashes}
        (staging / "manifest.json").write_text(json.dumps(manifest))
        staging.rename(final)
    return set_id


def point_to(set_id, expect):
    pointer = POLICY / ".active-next"
    pointer.write_text(json.dumps({"set": set_id}))
    pointer.replace(POLICY / "active")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            report = json.loads(STATUS.read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            report = {}
        if report.get("active") == set_id and report.get("outcome") == expect:
            if expect == "activated":
                assert report["enforcing"] == set_id, report
            return report
        time.sleep(0.05)
    raise AssertionError(f"set {set_id} was not {expect}: {report}")


def publish(expect="activated", **files):
    for name, text in files.items():
        staged[f"{name}.cedar" if name == "rules" else f"{name}.json"] = text
    return point_to(write_set(staged), expect)


def replace(path, text, expect="activated"):
    return publish(expect, **{path.stem: text})


def publish_inventory(tools, upstream=UPSTREAM, expect="activated"):
    publish(expect, tools=json.dumps({"governed": {"upstream": upstream, "tools": tools}}))


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

# The gateway ships a store whose active set has no rules, tools, or checks,
# and it reports enforcing that set.
shipped = json.loads((POLICY / "active").read_text())["set"]
assert sorted(path.name for path in POLICY.iterdir() if not path.name.startswith(".")) == ["active", "sets"]
assert sorted(path.name for path in (POLICY / "sets" / shipped).iterdir()) == sorted(FILES + ("manifest.json",))
staged.update({name: (POLICY / "sets" / shipped / name).read_text() for name in FILES})
assert staged["rules.cedar"].strip() == "", "the gateway must ship without rules"
assert json.loads(staged["tools.json"]) == {} and json.loads(staged["checks.json"]) == [], staged
point_to(shipped, "activated")
call(operator, "lookup", {})

# A denial alone cannot show that an empty file was accepted, because an
# unavailable evaluator also denies. Each empty file is swapped in while a
# permitting configuration is active instead: a rejected file would leave that
# configuration in force. The first permit relies on the shipped empty checks.
inventory = {"lookup": {"facts": {"readOnly": True}, "definition": catalog["lookup"],
                        "arguments": {"count": "long"}}}
publish_inventory(inventory)
initial = EXAMPLE_RULES
replace(rules, initial)
call(support, "lookup", {}, "found")
replace(rules, "")
call(operator, "lookup", {})
replace(rules, initial)
call(operator, "lookup", {}, "found")
replace(tools, "{}")
call(operator, "lookup", {})
publish_inventory(inventory)
call(operator, "lookup", {}, "found")
# A null tool entry is rejected rather than treated as a reviewed tool.
publish_inventory(dict(inventory, change=None), expect="rejected")
call(operator, "change", {"count": 2})

# A rejected candidate keeps the last good configuration.
publish_inventory(inventory)
replace(checks, json.dumps(EXAMPLE_CHECKS))
replace(rules, "invalid", "rejected")
call(operator, "lookup", {}, "found")
replace(rules, initial)
call(support, "lookup", {}, "found")
# Null checks are not an empty list: alongside empty rules they are rejected.
publish("rejected", checks="null", rules="")
call(operator, "lookup", {}, "found")
publish(checks=json.dumps(EXAMPLE_CHECKS), rules=initial)
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

# Onboard the real tool without facts. Under the example rules a tool not marked
# read-only is reserved for operators whatever the upstream declares, and the
# upstream declaration can further restrict the operator's call.
inventory["change"] = {"arguments": {"count": "long"}}
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
publish_inventory(dict(inventory, change={"argumants": {"count": "long"}}), expect="rejected")
call(operator, "change", {"count": 2})
publish_inventory(inventory)
replace(rules, "forbid(principal, action, resource);", "rejected")
call(guest, "lookup", {"count": 3}, "found")
replace(rules, initial + 'permit(principal, action, resource) when {principal.missing == "yes"};', "rejected")
call(operator, "change", {"count": 2})
# The operator can delegate a reviewed mutation to the same guest denied above.
delegated = """
permit (principal, action, resource) when {
  (principal.roles.contains("support") && resource.reviewed.flags.contains({name: "readOnly", value: true})) ||
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

# Rules can match each kind of operator-defined fact. An invalid fact value
# rejects the whole inventory and keeps the last good configuration.
inventory["lookup"]["facts"].update({"risk": "low", "tier": 1})
inventory["lookup"]["tags"] = ["directory"]
publish_inventory(inventory)
replace(rules, delegated + """
permit (principal, action, resource) when {
  principal.roles.contains("guest") &&
  resource.reviewed.strings.contains({name: "risk", value: "low"}) &&
  resource.reviewed.numbers.contains({name: "tier", value: 1}) &&
  resource.reviewed.tags.contains("directory")
};
""")
call(guest, "lookup", {}, "found")
call(guest, "change", {})
publish_inventory(dict(inventory, lookup={"facts": {"readOnly": True}}, change={"facts": {"weight": 1.5}}), expect="rejected")
call(guest, "lookup", {}, "found")
# A set whose files do not match its manifest is still being published: the
# gateway reports it as not ready and keeps enforcing the current set.
mismatched = dict(staged, **{"rules.cedar": "permit (principal, action, resource);"})
point_to(write_set(mismatched, manifest_files={name: digest(staged[name]) for name in FILES}), "not_ready")
call(guest, "lookup", {}, "found")
call(guest, "change", {})
print("Verified Cedar access and upstream dispatch with a Go MCP server.")
