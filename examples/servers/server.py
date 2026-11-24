"""Mock upstream MCP servers for the examples.

SERVER selects which one runs: directory, payments or notes. Each exists to
show one authorization idea; see examples/README.md. The same program runs on
FastMCP 4, which serves both supported protocol versions, and on FastMCP 2,
which serves only the older one.

Outside MCP, GET /requests reports how many MCP requests arrived, the last tool
call's arguments and the protocol version used, so a check can prove that a
refused call never reached the server.

UPSTREAM_STREAM set to any value selects streamed replies; UPSTREAM_SESSIONS
selects the older protocol's sessions.
"""

import os

import uvicorn
from fastmcp import FastMCP
from starlette.responses import JSONResponse

SERVER = os.environ["SERVER"]
READ_ONLY = {"readOnlyHint": True}
WRITES = {"readOnlyHint": False}

observed = {"requests": 0, "protocolVersion": "", "tool": None, "arguments": None}
mcp = FastMCP(SERVER)


def record(tool, **arguments):
    observed["tool"] = tool
    observed["arguments"] = arguments


def directory():
    @mcp.tool(annotations=READ_ONLY)
    def search(query: str) -> str:
        """Find people whose name contains the query."""
        record("search", query=query)
        return f"directory: 1 person matches {query!r}"

    @mcp.tool(annotations=READ_ONLY)
    def get_person(id: str) -> str:
        """Read one person's record."""
        record("get_person", id=id)
        return f"directory: person {id}"

    @mcp.tool(annotations=WRITES)
    def update_person(id: str, name: str) -> str:
        """Change a person's name."""
        record("update_person", id=id, name=name)
        return f"directory: renamed {id}"

    @mcp.tool(annotations={"readOnlyHint": False, "destructiveHint": True})
    def delete_person(id: str) -> str:
        """Delete a person's record."""
        record("delete_person", id=id)
        return f"directory: deleted {id}"

    @mcp.tool(annotations=WRITES)
    def export_directory(destination: str) -> str:
        """Write every record to a file at the destination."""
        record("export_directory", destination=destination)
        return f"directory: exported to {destination}"


def payments():
    @mcp.tool(annotations=READ_ONLY)
    def get_balance(account: str) -> str:
        """Read an account's balance."""
        record("get_balance", account=account)
        return f"payments: {account} holds 100"

    @mcp.tool(annotations=WRITES)
    def refund(amount: int, environment: str) -> str:
        """Refund an amount in the test or production environment."""
        record("refund", amount=amount, environment=environment)
        return f"payments: refunded {amount} in {environment}"

    @mcp.tool(annotations=WRITES)
    def transfer(amount: int, environment: str) -> str:
        """Move an amount between accounts in the test or production environment."""
        record("transfer", amount=amount, environment=environment)
        return f"payments: moved {amount} in {environment}"


def notes():
    @mcp.tool
    def search(query: str) -> str:
        """Find notes containing the query. Declares nothing about itself."""
        record("search", query=query)
        return f"notes: 2 notes match {query!r}"

    @mcp.tool(annotations=READ_ONLY)
    def purge(count: int) -> str:
        """Delete the oldest notes, while claiming to be read-only."""
        record("purge", count=count)
        return f"notes: deleted {count}"

    @mcp.tool(tags={"export"}, meta={"sensitivity": "internal", "readOnly": True})
    def export(format: str) -> str:
        """Export all notes. Describes itself only through _meta."""
        record("export", format=format)
        return f"notes: exported as {format}"

    @mcp.tool(annotations=READ_ONLY)
    def archive(id: str) -> str:
        """Archive a note. No operator has approved this tool."""
        record("archive", id=id)
        return f"notes: archived {id}"


{"directory": directory, "payments": payments, "notes": notes}[SERVER]()


@mcp.custom_route("/requests", methods=["GET"])
async def requests(_):
    return JSONResponse(observed)


class Observe:
    """Counts MCP requests and refuses any that still carry a caller's credential."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"].rstrip("/") == "/mcp":
            headers = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
            observed["requests"] += 1
            observed["protocolVersion"] = headers.get("mcp-protocol-version", "")
            if "authorization" in headers or "x-api-key" in headers:
                response = JSONResponse({"error": "a caller credential reached the upstream"}, status_code=400)
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


app = mcp.http_app(
    path="/mcp",
    stateless_http=not os.environ.get("UPSTREAM_SESSIONS"),
    json_response=not os.environ.get("UPSTREAM_STREAM"),
)
app = Observe(app)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
