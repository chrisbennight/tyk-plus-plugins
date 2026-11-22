from mcp.server.fastmcp import FastMCP

server = FastMCP("Example", host="0.0.0.0", stateless_http=True, json_response=True)


@server.tool()
def echo(message: str) -> str:
    """Return the message unchanged."""
    return message


if __name__ == "__main__":
    server.run(transport="streamable-http")
