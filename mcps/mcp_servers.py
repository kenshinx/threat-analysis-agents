import os
from dotenv import load_dotenv
from agents.mcp import MCPServerSse

load_dotenv()

XMCP_SERVER_URL = os.getenv("XMCP_SERVER_URL")
XMCP_SERVER_ACCESS = os.getenv("XMCP_SERVER_ACCESS")
XMCP_SERVER_SECRET = os.getenv("XMCP_SERVER_SECRET")

headers = {
    "fdp-access": XMCP_SERVER_ACCESS,
    "fdp-secret": XMCP_SERVER_SECRET
}

ip_mcp_server = MCPServerSse(
    name="IP mcp server, query IP related threat intelligence such as IP geo location",
    params={
        "url": XMCP_SERVER_URL+"/ip/sse",
        "headers": headers,
        "timeout": 15
    },
    cache_tools_list=True
)

domain_mcp_server = MCPServerSse(
    name="Domain mcp server, query domain related threat intelligence such as codomain, float, webdb",
    params={
        "url": XMCP_SERVER_URL+"/domain/sse",
        "headers": headers,
        "timeout": 15
    },
    cache_tools_list=True
)

basic_mcp_server = MCPServerSse(
    name="Basic mcp server, query basic threat intelligence for domains and IPs",
    params={
        "url": XMCP_SERVER_URL+"/basic/sse",
        "headers": headers,
        "timeout": 15
    },
    cache_tools_list=True
)
