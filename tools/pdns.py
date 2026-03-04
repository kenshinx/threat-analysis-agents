from datetime import datetime
from agents import function_tool
from pydantic import BaseModel
import os

from .base import fetch_fdp_api

# Configurable limits to prevent context overflow
# Can be adjusted via environment variable or changed based on your LLM's context window
MAX_PDNS_RECORDS = int(os.getenv("MAX_PDNS_RECORDS", "50"))  # Reduced from 200 to 50
DEFAULT_RECORD_LIMIT = 50  # Default limit for most queries
EXTENDED_RECORD_LIMIT = 100  # Extended limit for detailed analysis


class PDNSRecord(BaseModel):
    rrname: str
    rdata: str
    rrtype: str
    count: int
    fseen: datetime
    lseen: datetime


@function_tool
async def pdns_lookup(domain: str, limit: int = DEFAULT_RECORD_LIMIT) -> list[PDNSRecord]:
    """Fetch the PassiveDNS records for a given domain name.

    This tool retrieves historical DNS resolution records to analyze past IP associations,
    hosting patterns, and domain behavior over time. Useful for:
    - Identifying historical IP resolutions
    - Detecting domain fast-flux patterns
    - Analyzing hosting provider changes
    - Discovering malicious infrastructure patterns

    Args:
        domain: The Domain name to fetch the PDNS records for.
        limit: Maximum number of records to return (default: 50, max: 100).
               Lower limits reduce context usage and improve performance.

    Returns:
        A list of PDNSRecord objects containing historical DNS data, sorted by most recent.
    """
    # Enforce maximum limit to prevent context overflow
    limit = min(limit, MAX_PDNS_RECORDS)

    path = "/v3/flint/rrset/" + domain
    data = await fetch_fdp_api(path)

    records = []
    for item in data:
        r = PDNSRecord(
            rrname=item["rrname"],
            rdata=item["rdata"],
            rrtype=item["rrtype"],
            count=item["count"],
            fseen=datetime.fromtimestamp(item["time_first"]),
            lseen=datetime.fromtimestamp(item["time_last"])
        )
        records.append(r)

    # Sort by last seen (most recent first) for better relevance
    records.sort(key=lambda x: x.lseen, reverse=True)

    # Return limited number of records
    return records[:limit]
