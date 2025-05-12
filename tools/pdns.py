from datetime import datetime
from agents import function_tool
from pydantic import BaseModel

from .base import fetch_fdp_api


class PDNSRecord(BaseModel):
    rrname: str
    rdata: str
    rrtype: str
    count: int
    fseen: datetime
    lseen: datetime


@function_tool
async def pdns_lookup(domain: str) -> list[PDNSRecord]:
    """Fetch the PassiveDNS records for a given domain name.

    Args:
        domain: The Domain name to fetch the PDNS records for.

    """
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
    return records
