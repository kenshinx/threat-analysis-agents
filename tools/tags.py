from datetime import datetime
from agents import function_tool
from pydantic import BaseModel
from typing import Any


from .base import fetch_fdp_api


class TagRecord(BaseModel):
    category: str
    category_cn: str
    desc: dict[str, Any]
    name: str
    title: str
    title_cn: str
    type: str
    type_cn: str
    severity: int
    ctime: datetime
    utime: datetime


class EntityRecord(BaseModel):
    entity: str
    type: str
    confidence: int
    severity: int
    ctime: datetime
    etime: datetime
    detail: dict[str, Any]
    tag: TagRecord


@function_tool
async def tags_lookup(entity: str) -> list[EntityRecord]:
    """Fetch the Tags records for a given domain name, ip address or sample sha1.

    Args:
        entity: The Domain name, ip address or sample sha1 to fetch the Tags records for. 
                Can query multiple records at once by separating them with commas.

    Returns:
        A list of EntityRecord objects containing the tags records.
    """
    path = "/api/v1/entity"
    parameter = {"entity": entity}
    data = await fetch_fdp_api(path, parameter=parameter)
    records = []
    for item in data:
        tag_data = item['tag']
        tag_record = TagRecord(
            category=tag_data.get('category', ''),
            category_cn=tag_data.get('category_cn', ''),
            desc=tag_data.get('desc', {}),
            name=tag_data.get('name', ''),
            title=tag_data.get('title', ''),
            title_cn=tag_data.get('type_cn', ''),
            type=tag_data.get('type', ''),
            type_cn=tag_data.get('type_cn', ''),
            severity=tag_data.get('severity', 0),
            ctime=datetime.fromtimestamp(tag_data.get('ctime', 0)),
            utime=datetime.fromtimestamp(tag_data.get('utime', 0))
        )

        entity_record = EntityRecord(
            entity=item['entity'],
            type=item['type'],
            confidence=item['confidence'],
            severity=tag_data['severity'],
            ctime=datetime.fromtimestamp(item['ctime']),
            etime=datetime.fromtimestamp(item['etime']),
            detail=item.get('detail', {}),
            tag=tag_record
        )

        records.append(entity_record)

    return records
