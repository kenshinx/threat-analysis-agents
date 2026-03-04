from datetime import datetime
from agents import function_tool
from pydantic import BaseModel
from typing import Any, Optional

from .base import fetch_fdp_api


class YaraRuleMatch(BaseModel):
    """A single YARA rule match result."""
    rule_name: str
    rule_category: Optional[str] = None
    description: Optional[str] = None
    author: Optional[str] = None
    reference: Optional[str] = None
    severity: str = "medium"  # low, medium, high, critical
    tags: list[str] = []
    matched_strings: list[str] = []
    metadata: dict[str, Any] = {}


class YaraMatchResult(BaseModel):
    """YARA scanning result for a file hash."""
    hash: str
    total_matches: int = 0
    scan_time: Optional[datetime] = None
    matches: list[YaraRuleMatch] = []
    threat_classification: Optional[str] = None
    additional_info: dict[str, Any] = {}


@function_tool
async def yara_match(file_hash: str) -> YaraMatchResult:
    """Retrieve YARA rule matches for a given file hash.

    This tool queries YARA signature databases to identify:
    - Matched YARA rules and their metadata
    - Malware family/type classification
    - Specific patterns detected in the file
    - Rule authors and references
    - Threat severity levels
    - Matched string patterns

    YARA rules are used to identify and classify malware based on textual or binary patterns.

    Args:
        file_hash: The file hash (MD5, SHA1, or SHA256) to check against YARA rules.

    Returns:
        A YaraMatchResult object containing all matched YARA rules and details.
    """
    path = f"/api/v1/yara/{file_hash}"

    try:
        data = await fetch_fdp_api(path)

        # Parse YARA rule matches
        matches = []
        for match in data.get('matches', []):
            yara_match = YaraRuleMatch(
                rule_name=match.get('rule_name', 'unknown'),
                rule_category=match.get('category'),
                description=match.get('description'),
                author=match.get('author'),
                reference=match.get('reference'),
                severity=match.get('severity', 'medium'),
                tags=match.get('tags', []),
                matched_strings=match.get('matched_strings', []),
                metadata=match.get('metadata', {})
            )
            matches.append(yara_match)

        result = YaraMatchResult(
            hash=file_hash,
            total_matches=len(matches),
            scan_time=datetime.fromtimestamp(data['scan_time']) if data.get('scan_time') else None,
            matches=matches,
            threat_classification=data.get('threat_classification'),
            additional_info=data.get('additional_info', {})
        )

        return result

    except Exception as e:
        # If not found or error, return minimal result
        return YaraMatchResult(
            hash=file_hash,
            total_matches=0,
            additional_info={"error": str(e), "note": "YARA scan results not available or API error occurred"}
        )
