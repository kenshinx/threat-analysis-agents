from datetime import datetime
from agents import function_tool
from pydantic import BaseModel
from typing import Any, Optional

from .base import fetch_fdp_api


class CVSSScore(BaseModel):
    """CVSS scoring information."""
    version: str  # 2.0, 3.0, 3.1
    base_score: float
    temporal_score: Optional[float] = None
    environmental_score: Optional[float] = None
    vector_string: str
    severity: str  # low, medium, high, critical


class AffectedProduct(BaseModel):
    """Product affected by vulnerability."""
    vendor: str
    product: str
    version_range: str
    platform: Optional[str] = None


class CVERecord(BaseModel):
    """CVE vulnerability record."""
    cve_id: str
    description: str
    published_date: Optional[datetime] = None
    last_modified_date: Optional[datetime] = None

    # Scoring
    cvss_v2: Optional[CVSSScore] = None
    cvss_v3: Optional[CVSSScore] = None

    # Affected products
    affected_products: list[AffectedProduct] = []

    # Vulnerability details
    cwe_ids: list[str] = []
    vulnerability_types: list[str] = []
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None

    # References
    references: list[str] = []
    additional_info: dict[str, Any] = {}


class ExploitInfo(BaseModel):
    """Exploit availability information."""
    exploit_available: bool = False
    exploit_maturity: str = "unknown"  # unproven, proof-of-concept, functional, high
    exploit_sources: list[str] = []
    exploit_count: int = 0
    metasploit_modules: list[str] = []
    exploit_db_ids: list[str] = []
    in_the_wild: bool = False
    ransomware_campaigns: list[str] = []
    additional_info: dict[str, Any] = {}


class PatchInfo(BaseModel):
    """Patch and mitigation information."""
    patch_available: bool = False
    vendor_advisories: list[str] = []
    patch_urls: list[str] = []
    workarounds: list[str] = []
    mitigation_recommendations: list[str] = []
    patch_complexity: Optional[str] = None
    additional_info: dict[str, Any] = {}


@function_tool
async def cve_lookup(cve_id: str) -> CVERecord:
    """Retrieve detailed information about a CVE (Common Vulnerabilities and Exposures).

    This tool fetches comprehensive vulnerability intelligence including:
    - CVE description and timeline
    - CVSS severity scores (v2 and v3)
    - Affected products and versions
    - CWE (Common Weakness Enumeration) classifications
    - Attack vector and complexity
    - Reference links and advisories

    Args:
        cve_id: The CVE identifier (e.g., "CVE-2023-1234" or "2023-1234").

    Returns:
        A CVERecord object containing detailed vulnerability information.
    """
    # Normalize CVE ID format
    if not cve_id.upper().startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    path = f"/api/v1/cve/{cve_id}"

    try:
        data = await fetch_fdp_api(path)

        # Parse CVSS v2
        cvss_v2 = None
        if data.get('cvss_v2'):
            cvss_v2_data = data['cvss_v2']
            cvss_v2 = CVSSScore(
                version="2.0",
                base_score=cvss_v2_data.get('base_score', 0.0),
                temporal_score=cvss_v2_data.get('temporal_score'),
                environmental_score=cvss_v2_data.get('environmental_score'),
                vector_string=cvss_v2_data.get('vector_string', ''),
                severity=cvss_v2_data.get('severity', 'unknown')
            )

        # Parse CVSS v3
        cvss_v3 = None
        if data.get('cvss_v3'):
            cvss_v3_data = data['cvss_v3']
            cvss_v3 = CVSSScore(
                version=cvss_v3_data.get('version', '3.1'),
                base_score=cvss_v3_data.get('base_score', 0.0),
                temporal_score=cvss_v3_data.get('temporal_score'),
                environmental_score=cvss_v3_data.get('environmental_score'),
                vector_string=cvss_v3_data.get('vector_string', ''),
                severity=cvss_v3_data.get('severity', 'unknown')
            )

        # Parse affected products
        affected_products = []
        for product in data.get('affected_products', []):
            affected_products.append(AffectedProduct(
                vendor=product.get('vendor', 'unknown'),
                product=product.get('product', 'unknown'),
                version_range=product.get('version_range', ''),
                platform=product.get('platform')
            ))

        record = CVERecord(
            cve_id=cve_id,
            description=data.get('description', 'No description available'),
            published_date=datetime.fromisoformat(data['published_date']) if data.get('published_date') else None,
            last_modified_date=datetime.fromisoformat(data['last_modified_date']) if data.get('last_modified_date') else None,
            cvss_v2=cvss_v2,
            cvss_v3=cvss_v3,
            affected_products=affected_products,
            cwe_ids=data.get('cwe_ids', []),
            vulnerability_types=data.get('vulnerability_types', []),
            attack_vector=data.get('attack_vector'),
            attack_complexity=data.get('attack_complexity'),
            privileges_required=data.get('privileges_required'),
            user_interaction=data.get('user_interaction'),
            references=data.get('references', []),
            additional_info=data.get('additional_info', {})
        )

        return record

    except Exception as e:
        # If not found or error, return minimal record
        return CVERecord(
            cve_id=cve_id,
            description=f"CVE information not available: {str(e)}",
            additional_info={"error": str(e), "note": "CVE not found in database or API error occurred"}
        )


@function_tool
async def exploit_check(cve_id: str) -> ExploitInfo:
    """Check exploit availability and in-the-wild usage for a CVE.

    This tool queries exploit databases and threat intelligence to determine:
    - Whether public exploits exist
    - Exploit maturity level (PoC vs weaponized)
    - Exploit sources (Metasploit, Exploit-DB, GitHub, etc.)
    - Evidence of in-the-wild exploitation
    - Association with ransomware campaigns
    - Active exploitation by threat actors

    Args:
        cve_id: The CVE identifier (e.g., "CVE-2023-1234" or "2023-1234").

    Returns:
        An ExploitInfo object containing exploit availability and usage intelligence.
    """
    # Normalize CVE ID format
    if not cve_id.upper().startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    path = f"/api/v1/exploit/{cve_id}"

    try:
        data = await fetch_fdp_api(path)

        exploit_info = ExploitInfo(
            exploit_available=data.get('exploit_available', False),
            exploit_maturity=data.get('exploit_maturity', 'unknown'),
            exploit_sources=data.get('exploit_sources', []),
            exploit_count=data.get('exploit_count', 0),
            metasploit_modules=data.get('metasploit_modules', []),
            exploit_db_ids=data.get('exploit_db_ids', []),
            in_the_wild=data.get('in_the_wild', False),
            ransomware_campaigns=data.get('ransomware_campaigns', []),
            additional_info=data.get('additional_info', {})
        )

        return exploit_info

    except Exception as e:
        # If not found or error, return minimal info
        return ExploitInfo(
            exploit_available=False,
            additional_info={"error": str(e), "note": "Exploit information not available or API error occurred"}
        )


@function_tool
async def patch_check(cve_id: str) -> PatchInfo:
    """Retrieve patch availability and mitigation guidance for a CVE.

    This tool fetches patch and remediation intelligence including:
    - Patch availability status
    - Vendor security advisories
    - Official patch download URLs
    - Workarounds and temporary mitigations
    - Recommended remediation actions
    - Patch deployment complexity

    Args:
        cve_id: The CVE identifier (e.g., "CVE-2023-1234" or "2023-1234").

    Returns:
        A PatchInfo object containing patch availability and mitigation guidance.
    """
    # Normalize CVE ID format
    if not cve_id.upper().startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    path = f"/api/v1/patch/{cve_id}"

    try:
        data = await fetch_fdp_api(path)

        patch_info = PatchInfo(
            patch_available=data.get('patch_available', False),
            vendor_advisories=data.get('vendor_advisories', []),
            patch_urls=data.get('patch_urls', []),
            workarounds=data.get('workarounds', []),
            mitigation_recommendations=data.get('mitigation_recommendations', []),
            patch_complexity=data.get('patch_complexity'),
            additional_info=data.get('additional_info', {})
        )

        return patch_info

    except Exception as e:
        # If not found or error, return minimal info
        return PatchInfo(
            patch_available=False,
            additional_info={"error": str(e), "note": "Patch information not available or API error occurred"}
        )
