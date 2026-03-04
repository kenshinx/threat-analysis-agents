from datetime import datetime
from agents import function_tool
from pydantic import BaseModel
from typing import Any, Optional

from .base import fetch_fdp_api


class NetworkActivity(BaseModel):
    """Network activity observed during sandbox analysis."""
    protocol: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    domain: Optional[str] = None
    url: Optional[str] = None


class FileActivity(BaseModel):
    """File system activity observed during sandbox analysis."""
    action: str  # created, modified, deleted
    path: str
    file_type: Optional[str] = None


class RegistryActivity(BaseModel):
    """Registry activity observed during sandbox analysis."""
    action: str  # created, modified, deleted
    key: str
    value: Optional[str] = None


class SandboxAnalysisResult(BaseModel):
    """Sandbox dynamic analysis result."""
    hash: str
    analysis_id: Optional[str] = None
    verdict: str  # malicious, suspicious, clean, unknown
    score: int = 0  # 0-100
    analysis_time: Optional[datetime] = None
    sandbox_type: Optional[str] = None

    # Behavioral indicators
    network_activities: list[NetworkActivity] = []
    file_activities: list[FileActivity] = []
    registry_activities: list[RegistryActivity] = []
    processes_created: list[str] = []

    # Malicious behaviors detected
    behaviors: list[str] = []
    mitre_techniques: list[str] = []

    # Additional metadata
    additional_info: dict[str, Any] = {}


@function_tool
async def sandbox_analysis(file_hash: str) -> SandboxAnalysisResult:
    """Retrieve sandbox dynamic analysis results for a given file hash.

    This tool fetches behavioral analysis data from automated malware sandbox environments:
    - Verdict and maliciousness score
    - Network communications (IPs, domains, URLs contacted)
    - File system modifications
    - Registry changes
    - Process execution chains
    - MITRE ATT&CK techniques observed
    - Malicious behavior indicators

    Args:
        file_hash: The file hash (MD5, SHA1, or SHA256) to retrieve sandbox results for.

    Returns:
        A SandboxAnalysisResult object containing detailed behavioral analysis.
    """
    path = f"/api/v1/sandbox/{file_hash}"

    try:
        data = await fetch_fdp_api(path)

        # Parse network activities
        network_activities = []
        for net in data.get('network_activities', []):
            network_activities.append(NetworkActivity(
                protocol=net.get('protocol', 'unknown'),
                src_ip=net.get('src_ip'),
                dst_ip=net.get('dst_ip'),
                dst_port=net.get('dst_port'),
                domain=net.get('domain'),
                url=net.get('url')
            ))

        # Parse file activities
        file_activities = []
        for file in data.get('file_activities', []):
            file_activities.append(FileActivity(
                action=file.get('action', 'unknown'),
                path=file.get('path', ''),
                file_type=file.get('file_type')
            ))

        # Parse registry activities
        registry_activities = []
        for reg in data.get('registry_activities', []):
            registry_activities.append(RegistryActivity(
                action=reg.get('action', 'unknown'),
                key=reg.get('key', ''),
                value=reg.get('value')
            ))

        result = SandboxAnalysisResult(
            hash=file_hash,
            analysis_id=data.get('analysis_id'),
            verdict=data.get('verdict', 'unknown'),
            score=data.get('score', 0),
            analysis_time=datetime.fromtimestamp(data['analysis_time']) if data.get('analysis_time') else None,
            sandbox_type=data.get('sandbox_type'),
            network_activities=network_activities,
            file_activities=file_activities,
            registry_activities=registry_activities,
            processes_created=data.get('processes_created', []),
            behaviors=data.get('behaviors', []),
            mitre_techniques=data.get('mitre_techniques', []),
            additional_info=data.get('additional_info', {})
        )

        return result

    except Exception as e:
        # If not found or error, return minimal result
        return SandboxAnalysisResult(
            hash=file_hash,
            verdict='unknown',
            additional_info={"error": str(e), "note": "Sandbox analysis not available or API error occurred"}
        )
