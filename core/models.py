from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


@dataclass
class Service:
    port: int
    protocol: str
    state: str
    service: str
    version: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class Finding:
    title: str
    category: str
    severity: str = "info"
    impact: float = 1.0
    exploitability: float = 1.0
    confidence: float = 0.5
    exposure: float = 1.0
    evidence: str = ""
    source_tool: str = ""
    target: str = ""
    recommendation: str = "Review and validate this finding."
    metadata: Dict[str, Any] = field(default_factory=dict)
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    score: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()

@dataclass
class CorrelationGroup:
    target: str
    key: str
    findings: List[Finding] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    confidence: float = 0.0

    def as_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "key": self.key,
            "findings": [f.as_dict() for f in self.findings],
            "sources": self.sources,
            "confidence": self.confidence,
        }
    
@dataclass
class ToolResult:
    tool: str
    category: str
    target: str
    started_at: str
    finished_at: str
    return_code: Optional[int]
    stdout: str = ""
    stderr: str = ""
    duration_seconds: float = 0.0
    status: str = "success"
    command: List[str] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        data = self.__dict__.copy()
        data["services"] = [s.as_dict() for s in self.services]
        data["findings"] = [f.as_dict() for f in self.findings]
        return data


@dataclass
class Session:
    target: str
    profile: str
    started_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    results: List[ToolResult] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    session_id: str = field(
        default_factory=lambda: datetime.now().strftime("%Y%m%d_%H%M%S")
    )

    def as_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target": self.target,
            "profile": self.profile,
            "started_at": self.started_at,
            "results": [r.as_dict() for r in self.results],
            "notes": self.notes,
        }