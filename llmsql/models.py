"""Data models for LLMSQL scans."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class InjectionType(str, Enum):
    ERROR_BASED = "error_based"
    BOOLEAN_BLIND = "boolean_blind"
    TIME_BLIND = "time_blind"
    UNION_BASED = "union_based"
    STACKED = "stacked"
    UNKNOWN = "unknown"


class ParamLocation(str, Enum):
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"
    JSON = "json"


@dataclass
class InjectionPoint:
    """A parameter that can be tested for SQL injection."""

    name: str
    location: ParamLocation
    original_value: str
    json_path: Optional[str] = None  # e.g. "user.name" for nested JSON


@dataclass
class HttpExchange:
    """Request/response pair for analysis."""

    method: str
    url: str
    status_code: int
    response_time_ms: float
    request_headers: dict[str, str]
    request_body: Optional[str]
    response_headers: dict[str, str]
    response_body: str
    injected_param: Optional[str] = None
    payload: Optional[str] = None


@dataclass
class AgentDecision:
    """LLM agent's next action."""

    action: str  # "inject", "confirm", "skip", "done"
    payload: Optional[str] = None
    injection_type: Optional[InjectionType] = None
    reasoning: str = ""
    confidence: float = 0.0
    db_hint: Optional[str] = None


@dataclass
class Finding:
    """Confirmed or suspected SQL injection."""

    param: str
    location: ParamLocation
    injection_type: InjectionType
    severity: Severity
    payload: str
    evidence: str
    confidence: float
    db_type: Optional[str] = None
    reasoning: str = ""


@dataclass
class ScanReport:
    """Complete scan results."""

    target_url: str
    injection_points: list[InjectionPoint] = field(default_factory=list)
    exchanges: list[HttpExchange] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    agent_log: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    llm_model: str = ""
    total_requests: int = 0
