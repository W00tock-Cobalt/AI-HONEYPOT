"""Data models for SQLi-AI scans."""

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
    NOSQL = "nosql"
    XPATH = "xpath"
    UNKNOWN = "unknown"


class ParamLocation(str, Enum):
    QUERY = "query"
    BODY = "body"
    HEADER = "header"
    COOKIE = "cookie"
    JSON = "json"
    PATH = "path"


@dataclass
class InjectionPoint:
    """A parameter that will be tested for SQL injection."""
    name: str
    location: ParamLocation
    original_value: str
    json_path: Optional[str] = None   # e.g. "user.name" for nested JSON bodies
    path_index: Optional[int] = None  # URL path segment index for PATH injection
    # True when this point came from generic wordlist mining (guess_params),
    # as opposed to a real URL/organic/spec param. Used to avoid running the
    # expensive blind battery on dozens of speculative guessed params.
    mined: bool = False


@dataclass
class HttpExchange:
    """One HTTP request/response pair captured during scanning."""
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
    # Set by scanner when payload is a time-based probe; used by detector
    # to calibrate the timing threshold.
    expected_sleep_ms: Optional[float] = None


@dataclass
class AgentDecision:
    """What the LLM agent decided to do next."""
    action: str  # "inject" | "confirm" | "skip" | "done"
    payload: Optional[str] = None
    injection_type: Optional[InjectionType] = None
    reasoning: str = ""
    confidence: float = 0.0
    db_hint: Optional[str] = None


@dataclass
class Finding:
    """A confirmed (or suspected) SQL injection vulnerability."""
    param: str
    location: ParamLocation
    injection_type: InjectionType
    severity: Severity
    payload: str
    evidence: str
    confidence: float
    db_type: Optional[str] = None
    reasoning: str = ""
    poc_curl: str = ""      # Ready-to-run curl PoC command
    poc_request: str = ""   # Raw HTTP request for the confirming exchange
    # Before/after evidence: the clean baseline vs. the injected response so a
    # reviewer can see exactly what the payload changed.
    response_before: str = ""   # "HTTP <code>\n<snippet>" for the baseline
    response_after: str = ""    # "HTTP <code>\n<snippet>" for the injected req
    payload_url: str = ""       # The exact URL/target the payload hit
    # AI post-confirmation analysis (impact/exploitation/remediation). Populated
    # only when the LLM is enabled; never affects detection.
    ai_analysis: str = ""


@dataclass
class ScanReport:
    """Complete results of one target scan."""
    target_url: str
    injection_points: list[InjectionPoint] = field(default_factory=list)
    exchanges: list[HttpExchange] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    agent_log: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    llm_model: str = ""
    total_requests: int = 0

    def __post_init__(self):
        import threading
        # Lock used by scanner when multiple param-test threads write to this report
        self._lock: threading.Lock = threading.Lock()

    def add_request(self, exchange: Optional["HttpExchange"] = None) -> None:
        """Thread-safe request counter increment."""
        with self._lock:
            self.total_requests += 1
            if exchange is not None:
                self.exchanges.append(exchange)

    def add_error(self, msg: str) -> None:
        """Thread-safe error append."""
        with self._lock:
            self.errors.append(msg)

    def add_log(self, msg: str) -> None:
        """Thread-safe agent log append."""
        with self._lock:
            self.agent_log.append(msg)
