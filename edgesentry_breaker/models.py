"""Data models for EdgeSentryBreaker testing framework."""

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional


class SignalCategory(str, Enum):
    """Detection signals defined in Section 4 of the plan."""
    S1 = "S1: IP 평판 (Datacenter/Tor/Proxy/Abuse)"
    S2 = "S2: 지리 일관성 (Impossible Travel)"
    S3 = "S3: 빈도·속도 (Velocity)"
    S4 = "S4: 계정-자산 연관성 (IP/Device Trust History)"
    S5 = "S5: 시간대 패턴 (Timezone/Working Hours)"
    S6 = "S6: 성공/실패 비율 (Success/Failure Ratio)"
    S7 = "S7: 분산도 (Target Dispersion)"


class DetectionVerdict(str, Enum):
    """Verdict inferred from server response."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    CHALLENGE = "CHALLENGE"
    FLAGGED = "FLAGGED"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


@dataclass
class DetectionRequest:
    """Request payload sent to POST /v1/detect."""
    ip: str
    account_id: str
    login_result: str = "success"
    headers: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    delay_before_seconds: float = 0.0

    def to_payload(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "account_id": self.account_id,
            "login_result": self.login_result,
        }


@dataclass
class DetectionResponse:
    """Parsed response from detection server."""
    status_code: int
    verdict: DetectionVerdict
    latency_ms: float
    body: Any = None
    raw_text: str = ""
    error_message: Optional[str] = None


@dataclass
class StepResult:
    """Result of a single request step within a scenario."""
    step_index: int
    request: DetectionRequest
    response: DetectionResponse
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_index": self.step_index,
            "timestamp": self.timestamp,
            "ip": self.request.ip,
            "account_id": self.request.account_id,
            "login_result": self.request.login_result,
            "metadata": self.request.metadata,
            "status_code": self.response.status_code,
            "verdict": self.response.verdict.value,
            "latency_ms": round(self.response.latency_ms, 2),
            "response_body": self.response.body,
            "error_message": self.response.error_message,
        }


@dataclass
class ScenarioOutcome:
    """Aggregated outcome of executing a test scenario."""
    scenario_id: str
    name: str
    target_signals: List[str]
    hypothesis: str
    validation_method: str
    steps: List[StepResult] = field(default_factory=list)
    total_requests: int = 0
    allow_count: int = 0
    block_count: int = 0
    challenge_count: int = 0
    error_count: int = 0
    detection_observed: bool = False
    evasion_successful: bool = False
    notes: str = ""

    def compute_aggregates(self) -> None:
        self.total_requests = len(self.steps)
        self.allow_count = sum(1 for s in self.steps if s.response.verdict == DetectionVerdict.ALLOW)
        self.block_count = sum(1 for s in self.steps if s.response.verdict in (DetectionVerdict.BLOCK, DetectionVerdict.FLAGGED))
        self.challenge_count = sum(1 for s in self.steps if s.response.verdict == DetectionVerdict.CHALLENGE)
        self.error_count = sum(1 for s in self.steps if s.response.verdict == DetectionVerdict.ERROR)
        self.detection_observed = (self.block_count + self.challenge_count) > 0


@dataclass
class SignalCoverageResult:
    """Coverage status for each signal category (S1-S7)."""
    signal_code: str
    signal_name: str
    related_scenarios: List[str]
    reaction_observed: bool
    notes: str


@dataclass
class RunReport:
    """Full execution report containing all scenario outcomes and metrics."""
    run_id: str
    target_url: str
    start_time: str
    end_time: str
    duration_seconds: float
    scenarios: List[ScenarioOutcome] = field(default_factory=list)
    signal_coverages: List[SignalCoverageResult] = field(default_factory=list)
    total_requests: int = 0
    total_blocked: int = 0
    total_allowed: int = 0
    detection_rate: float = 0.0
    evasion_rate: float = 0.0
    false_positive_detected: bool = False
    blind_spots: List[str] = field(default_factory=list)
