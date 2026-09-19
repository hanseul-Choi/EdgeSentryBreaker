"""Scenario T1: 단발성 정상 요청 (Baseline Normal Request)."""

from typing import List
from edgesentry_breaker.config import Config
from edgesentry_breaker.models import (
    DetectionRequest,
    DetectionVerdict,
    ScenarioOutcome,
    SignalCategory,
)
from edgesentry_breaker.scenarios.base import BaseScenario


class ScenarioT1Baseline(BaseScenario):
    """T1: 단발성 정상 요청 검증."""

    scenario_id = "T1"
    name = "단발성 정상 요청 (기준선 검증)"
    hypothesis = "기존 이력 있는 정상 IP+계정 조합, 낮은 빈도의 1회 요청은 정상 통과(ALLOW)되어야 함"
    validation_method = "정상 주거용/사무실 형태의 IP로 1회 정상 로그인 요청 전송 후 응답 기록"
    target_signals = [SignalCategory.S4]

    def generate_requests(self, config: Config) -> List[DetectionRequest]:
        return [
            DetectionRequest(
                ip="203.0.113.10",
                account_id="test_user@example.com",
                login_result="success",
                metadata={"test_type": "baseline_normal", "expected_verdict": "ALLOW"},
            )
        ]

    def evaluate_outcome(self, outcome: ScenarioOutcome) -> None:
        super().evaluate_outcome(outcome)
        if outcome.total_requests > 0:
            first_step = outcome.steps[0]
            if first_step.response.verdict in (DetectionVerdict.BLOCK, DetectionVerdict.FLAGGED):
                outcome.notes = "CRITICAL: 정상 기준선 요청이 차단/플래그되었습니다 (오탐, False Positive 발생)."
            elif first_step.response.verdict == DetectionVerdict.ALLOW:
                outcome.notes = "정상 기준선 통과 확인 (정상 트래픽에 대한 오탐 없음)."
            else:
                outcome.notes = f"예상치 못한 응답 판정: {first_step.response.verdict.value}"
