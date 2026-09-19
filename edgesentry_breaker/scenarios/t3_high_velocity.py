"""Scenario T3: 고빈도 요청 (High Velocity Burst Requests)."""

from typing import List
from edgesentry_breaker.config import Config
from edgesentry_breaker.models import (
    DetectionRequest,
    DetectionVerdict,
    ScenarioOutcome,
    SignalCategory,
)
from edgesentry_breaker.scenarios.base import BaseScenario


class ScenarioT3HighVelocity(BaseScenario):
    """T3: 고빈도(Velocity) 요청 검증."""

    scenario_id = "T3"
    name = "고빈도 버스트 요청 (Velocity 임계값 검증)"
    hypothesis = "동일 IP에서 짧은 시간 내 다수의 요청 발생 시 Velocity/Rate-limiting 임계값(S3)에 의해 차단되는지 확인"
    validation_method = "동일 IP에서 간격 없이 10회의 연속 로그인 요청을 고속 전송 후 응답 코드(429/403 등) 및 판정 추적"
    target_signals = [SignalCategory.S3]

    BURST_COUNT = 10
    ATTACK_IP = "198.51.100.55"

    def generate_requests(self, config: Config) -> List[DetectionRequest]:
        requests = []
        for i in range(self.BURST_COUNT):
            requests.append(
                DetectionRequest(
                    ip=self.ATTACK_IP,
                    account_id=f"test_velocity_{i+1}@example.com",
                    login_result="success",
                    metadata={
                        "test_type": "high_velocity_burst",
                        "burst_index": i + 1,
                    },
                    delay_before_seconds=0.0,  # no delay for burst
                )
            )
        return requests

    def evaluate_outcome(self, outcome: ScenarioOutcome) -> None:
        super().evaluate_outcome(outcome)
        first_block_idx = None
        for i, step in enumerate(outcome.steps):
            if step.response.verdict in (DetectionVerdict.BLOCK, DetectionVerdict.FLAGGED, DetectionVerdict.CHALLENGE):
                first_block_idx = i + 1
                break

        if first_block_idx is not None:
            outcome.notes = (
                f"Velocity 탐지 활성화: 동일 IP에서 {first_block_idx}번째 요청부터 "
                f"차단/플래그가 발생했습니다 (S3 작동 확인)."
            )
            outcome.evasion_successful = False
        else:
            outcome.notes = (
                f"사각지대 발견 (S3 Velocity): 동일 IP에서 {self.BURST_COUNT}회의 고속 요청이 "
                f"모두 통과(ALLOW)되었습니다. 속도 기반 이상탐지 또는 Rate-limiting 임계값이 부재하거나 지나치게 높습니다."
            )
            outcome.evasion_successful = True
