"""Scenario T4: 저속·분산 요청 (Low & Slow Evasion)."""

from typing import List
from edgesentry_breaker.config import Config
from edgesentry_breaker.models import (
    DetectionRequest,
    DetectionVerdict,
    ScenarioOutcome,
    SignalCategory,
)
from edgesentry_breaker.scenarios.base import BaseScenario


class ScenarioT4LowAndSlow(BaseScenario):
    """T4: 저속·분산(Low & Slow) 회피 검증."""

    scenario_id = "T4"
    name = "저속·분산 요청 (Low & Slow 속도 우회)"
    hypothesis = "요청 간격을 인위적으로 늘리고 소수 IP를 로테이션함으로써 Velocity(S3) 탐지 임계값을 우회할 수 있는지 확인"
    validation_method = "3개의 IP를 순환하며 딜레이를 두고 동일 계정에 대해 분산 요청 전송"
    target_signals = [SignalCategory.S3, SignalCategory.S7]

    ROTATION_IPS = [
        "198.51.100.61",
        "198.51.100.62",
        "198.51.100.63",
    ]
    CYCLES = 2  # Total 6 requests
    BASE_DELAY_SECONDS = 0.5

    def generate_requests(self, config: Config) -> List[DetectionRequest]:
        requests = []
        step_count = 0
        for cycle in range(self.CYCLES):
            for ip in self.ROTATION_IPS:
                step_count += 1
                # apply delay scaled by config
                delay = self.BASE_DELAY_SECONDS * config.delay_scale if step_count > 1 else 0.0
                requests.append(
                    DetectionRequest(
                        ip=ip,
                        account_id="test_slow_target@example.com",
                        login_result="success",
                        metadata={
                            "test_type": "low_and_slow",
                            "cycle": cycle + 1,
                            "ip_index": ip,
                        },
                        delay_before_seconds=delay,
                    )
                )
        return requests

    def evaluate_outcome(self, outcome: ScenarioOutcome) -> None:
        super().evaluate_outcome(outcome)
        if outcome.block_count == 0 and outcome.challenge_count == 0:
            outcome.notes = (
                "회피 성공 / 사각지대 (S3 & S7): 시간 지연 및 IP 로테이션을 적용한 요청이 "
                "전부 허용(ALLOW)되었습니다. 단순 단일 IP Velocity 룰만 존재하는 경우 Low & Slow 공격에 취약합니다."
            )
            outcome.evasion_successful = True
        else:
            outcome.notes = (
                f"탐지 활성화: 저속·분산 패턴임에도 {outcome.block_count + outcome.challenge_count}건의 차단/도전이 감지되었습니다. "
                "계정 중심 윈도우 집계 또는 분산 패턴 상관분석이 작동 중입니다."
            )
            outcome.evasion_successful = False
