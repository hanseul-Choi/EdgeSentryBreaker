"""Scenario T7: 계정 순회 vs 계정 고정 (Account Spraying vs Targeted Account)."""

from typing import List
from edgesentry_breaker.config import Config
from edgesentry_breaker.models import (
    DetectionRequest,
    DetectionVerdict,
    ScenarioOutcome,
    SignalCategory,
)
from edgesentry_breaker.scenarios.base import BaseScenario


class ScenarioT7AccountSpray(BaseScenario):
    """T7: 계정 순회(Password Spraying) vs 계정 고정(Targeted) 판정 차이 검증."""

    scenario_id = "T7"
    name = "계정 순회 vs 계정 고정 (Spraying vs Targeted)"
    hypothesis = "동일 IP가 다수 계정을 순회하는 경우(Spraying, S7)와 특정 단일 계정에 집중하는 경우(Targeted, S3) 탐지 임계값/로직의 차이가 존재하는지 확인"
    validation_method = "동일 IP로 계정 5개를 1회씩 시도하는 패턴과, 다른 IP로 단일 계정을 5회 집중 시도하는 패턴을 비교 실행"
    target_signals = [SignalCategory.S3, SignalCategory.S7]

    SPRAY_IP = "198.51.100.88"
    TARGETED_IP = "198.51.100.89"
    ATTEMPTS = 5

    def generate_requests(self, config: Config) -> List[DetectionRequest]:
        requests = []
        # Phase A: Account Spraying (different account each time)
        for i in range(self.ATTEMPTS):
            requests.append(
                DetectionRequest(
                    ip=self.SPRAY_IP,
                    account_id=f"test_spray_{i+1}@example.com",
                    login_result="failure",
                    metadata={
                        "test_type": "account_spray",
                        "phase": "spraying",
                        "attempt": i + 1,
                    },
                    delay_before_seconds=0.05 * config.delay_scale if i > 0 else 0.0,
                )
            )

        # Phase B: Targeted Account (same account repeated)
        for i in range(self.ATTEMPTS):
            requests.append(
                DetectionRequest(
                    ip=self.TARGETED_IP,
                    account_id="test_targeted_focus@example.com",
                    login_result="failure",
                    metadata={
                        "test_type": "account_targeted",
                        "phase": "targeted",
                        "attempt": i + 1,
                    },
                    delay_before_seconds=0.05 * config.delay_scale,
                )
            )
        return requests

    def evaluate_outcome(self, outcome: ScenarioOutcome) -> None:
        super().evaluate_outcome(outcome)
        spray_steps = [s for s in outcome.steps if s.request.metadata.get("phase") == "spraying"]
        targeted_steps = [s for s in outcome.steps if s.request.metadata.get("phase") == "targeted"]

        spray_detected = any(s.response.verdict in (DetectionVerdict.BLOCK, DetectionVerdict.FLAGGED) for s in spray_steps)
        targeted_detected = any(s.response.verdict in (DetectionVerdict.BLOCK, DetectionVerdict.FLAGGED) for s in targeted_steps)

        if spray_detected and targeted_detected:
            outcome.notes = "양측 모두 탐지: IP 단위 Spraying(S7)과 단일 계정 집중 Brute-force(S3)가 모두 정상 차단되었습니다."
            outcome.evasion_successful = False
        elif not spray_detected and targeted_detected:
            outcome.notes = (
                "사각지대 발견 (S7 Spraying): 단일 계정 집중 공격은 탐지되었으나, "
                "다수 계정을 1회씩 순회하는 Password Spraying은 탐지되지 않았습니다 (계정 잠금 룰만 존재할 가능성)."
            )
            outcome.evasion_successful = True
        elif spray_detected and not targeted_detected:
            outcome.notes = "특이 패턴: IP 단위 Spraying은 차단되었으나 단일 계정 반복 시도는 차단되지 않았습니다."
            outcome.evasion_successful = True
        else:
            outcome.notes = (
                "사각지대 발견 (S3 & S7): Spraying과 단일 계정 반복 공격 모두 탐지되지 않았습니다. "
                "실패 카운터 및 분산도 분석이 부재합니다."
            )
            outcome.evasion_successful = True
