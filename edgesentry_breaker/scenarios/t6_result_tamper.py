"""Scenario T6: login_result 조작 및 신뢰 경계 검증 (Trust Boundary & Result Tampering)."""

from typing import List
from edgesentry_breaker.config import Config
from edgesentry_breaker.models import (
    DetectionRequest,
    DetectionVerdict,
    ScenarioOutcome,
    SignalCategory,
)
from edgesentry_breaker.scenarios.base import BaseScenario


class ScenarioT6ResultTamper(BaseScenario):
    """T6: login_result 조작 및 S6 성공/실패 비율 검증."""

    scenario_id = "T6"
    name = "login_result 조작 및 신뢰 경계 검증 (API Trust Boundary)"
    hypothesis = "클라이언트가 보고하는 login_result 필드에 따라 탐지 판정이 좌우되거나, 공격자가 임의로 조작하여 통계 오염 및 브루트포스 흔적 은폐가 가능한지 확인"
    validation_method = "동일 IP에서 연속 failure 전송 후 success 전송 비교, 및 임의의 비표준 문자열 전달 시 반응 관찰"
    target_signals = [SignalCategory.S6]

    TEST_IP = "198.51.100.77"
    TARGET_ACCOUNT = "test_tamper_user@example.com"

    def generate_requests(self, config: Config) -> List[DetectionRequest]:
        return [
            # 1. First failure
            DetectionRequest(
                ip=self.TEST_IP,
                account_id=self.TARGET_ACCOUNT,
                login_result="failure",
                metadata={"test_type": "tamper_failure_1", "phase": "repeated_failures"},
                delay_before_seconds=0.0,
            ),
            # 2. Second failure
            DetectionRequest(
                ip=self.TEST_IP,
                account_id=self.TARGET_ACCOUNT,
                login_result="failure",
                metadata={"test_type": "tamper_failure_2", "phase": "repeated_failures"},
                delay_before_seconds=0.05 * config.delay_scale,
            ),
            # 3. Third failure
            DetectionRequest(
                ip=self.TEST_IP,
                account_id=self.TARGET_ACCOUNT,
                login_result="failure",
                metadata={"test_type": "tamper_failure_3", "phase": "repeated_failures"},
                delay_before_seconds=0.05 * config.delay_scale,
            ),
            # 4. Fourth failure
            DetectionRequest(
                ip=self.TEST_IP,
                account_id=self.TARGET_ACCOUNT,
                login_result="failure",
                metadata={"test_type": "tamper_failure_4", "phase": "repeated_failures"},
                delay_before_seconds=0.05 * config.delay_scale,
            ),
            # 5. Suddenly claim success from same IP
            DetectionRequest(
                ip=self.TEST_IP,
                account_id=self.TARGET_ACCOUNT,
                login_result="success",
                metadata={"test_type": "tamper_claimed_success", "phase": "success_after_failures"},
                delay_before_seconds=0.05 * config.delay_scale,
            ),
            # 6. Non-standard input to test input validation
            DetectionRequest(
                ip=self.TEST_IP,
                account_id=self.TARGET_ACCOUNT,
                login_result="arbitrary_tampered_value",
                metadata={"test_type": "tamper_invalid_value", "phase": "schema_validation"},
                delay_before_seconds=0.05 * config.delay_scale,
            ),
        ]

    def evaluate_outcome(self, outcome: ScenarioOutcome) -> None:
        super().evaluate_outcome(outcome)
        steps = outcome.steps

        failure_steps = [s for s in steps if s.request.metadata.get("phase") == "repeated_failures"]
        success_step = next((s for s in steps if s.request.metadata.get("phase") == "success_after_failures"), None)
        schema_step = next((s for s in steps if s.request.metadata.get("phase") == "schema_validation"), None)

        failure_blocked = any(s.response.verdict in (DetectionVerdict.BLOCK, DetectionVerdict.FLAGGED) for s in failure_steps)
        success_blocked = success_step and (success_step.response.verdict in (DetectionVerdict.BLOCK, DetectionVerdict.FLAGGED))

        notes_parts = []
        if failure_blocked and success_blocked:
            notes_parts.append("성공/실패 비율(S6) 추적 확인: 반복 실패 후 성공 요청도 연관 탐지되었습니다.")
        elif failure_blocked and not success_blocked:
            notes_parts.append("사각지대/신뢰 경계 위험: 반복 실패는 차단되었으나, success 조작 요청은 허용되었습니다.")
            outcome.evasion_successful = True
        elif not failure_blocked and not success_blocked:
            notes_parts.append("사각지대 발견 (S6): 반복 실패 및 조작된 성공 요청 모두 탐지되지 않았습니다.")
            outcome.evasion_successful = True

        if schema_step and schema_step.response.status_code in (400, 422):
            notes_parts.append("입력 스키마 검증(400/422) 작동 확인.")
        elif schema_step and schema_step.response.status_code == 200:
            notes_parts.append("경고: login_result의 비표준 임의 값('arbitrary_tampered_value')이 200 OK로 수락되었습니다.")

        outcome.notes = " ".join(notes_parts)
