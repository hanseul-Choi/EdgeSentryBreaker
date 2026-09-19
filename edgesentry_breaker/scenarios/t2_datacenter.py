"""Scenario T2: 데이터센터 IP 대역 요청 (Datacenter IP Range)."""

from typing import List
from edgesentry_breaker.config import Config
from edgesentry_breaker.models import (
    DetectionRequest,
    DetectionVerdict,
    ScenarioOutcome,
    SignalCategory,
)
from edgesentry_breaker.scenarios.base import BaseScenario


class ScenarioT2Datacenter(BaseScenario):
    """T2: 데이터센터/클라우드/호스팅 IP 요청 검증."""

    scenario_id = "T2"
    name = "데이터센터 IP 대역 요청"
    hypothesis = "주요 퍼블릭 클라우드/호스팅 IP(AWS, GCP, Azure, DigitalOcean) 대역에서 요청 시 IP 평판(S1)에 의해 차단/플래그되는지 확인"
    validation_method = "알려진 주요 데이터센터 IP 대역으로 각각 요청 전송 후 판정 비교"
    target_signals = [SignalCategory.S1]

    # Sample public cloud/datacenter IP ranges for testing
    DATACENTER_TARGETS = [
        {"provider": "AWS EC2", "ip": "3.5.140.2"},
        {"provider": "Google Cloud", "ip": "34.64.120.1"},
        {"provider": "Microsoft Azure", "ip": "20.40.10.1"},
        {"provider": "DigitalOcean", "ip": "159.89.10.5"},
        {"provider": "Tor Exit Node", "ip": "185.220.101.5"},
    ]

    def generate_requests(self, config: Config) -> List[DetectionRequest]:
        requests = []
        for target in self.DATACENTER_TARGETS:
            requests.append(
                DetectionRequest(
                    ip=target["ip"],
                    account_id="test_user@example.com",
                    login_result="success",
                    metadata={
                        "test_type": "datacenter_reputation",
                        "provider": target["provider"],
                    },
                    delay_before_seconds=0.1 * config.delay_scale,
                )
            )
        return requests

    def evaluate_outcome(self, outcome: ScenarioOutcome) -> None:
        super().evaluate_outcome(outcome)
        blocked_providers = [
            step.request.metadata.get("provider", step.request.ip)
            for step in outcome.steps
            if step.response.verdict in (DetectionVerdict.BLOCK, DetectionVerdict.FLAGGED, DetectionVerdict.CHALLENGE)
        ]
        allowed_providers = [
            step.request.metadata.get("provider", step.request.ip)
            for step in outcome.steps
            if step.response.verdict == DetectionVerdict.ALLOW
        ]

        if not blocked_providers:
            outcome.notes = (
                "사각지대 발견 (S1 IP 평판): 모든 데이터센터 및 Tor IP가 정상 통과(ALLOW)되었습니다. "
                "IP 인텔리전스/호스팅 대역 식별 규칙이 부재할 가능성이 높습니다."
            )
            outcome.evasion_successful = True
        elif not allowed_providers:
            outcome.notes = f"IP 평판 탐지 활성화: 모든 테스트 대역({', '.join(blocked_providers)})이 차단/도전 처리되었습니다."
            outcome.evasion_successful = False
        else:
            outcome.notes = (
                f"부분 탐지: {', '.join(blocked_providers)}는 차단되었으나, "
                f"{', '.join(allowed_providers)}는 통과되었습니다."
            )
            outcome.evasion_successful = True
