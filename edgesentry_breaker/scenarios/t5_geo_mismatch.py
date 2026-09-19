"""Scenario T5: 지리적 불일치 요청 (Geographic Inconsistency / Impossible Travel)."""

from typing import List
from edgesentry_breaker.config import Config
from edgesentry_breaker.models import (
    DetectionRequest,
    DetectionVerdict,
    ScenarioOutcome,
    SignalCategory,
)
from edgesentry_breaker.scenarios.base import BaseScenario


class ScenarioT5GeoMismatch(BaseScenario):
    """T5: 지리적 불일치(Impossible Travel) 검증."""

    scenario_id = "T5"
    name = "지리적 불일치 (Impossible Travel 이상징후)"
    hypothesis = "동일 계정에 대해 기존 활동 국가/지역과 물리적으로 도달 불가능한 원거리 해외 IP로 즉시 요청 시 지리 이상(S2)으로 탐지되는지 확인"
    validation_method = "국내/주거 기준선 IP 요청 직후, 원거리 해외 공인 IP(남아공, 루마니아, 브라질)로 연속 요청 전송"
    target_signals = [SignalCategory.S2]

    # Geographically disparate public IPs
    GEO_TARGETS = [
        {"country": "KR (기준선)", "ip": "203.0.113.1"},
        {"country": "ZA (남아프리카공화국)", "ip": "196.25.1.1"},
        {"country": "RO (루마니아)", "ip": "185.220.101.5"},
        {"country": "BR (브라질)", "ip": "200.147.67.142"},
    ]

    def generate_requests(self, config: Config) -> List[DetectionRequest]:
        requests = []
        account_id = "test_geo_user@example.com"
        for i, target in enumerate(self.GEO_TARGETS):
            requests.append(
                DetectionRequest(
                    ip=target["ip"],
                    account_id=account_id,
                    login_result="success",
                    metadata={
                        "test_type": "geo_impossible_travel",
                        "country": target["country"],
                        "is_baseline": i == 0,
                    },
                    delay_before_seconds=0.1 * config.delay_scale if i > 0 else 0.0,
                )
            )
        return requests

    def evaluate_outcome(self, outcome: ScenarioOutcome) -> None:
        super().evaluate_outcome(outcome)
        foreign_blocked = [
            step.request.metadata.get("country", step.request.ip)
            for step in outcome.steps
            if not step.request.metadata.get("is_baseline")
            and step.response.verdict in (DetectionVerdict.BLOCK, DetectionVerdict.FLAGGED, DetectionVerdict.CHALLENGE)
        ]
        foreign_allowed = [
            step.request.metadata.get("country", step.request.ip)
            for step in outcome.steps
            if not step.request.metadata.get("is_baseline")
            and step.response.verdict == DetectionVerdict.ALLOW
        ]

        if not foreign_blocked:
            outcome.notes = (
                "사각지대 발견 (S2 지리 일관성): 원거리 국가 IP 간 급격한 이동(Impossible Travel)이 "
                "모두 허용(ALLOW)되었습니다. IP 역지오로케이션(GeoIP) 또는 거리/속도 상관분석이 동작하지 않습니다."
            )
            outcome.evasion_successful = True
        elif not foreign_allowed:
            outcome.notes = f"지리 이상 탐지 활성화: 원거리 해외 IP 시도({', '.join(foreign_blocked)})가 모두 감지/차단되었습니다."
            outcome.evasion_successful = False
        else:
            outcome.notes = f"부분 탐지: {', '.join(foreign_blocked)}는 탐지되었으나, {', '.join(foreign_allowed)}는 허용되었습니다."
            outcome.evasion_successful = True
