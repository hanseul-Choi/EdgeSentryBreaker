"""Unit tests for scenario request generation and outcome evaluation."""

import unittest
from edgesentry_breaker.config import Config
from edgesentry_breaker.models import (
    DetectionRequest,
    DetectionResponse,
    DetectionVerdict,
    ScenarioOutcome,
    StepResult,
)
from edgesentry_breaker.scenarios.registry import (
    get_all_scenarios,
    get_scenario_by_id,
    resolve_scenarios,
)
from edgesentry_breaker.scenarios.t1_baseline import ScenarioT1Baseline
from edgesentry_breaker.scenarios.t2_datacenter import ScenarioT2Datacenter
from edgesentry_breaker.scenarios.t3_high_velocity import ScenarioT3HighVelocity
from edgesentry_breaker.scenarios.t4_low_and_slow import ScenarioT4LowAndSlow
from edgesentry_breaker.scenarios.t5_geo_mismatch import ScenarioT5GeoMismatch
from edgesentry_breaker.scenarios.t6_result_tamper import ScenarioT6ResultTamper
from edgesentry_breaker.scenarios.t7_account_spray import ScenarioT7AccountSpray


class TestScenarios(unittest.TestCase):
    def setUp(self):
        self.config = Config(delay_scale=0.01)

    def test_registry_contains_all_scenarios(self):
        scenarios = get_all_scenarios()
        ids = [s.scenario_id.lower() for s in scenarios]
        self.assertEqual(ids, ["t1", "t2", "t3", "t4", "t5", "t6", "t7"])

    def test_resolve_scenarios(self):
        selected = resolve_scenarios("t1,t3,T6")
        self.assertEqual(len(selected), 3)
        self.assertEqual([s.scenario_id for s in selected], ["T1", "T3", "T6"])

    def test_t1_request_and_evaluation(self):
        scenario = ScenarioT1Baseline()
        reqs = scenario.generate_requests(self.config)
        self.assertEqual(len(reqs), 1)

        outcome = ScenarioOutcome(
            scenario_id="T1",
            name=scenario.name,
            target_signals=[],
            hypothesis=scenario.hypothesis,
            validation_method=scenario.validation_method,
        )
        # Simulate allow response
        outcome.steps.append(
            StepResult(
                step_index=1,
                request=reqs[0],
                response=DetectionResponse(status_code=200, verdict=DetectionVerdict.ALLOW, latency_ms=10.0),
                timestamp="2026-09-18T01:00:00",
            )
        )
        scenario.evaluate_outcome(outcome)
        self.assertFalse(outcome.detection_observed)
        self.assertIn("정상 기준선 통과 확인", outcome.notes)

    def test_t2_datacenter_evaluation(self):
        scenario = ScenarioT2Datacenter()
        reqs = scenario.generate_requests(self.config)
        self.assertGreater(len(reqs), 1)

        outcome = ScenarioOutcome(
            scenario_id="T2",
            name=scenario.name,
            target_signals=[],
            hypothesis=scenario.hypothesis,
            validation_method=scenario.validation_method,
        )
        # Simulate all blocked
        for i, req in enumerate(reqs, 1):
            outcome.steps.append(
                StepResult(
                    step_index=i,
                    request=req,
                    response=DetectionResponse(status_code=403, verdict=DetectionVerdict.BLOCK, latency_ms=10.0),
                    timestamp="2026-09-18T01:00:00",
                )
            )
        scenario.evaluate_outcome(outcome)
        self.assertTrue(outcome.detection_observed)
        self.assertFalse(outcome.evasion_successful)

    def test_t3_velocity_requests(self):
        scenario = ScenarioT3HighVelocity()
        reqs = scenario.generate_requests(self.config)
        self.assertEqual(len(reqs), 10)
        # All from same IP
        ips = {r.ip for r in reqs}
        self.assertEqual(len(ips), 1)


if __name__ == "__main__":
    unittest.main()
