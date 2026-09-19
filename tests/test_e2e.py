"""End-to-end integration tests using in-process MockDetectorEngine."""

import os
import shutil
import unittest
from edgesentry_breaker.client import DetectionClient
from edgesentry_breaker.config import Config
from edgesentry_breaker.mock_server import MockDetectorEngine
from edgesentry_breaker.runner import ScenarioRunner
from edgesentry_breaker.scenarios.registry import get_all_scenarios


class TestE2E(unittest.TestCase):
    def setUp(self):
        self.test_results_dir = "results_test_e2e"
        os.makedirs(self.test_results_dir, exist_ok=True)
        self.engine = MockDetectorEngine(
            enable_datacenter_block=True,
            enable_velocity_block=True,
            enable_geo_block=True,
            velocity_threshold=5,
        )

    def tearDown(self):
        if os.path.exists(self.test_results_dir):
            shutil.rmtree(self.test_results_dir)

    def test_run_all_scenarios_e2e(self):
        config = Config(
            target_url="http://127.0.0.1:8080/v1/detect",
            timeout=3.0,
            delay_scale=0.001,  # ultra-fast for testing
            results_dir=self.test_results_dir,
        )
        client = DetectionClient(config, engine=self.engine)
        runner = ScenarioRunner(config, client=client)

        scenarios = get_all_scenarios()
        report = runner.run(scenarios)

        self.assertEqual(len(report.scenarios), 7)
        self.assertGreater(report.total_requests, 20)
        self.assertFalse(report.false_positive_detected)  # T1 baseline should pass

        # Check saved files
        run_folder = os.path.join(self.test_results_dir, report.run_id)
        self.assertTrue(os.path.exists(os.path.join(run_folder, "results.json")))
        self.assertTrue(os.path.exists(os.path.join(run_folder, "results.csv")))
        self.assertTrue(os.path.exists(os.path.join(run_folder, "summary.md")))

        # Check signals coverage
        signal_codes = {sc.signal_code for sc in report.signal_coverages}
        self.assertEqual(signal_codes, {"S1", "S2", "S3", "S4", "S5", "S6", "S7"})

        # Check that detection rate is greater than 0
        self.assertGreater(report.detection_rate, 0.0)
        self.assertGreater(report.total_blocked, 0)
        self.assertGreater(report.total_allowed, 0)

    def test_run_mock_url_target(self):
        config = Config(
            target_url="mock://local/v1/detect",
            delay_scale=0.001,
            results_dir=self.test_results_dir,
        )
        runner = ScenarioRunner(config)
        scenarios = get_all_scenarios()
        report = runner.run(scenarios)
        self.assertEqual(len(report.scenarios), 7)
        self.assertGreater(report.total_requests, 20)


if __name__ == "__main__":
    unittest.main()
