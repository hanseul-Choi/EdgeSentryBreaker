"""Runner module for executing scenarios against target."""

import time
from datetime import datetime
from typing import List, Optional
from edgesentry_breaker.client import DetectionClient
from edgesentry_breaker.config import Config
from edgesentry_breaker.models import (
    DetectionRequest,
    RunReport,
    ScenarioOutcome,
    StepResult,
)
from edgesentry_breaker.reporter import Reporter
from edgesentry_breaker.scenarios.base import BaseScenario


class ScenarioRunner:
    """Orchestrates test scenarios, measures timing, and collects results."""

    def __init__(self, config: Config, client: Optional[DetectionClient] = None, reporter: Optional[Reporter] = None):
        self.config = config
        self.client = client or DetectionClient(config)
        self.reporter = reporter or Reporter(results_dir=config.results_dir)

    def run(self, scenarios: List[BaseScenario]) -> RunReport:
        """Runs the given list of scenarios sequentially and generates reports."""
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        start_time = datetime.now()
        outcomes: List[ScenarioOutcome] = []

        print(f"\n[*] Starting EdgeSentryBreaker run {run_id}")
        print(f"[*] Target: {self.config.target_url}")
        print(f"[*] Scenarios queued: {len(scenarios)} ({', '.join(s.scenario_id for s in scenarios)})\n")

        for scenario in scenarios:
            print(f"--> Executing {scenario.scenario_id}: {scenario.name}...")
            outcome = ScenarioOutcome(
                scenario_id=scenario.scenario_id,
                name=scenario.name,
                target_signals=[sig.value if hasattr(sig, "value") else str(sig) for sig in scenario.target_signals],
                hypothesis=scenario.hypothesis,
                validation_method=scenario.validation_method,
            )

            requests: List[DetectionRequest] = scenario.generate_requests(self.config)
            for idx, req in enumerate(requests, 1):
                if req.delay_before_seconds > 0:
                    time.sleep(req.delay_before_seconds)

                step_ts = datetime.now().isoformat()
                response = self.client.send(req)

                step_result = StepResult(
                    step_index=idx,
                    request=req,
                    response=response,
                    timestamp=step_ts,
                )
                outcome.steps.append(step_result)

            scenario.evaluate_outcome(outcome)
            outcomes.append(outcome)

            verdict_str = "DETECTED" if outcome.detection_observed else "EVADED"
            print(f"    Finished {scenario.scenario_id}: {outcome.total_requests} requests, "
                  f"{outcome.block_count + outcome.challenge_count} blocked, "
                  f"{outcome.allow_count} allowed -> [{verdict_str}]")

        end_time = datetime.now()
        report = self.reporter.generate_report(
            run_id=run_id,
            target_url=self.config.target_url,
            start_time=start_time,
            end_time=end_time,
            scenarios=outcomes,
        )

        saved_path = self.reporter.save_all(report)
        print(f"\n[+] Results saved to: {saved_path}")
        self.reporter.print_summary(report)

        return report
