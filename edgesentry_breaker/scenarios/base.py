"""Base scenario class for EdgeSentryBreaker."""

from abc import ABC, abstractmethod
from typing import List

from edgesentry_breaker.config import Config
from edgesentry_breaker.models import (
    DetectionRequest,
    DetectionVerdict,
    ScenarioOutcome,
    SignalCategory,
)


class BaseScenario(ABC):
    """Abstract base class for all red team test scenarios."""

    scenario_id: str
    name: str
    hypothesis: str
    validation_method: str
    target_signals: List[SignalCategory]

    @abstractmethod
    def generate_requests(self, config: Config) -> List[DetectionRequest]:
        """Generates the list of requests to execute for this scenario."""
        raise NotImplementedError

    def evaluate_outcome(self, outcome: ScenarioOutcome) -> None:
        """Analyzes results to determine if detection was observed or evasion succeeded.

        Subclasses can override to provide scenario-specific analysis notes.
        """
        outcome.compute_aggregates()
        if outcome.block_count > 0 or outcome.challenge_count > 0:
            outcome.detection_observed = True
        else:
            outcome.detection_observed = False
