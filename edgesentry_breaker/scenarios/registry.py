"""Scenario registry for discovery and resolution."""

from typing import Dict, List, Type
from edgesentry_breaker.scenarios.base import BaseScenario
from edgesentry_breaker.scenarios.t1_baseline import ScenarioT1Baseline
from edgesentry_breaker.scenarios.t2_datacenter import ScenarioT2Datacenter
from edgesentry_breaker.scenarios.t3_high_velocity import ScenarioT3HighVelocity
from edgesentry_breaker.scenarios.t4_low_and_slow import ScenarioT4LowAndSlow
from edgesentry_breaker.scenarios.t5_geo_mismatch import ScenarioT5GeoMismatch
from edgesentry_breaker.scenarios.t6_result_tamper import ScenarioT6ResultTamper
from edgesentry_breaker.scenarios.t7_account_spray import ScenarioT7AccountSpray

SCENARIO_CLASSES: Dict[str, Type[BaseScenario]] = {
    "t1": ScenarioT1Baseline,
    "t2": ScenarioT2Datacenter,
    "t3": ScenarioT3HighVelocity,
    "t4": ScenarioT4LowAndSlow,
    "t5": ScenarioT5GeoMismatch,
    "t6": ScenarioT6ResultTamper,
    "t7": ScenarioT7AccountSpray,
}


def get_all_scenarios() -> List[BaseScenario]:
    """Returns instantiated list of all registered scenarios."""
    return [cls() for cls in SCENARIO_CLASSES.values()]


def get_scenario_by_id(scenario_id: str) -> BaseScenario:
    """Returns an instantiated scenario by ID (case-insensitive)."""
    key = scenario_id.strip().lower()
    if key not in SCENARIO_CLASSES:
        raise KeyError(f"Unknown scenario ID '{scenario_id}'. Available: {list(SCENARIO_CLASSES.keys())}")
    return SCENARIO_CLASSES[key]()


def resolve_scenarios(selector: str) -> List[BaseScenario]:
    """Resolves a comma-separated selector string (e.g. 'all' or 't1,t3,t6')."""
    if not selector or selector.strip().lower() == "all":
        return get_all_scenarios()

    tokens = [t.strip().lower() for t in selector.split(",") if t.strip()]
    scenarios = []
    for token in tokens:
        scenarios.append(get_scenario_by_id(token))
    return scenarios
