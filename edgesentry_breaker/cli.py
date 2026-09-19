"""Command Line Interface for EdgeSentryBreaker."""

import argparse
import os
import sys
from edgesentry_breaker.config import Config, GuardrailViolationError
from edgesentry_breaker.mock_server import MockDetectorEngine, run_mock_server
from edgesentry_breaker.runner import ScenarioRunner
from edgesentry_breaker.scenarios.registry import get_all_scenarios, resolve_scenarios


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="edgesentry-breaker",
        description="EdgeSentryBreaker: Blackbox Login Anomaly Detection Red Team Testing Framework",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # run command
    run_cmd = subparsers.add_parser("run", help="Run red team test scenarios against target")
    run_cmd.add_argument(
        "--target",
        "-t",
        default="http://127.0.0.1:8080/v1/detect",
        help="Target endpoint URL (default: http://127.0.0.1:8080/v1/detect)",
    )
    run_cmd.add_argument(
        "--scenarios",
        "-s",
        default="all",
        help="Comma-separated scenario IDs to run (e.g. 't1,t2,t3') or 'all' (default: all)",
    )
    run_cmd.add_argument(
        "--delay-scale",
        type=float,
        default=1.0,
        help="Multiplier for inter-request delays (e.g. 0.1 for faster execution, default: 1.0)",
    )
    run_cmd.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="HTTP request timeout in seconds (default: 5.0)",
    )
    run_cmd.add_argument(
        "--results-dir",
        default="results",
        help="Directory to store JSON/CSV/MD reports (default: results)",
    )
    run_cmd.add_argument(
        "--force-unsafe-target",
        action="store_true",
        help="Bypass local IP guardrail (CAUTION: requires explicit staging/authorization)",
    )
    run_cmd.add_argument(
        "--allow-non-test-accounts",
        action="store_true",
        help="Bypass test account ID filter guardrail",
    )

    # list command
    subparsers.add_parser("list", help="List all available scenarios and mapped signals")

    # serve-mock command
    mock_cmd = subparsers.add_parser("serve-mock", help="Start local mock EdgeSentry server")
    mock_cmd.add_argument("--host", default="127.0.0.1", help="Host address (default: 127.0.0.1)")
    mock_cmd.add_argument("--port", type=int, default=8080, help="Port number (default: 8080)")
    mock_cmd.add_argument("--disable-datacenter", action="store_true", help="Disable datacenter IP blocking rule")
    mock_cmd.add_argument("--disable-velocity", action="store_true", help="Disable velocity rate-limiting rule")
    mock_cmd.add_argument("--disable-geo", action="store_true", help="Disable impossible travel rule")
    mock_cmd.add_argument("--velocity-threshold", type=int, default=5, help="Velocity request threshold (default: 5)")

    # inspect command
    inspect_cmd = subparsers.add_parser("inspect", help="Inspect latest or specific test run summary")
    inspect_cmd.add_argument("--run-dir", help="Path to specific run directory (e.g. results/run_20260918_...)")

    return parser


def handle_run(args: argparse.Namespace) -> int:
    config = Config(
        target_url=args.target,
        timeout=args.timeout,
        delay_scale=args.delay_scale,
        results_dir=args.results_dir,
        force_unsafe_target=args.force_unsafe_target,
        allow_non_test_accounts=args.allow_non_test_accounts,
    )

    try:
        config.validate_target()
    except GuardrailViolationError as exc:
        print(f"\n[!] Guardrail Error: {exc}\n", file=sys.stderr)
        return 1

    try:
        scenarios = resolve_scenarios(args.scenarios)
    except KeyError as exc:
        print(f"\n[!] Error: {exc}\n", file=sys.stderr)
        return 1

    runner = ScenarioRunner(config)
    report = runner.run(scenarios)
    return 0 if report.total_requests > 0 else 1


def handle_list() -> int:
    scenarios = get_all_scenarios()
    print("\n" + "=" * 80)
    print(f"{'ID':<6} {'Scenario Name':<30} {'Target Signals':<30}")
    print("=" * 80)
    for s in scenarios:
        sig_str = ", ".join(sig.name if hasattr(sig, "name") else str(sig) for sig in s.target_signals)
        print(f"{s.scenario_id:<6} {s.name:<30} {sig_str:<30}")
        print(f"       가설: {s.hypothesis}")
        print(f"       검증: {s.validation_method}")
        print("-" * 80)
    print()
    return 0


def handle_mock(args: argparse.Namespace) -> int:
    engine = MockDetectorEngine(
        enable_datacenter_block=not args.disable_datacenter,
        enable_velocity_block=not args.disable_velocity,
        enable_geo_block=not args.disable_geo,
        velocity_threshold=args.velocity_threshold,
    )
    print(f"[*] Starting mock detection server with rules:")
    print(f"    - Datacenter Block (S1): {'Enabled' if not args.disable_datacenter else 'Disabled'}")
    print(f"    - Velocity Limit   (S3): {'Enabled (limit=' + str(args.velocity_threshold) + ')' if not args.disable_velocity else 'Disabled'}")
    print(f"    - Geo Travel Check (S2): {'Enabled' if not args.disable_geo else 'Disabled'}")
    run_mock_server(host=args.host, port=args.port, engine=engine)
    return 0


def handle_inspect(args: argparse.Namespace) -> int:
    results_dir = "results"
    target_dir = args.run_dir
    if not target_dir:
        if not os.path.exists(results_dir):
            print("No results directory found.")
            return 1
        runs = sorted([d for d in os.listdir(results_dir) if d.startswith("run_")])
        if not runs:
            print("No previous test runs found in results/.")
            return 1
        target_dir = os.path.join(results_dir, runs[-1])

    summary_file = os.path.join(target_dir, "summary.md")
    if not os.path.exists(summary_file):
        print(f"Summary file not found: {summary_file}")
        return 1

    with open(summary_file, "r", encoding="utf-8") as f:
        print(f.read())
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "run":
        sys.exit(handle_run(args))
    elif args.command == "list":
        sys.exit(handle_list())
    elif args.command == "serve-mock":
        sys.exit(handle_mock(args))
    elif args.command == "inspect":
        sys.exit(handle_inspect(args))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
