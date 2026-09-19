"""Reporting and metrics module for EdgeSentryBreaker."""

import csv
import json
import os
from datetime import datetime
from typing import Dict, List
from edgesentry_breaker.models import (
    DetectionVerdict,
    RunReport,
    ScenarioOutcome,
    SignalCategory,
    SignalCoverageResult,
)


class Reporter:
    """Generates structured JSON, CSV, and Markdown reports and terminal summaries."""

    SIGNAL_MAPPINGS = [
        ("S1", "IP 평판 (Datacenter/Tor/Proxy)", ["T2"]),
        ("S2", "지리 일관성 (Impossible Travel)", ["T5"]),
        ("S3", "빈도·속도 (Velocity)", ["T3", "T4", "T7"]),
        ("S4", "계정-자산 연관성 (IP/Device Trust)", ["T1"]),
        ("S5", "시간대 패턴 (Timezone Anomaly)", []),
        ("S6", "성공/실패 비율 (Success/Failure Ratio)", ["T6"]),
        ("S7", "분산도 (Target Dispersion)", ["T4", "T7"]),
    ]

    def __init__(self, results_dir: str = "results"):
        self.results_dir = results_dir
        os.makedirs(self.results_dir, exist_ok=True)

    def generate_report(
        self,
        run_id: str,
        target_url: str,
        start_time: datetime,
        end_time: datetime,
        scenarios: List[ScenarioOutcome],
    ) -> RunReport:
        """Computes all Section 8 metrics and signal coverage."""
        duration = (end_time - start_time).total_seconds()
        total_requests = sum(s.total_requests for s in scenarios)
        total_blocked = sum(s.block_count + s.challenge_count for s in scenarios)
        total_allowed = sum(s.allow_count for s in scenarios)

        detection_rate = (total_blocked / total_requests * 100.0) if total_requests > 0 else 0.0
        evasion_count = sum(1 for s in scenarios if s.evasion_successful)
        evasion_rate = (evasion_count / len(scenarios) * 100.0) if scenarios else 0.0

        # Check for False Positive on T1
        t1 = next((s for s in scenarios if s.scenario_id.upper() == "T1"), None)
        false_positive = False
        if t1 and (t1.block_count > 0 or t1.challenge_count > 0):
            false_positive = True

        # Compute Signal Coverage (S1 - S7)
        signal_coverages = []
        blind_spots = []
        for code, name, rel_scenarios in self.SIGNAL_MAPPINGS:
            reaction = False
            notes = ""
            if not rel_scenarios:
                notes = "본 테스트 세트에서 직접적인 시나리오 미배정"
            else:
                matched_scenarios = [s for s in scenarios if s.scenario_id.upper() in rel_scenarios]
                reaction = any(s.detection_observed for s in matched_scenarios)
                if reaction:
                    notes = f"신호 반응 확인됨 ({', '.join(s.scenario_id for s in matched_scenarios if s.detection_observed)})"
                else:
                    notes = f"반응 미관찰 (사각지대 가능성, 대상: {', '.join(rel_scenarios)})"
                    blind_spots.append(f"{code} ({name}): {notes}")

            signal_coverages.append(
                SignalCoverageResult(
                    signal_code=code,
                    signal_name=name,
                    related_scenarios=rel_scenarios,
                    reaction_observed=reaction,
                    notes=notes,
                )
            )

        return RunReport(
            run_id=run_id,
            target_url=target_url,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            duration_seconds=round(duration, 2),
            scenarios=scenarios,
            signal_coverages=signal_coverages,
            total_requests=total_requests,
            total_blocked=total_blocked,
            total_allowed=total_allowed,
            detection_rate=round(detection_rate, 2),
            evasion_rate=round(evasion_rate, 2),
            false_positive_detected=false_positive,
            blind_spots=blind_spots,
        )

    def save_all(self, report: RunReport) -> str:
        """Saves JSON, CSV, and Markdown files under results/<run_id>/."""
        run_folder = os.path.join(self.results_dir, report.run_id)
        os.makedirs(run_folder, exist_ok=True)

        self._save_json(report, os.path.join(run_folder, "results.json"))
        self._save_csv(report, os.path.join(run_folder, "results.csv"))
        self._save_markdown(report, os.path.join(run_folder, "summary.md"))

        return run_folder

    def _save_json(self, report: RunReport, filepath: str) -> None:
        data = {
            "run_id": report.run_id,
            "target_url": report.target_url,
            "start_time": report.start_time,
            "end_time": report.end_time,
            "duration_seconds": report.duration_seconds,
            "metrics": {
                "total_requests": report.total_requests,
                "total_blocked": report.total_blocked,
                "total_allowed": report.total_allowed,
                "detection_rate_pct": report.detection_rate,
                "evasion_rate_pct": report.evasion_rate,
                "false_positive_detected": report.false_positive_detected,
            },
            "blind_spots": report.blind_spots,
            "signal_coverage": [
                {
                    "code": sc.signal_code,
                    "name": sc.signal_name,
                    "related_scenarios": sc.related_scenarios,
                    "reaction_observed": sc.reaction_observed,
                    "notes": sc.notes,
                }
                for sc in report.signal_coverages
            ],
            "scenarios": [
                {
                    "scenario_id": s.scenario_id,
                    "name": s.name,
                    "hypothesis": s.hypothesis,
                    "target_signals": [sig.value if hasattr(sig, "value") else str(sig) for sig in s.target_signals],
                    "total_requests": s.total_requests,
                    "allow_count": s.allow_count,
                    "block_count": s.block_count,
                    "challenge_count": s.challenge_count,
                    "error_count": s.error_count,
                    "detection_observed": s.detection_observed,
                    "evasion_successful": s.evasion_successful,
                    "notes": s.notes,
                    "steps": [step.to_dict() for step in s.steps],
                }
                for s in report.scenarios
            ],
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)

    def _save_csv(self, report: RunReport, filepath: str) -> None:
        fieldnames = [
            "scenario_id",
            "step_index",
            "timestamp",
            "ip",
            "account_id",
            "login_result",
            "status_code",
            "verdict",
            "latency_ms",
            "error_message",
        ]
        with open(filepath, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for s in report.scenarios:
                for step in s.steps:
                    writer.writerow({
                        "scenario_id": s.scenario_id,
                        "step_index": step.step_index,
                        "timestamp": step.timestamp,
                        "ip": step.request.ip,
                        "account_id": step.request.account_id,
                        "login_result": step.request.login_result,
                        "status_code": step.response.status_code,
                        "verdict": step.response.verdict.value,
                        "latency_ms": round(step.response.latency_ms, 2),
                        "error_message": step.response.error_message or "",
                    })

    def _save_markdown(self, report: RunReport, filepath: str) -> None:
        lines = []
        lines.append(f"# EdgeSentry 블랙박스 레드팀 테스트 리포트 ({report.run_id})")
        lines.append("")
        lines.append(f"- **대상 엔드포인트**: `{report.target_url}`")
        lines.append(f"- **실행 시간**: {report.start_time} ~ {report.end_time} ({report.duration_seconds}초)")
        lines.append(f"- **총 요청 수**: {report.total_requests}건 (차단/도전: {report.total_blocked}건, 통과: {report.total_allowed}건)")
        lines.append(f"- **전체 탐지율**: `{report.detection_rate}%`")
        lines.append(f"- **회피 성공률**: `{report.evasion_rate}%` (낮을수록 방어 우수)")
        if report.false_positive_detected:
            lines.append("- ⚠️ **오탐(False Positive) 경고**: 정상 기준선 요청(T1)에서 차단/플래그가 발생했습니다.")
        else:
            lines.append("- ✅ **정상 기준선(T1)**: 정상 트래픽 오탐 없음")
        lines.append("")

        lines.append("## 1. 탐지 신호 커버리지 매트릭스 (S1~S7)")
        lines.append("")
        lines.append("| 신호 코드 | 신호명 | 관련 시나리오 | 탐지 반응 여부 | 분석 결과 |")
        lines.append("|---|---|---|---|---|")
        for sc in report.signal_coverages:
            status = "✅ 반응 확인" if sc.reaction_observed else "❌ 미관찰"
            rel = ", ".join(sc.related_scenarios) if sc.related_scenarios else "-"
            lines.append(f"| {sc.signal_code} | {sc.signal_name} | {rel} | {status} | {sc.notes} |")
        lines.append("")

        lines.append("## 2. 시나리오별 실행 결과 요약")
        lines.append("")
        lines.append("| ID | 시나리오명 | 요청 수 | 차단/도전 | 통과 | 에러 | 탐지 여부 | 회피 여부 | 분석 요약 |")
        lines.append("|---|---|---|---|---|---|---|---|---|")
        for s in report.scenarios:
            det = "탐지" if s.detection_observed else "미탐지"
            eva = "성공(우회)" if s.evasion_successful else "차단/방어"
            lines.append(f"| {s.scenario_id} | {s.name} | {s.total_requests} | {s.block_count + s.challenge_count} | {s.allow_count} | {s.error_count} | {det} | {eva} | {s.notes} |")
        lines.append("")

        lines.append("## 3. 발견된 사각지대 및 방어 권고사항 (False Negatives & Trust Boundaries)")
        lines.append("")
        if report.blind_spots:
            for i, bs in enumerate(report.blind_spots, 1):
                lines.append(f"{i}. **{bs}**")
        else:
            lines.append("테스트된 모든 신호에 대해 탐지 시스템이 정상적으로 반응했습니다.")
        lines.append("")

        lines.append("---")
        lines.append("*본 문서는 EdgeSentryBreaker 자동화 프레임워크에 의해 생성되었습니다.*")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def print_summary(self, report: RunReport) -> None:
        """Prints a friendly terminal summary."""
        print("\n" + "=" * 70)
        print(f"  EdgeSentryBreaker Execution Summary [{report.run_id}]")
        print("=" * 70)
        print(f"Target: {report.target_url}")
        print(f"Duration: {report.duration_seconds}s | Requests: {report.total_requests} (Blocked: {report.total_blocked}, Allowed: {report.total_allowed})")
        print(f"Detection Rate: {report.detection_rate}% | Evasion Rate: {report.evasion_rate}%")
        print(f"False Positive Alert: {'YES ⚠️' if report.false_positive_detected else 'No ✅'}")
        print("-" * 70)
        print(f"{'ID':<4} {'Scenario Name':<28} {'Reqs':<6} {'Block':<6} {'Allow':<6} {'Verdict'}")
        print("-" * 70)
        for s in report.scenarios:
            status = "EVADED" if s.evasion_successful else "DETECTED"
            print(f"{s.scenario_id:<4} {s.name[:27]:<28} {s.total_requests:<6} {s.block_count+s.challenge_count:<6} {s.allow_count:<6} {status}")
        print("-" * 70)
        print("Signal Coverage (S1 - S7):")
        for sc in report.signal_coverages:
            marker = "[X]" if sc.reaction_observed else "[ ]"
            print(f"  {marker} {sc.signal_code}: {sc.signal_name} -> {sc.notes}")
        print("=" * 70 + "\n")
