"""HTTP client for dispatching detection requests against target server."""

import json
import time
from typing import Any, Dict, Optional
import requests

from edgesentry_breaker.config import Config
from edgesentry_breaker.models import (
    DetectionRequest,
    DetectionResponse,
    DetectionVerdict,
)
from edgesentry_breaker.mock_server import MockDetectorEngine, MockTransportAdapter


class DetectionClient:
    """Safe HTTP client to test /v1/detect endpoint."""

    def __init__(self, config: Config, engine: Optional[MockDetectorEngine] = None):
        self.config = config
        self.config.validate_target()
        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
            "User-Agent": "EdgeSentryBreaker/0.1.0",
        })

        if engine is not None:
            adapter = MockTransportAdapter(engine)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
            self.session.mount("mock://", adapter)
        elif self.config.is_mock():
            adapter = MockTransportAdapter()
            self.session.mount("mock://", adapter)

    def send(self, request: DetectionRequest) -> DetectionResponse:
        """Sends a single detection request and classifies the outcome."""
        self.config.validate_account_id(request.account_id)

        payload = request.to_payload()
        start_time = time.perf_counter()

        headers = dict(self.session.headers)
        if request.headers:
            headers.update(request.headers)

        try:
            resp = self.session.post(
                self.config.target_url,
                json=payload,
                headers=headers,
                timeout=self.config.timeout,
            )
            latency_ms = (time.perf_counter() - start_time) * 1000.0

            # Try parsing JSON body
            body: Any = None
            try:
                body = resp.json()
            except Exception:
                body = resp.text

            verdict = self._determine_verdict(resp.status_code, body)

            return DetectionResponse(
                status_code=resp.status_code,
                verdict=verdict,
                latency_ms=latency_ms,
                body=body,
                raw_text=resp.text,
            )

        except requests.RequestException as exc:
            latency_ms = (time.perf_counter() - start_time) * 1000.0
            return DetectionResponse(
                status_code=0,
                verdict=DetectionVerdict.ERROR,
                latency_ms=latency_ms,
                error_message=f"{exc.__class__.__name__}: {str(exc)}",
            )

    def _determine_verdict(self, status_code: int, body: Any) -> DetectionVerdict:
        """Infers the detection verdict based on HTTP status code and response payload."""
        # Standard HTTP blocking status codes
        if status_code in (403, 429):
            return DetectionVerdict.BLOCK

        # Server error codes
        if status_code >= 500:
            return DetectionVerdict.ERROR

        # Inspect body dictionary if available
        if isinstance(body, dict):
            # Check common decision/action keys
            for key in ("action", "decision", "verdict", "result", "status"):
                val = str(body.get(key, "")).lower()
                if val in ("block", "deny", "blocked", "drop", "rejected"):
                    return DetectionVerdict.BLOCK
                if val in ("challenge", "mfa", "captcha", "verify", "2fa"):
                    return DetectionVerdict.CHALLENGE
                if val in ("flag", "flagged", "review", "suspicious"):
                    return DetectionVerdict.FLAGGED
                if val in ("allow", "pass", "permit", "success", "ok"):
                    return DetectionVerdict.ALLOW

            # Boolean blocked flag
            if body.get("blocked") is True:
                return DetectionVerdict.BLOCK
            if body.get("is_anomaly") is True:
                return DetectionVerdict.FLAGGED

            # Risk score inspection
            for score_key in ("risk_score", "anomaly_score", "score"):
                if score_key in body and isinstance(body[score_key], (int, float)):
                    score = float(body[score_key])
                    # Support normalized 0.0-1.0 or 0-100 scale
                    if score >= 80.0 or (0.8 <= score <= 1.0):
                        return DetectionVerdict.BLOCK
                    elif score >= 50.0 or (0.5 <= score < 0.8):
                        return DetectionVerdict.FLAGGED

        if 200 <= status_code < 300:
            return DetectionVerdict.ALLOW

        return DetectionVerdict.UNKNOWN
