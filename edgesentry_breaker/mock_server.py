"""Lightweight mock detection server for local testing and CI."""

import io
import json
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple
import requests
from requests.adapters import BaseAdapter
from requests.models import Response


class MockDetectorEngine:
    """Configurable anomaly detection engine for staging and simulation."""

    def __init__(
        self,
        enable_datacenter_block: bool = True,
        enable_velocity_block: bool = True,
        enable_geo_block: bool = True,
        velocity_threshold: int = 5,
        velocity_window_sec: float = 5.0,
    ):
        self.enable_datacenter_block = enable_datacenter_block
        self.enable_velocity_block = enable_velocity_block
        self.enable_geo_block = enable_geo_block
        self.velocity_threshold = velocity_threshold
        self.velocity_window_sec = velocity_window_sec

        # Known datacenter IP prefixes or IPs
        self.datacenter_ips = {
            "3.5.140.2",
            "34.64.120.1",
            "20.40.10.1",
            "159.89.10.5",
            "185.220.101.5",
        }
        # Non-domestic / foreign IPs for geo test
        self.foreign_ips = {
            "196.25.1.1",
            "185.220.101.5",
            "200.147.67.142",
        }

        # IP request timestamps: ip -> list of timestamps
        self.ip_history = defaultdict(list)
        # Account failure history: account_id -> count
        self.account_failures = defaultdict(int)
        self.lock = threading.Lock()

    def evaluate(self, payload: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
        """Evaluates payload against active rules and returns (status_code, response_dict)."""
        ip = payload.get("ip", "")
        account_id = payload.get("account_id", "")
        login_result = payload.get("login_result", "")
        now = time.time()

        with self.lock:
            # Record velocity
            self.ip_history[ip].append(now)
            # Prune old timestamps
            self.ip_history[ip] = [t for t in self.ip_history[ip] if now - t <= self.velocity_window_sec]
            recent_count = len(self.ip_history[ip])

            if login_result == "failure":
                self.account_failures[account_id] += 1

            # Rule 1: Velocity / Rate-limiting (S3)
            if self.enable_velocity_block and recent_count > self.velocity_threshold:
                return 429, {
                    "action": "block",
                    "reason": "rate_limit_exceeded",
                    "risk_score": 95,
                    "details": f"Velocity limit exceeded ({recent_count} reqs in window)",
                }

            # Rule 2: Datacenter / IP Reputation (S1)
            if self.enable_datacenter_block and ip in self.datacenter_ips:
                return 403, {
                    "action": "block",
                    "reason": "datacenter_ip_detected",
                    "risk_score": 88,
                    "details": f"IP {ip} belongs to known cloud/datacenter provider",
                }

            # Rule 3: Geo Impossible Travel (S2)
            if self.enable_geo_block and ip in self.foreign_ips:
                return 200, {
                    "action": "challenge",
                    "reason": "impossible_travel_anomaly",
                    "risk_score": 75,
                    "details": f"Geographical mismatch detected for IP {ip}",
                }

            # Rule 4: Credential stuffing / failure threshold (S6)
            if self.account_failures[account_id] >= 4 and login_result == "failure":
                return 403, {
                    "action": "block",
                    "reason": "excessive_failed_attempts",
                    "risk_score": 90,
                    "details": f"Account {account_id} reached failed attempt threshold",
                }

            # Default: Allow
            return 200, {
                "action": "allow",
                "risk_score": 10,
                "status": "normal",
            }


class MockTransportAdapter(BaseAdapter):
    """In-process requests adapter routing directly to MockDetectorEngine."""

    def __init__(self, engine: Optional[MockDetectorEngine] = None):
        super().__init__()
        self.engine = engine or MockDetectorEngine()

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        raw_body = request.body or b"{}"
        if isinstance(raw_body, str):
            raw_body = raw_body.encode("utf-8")
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception:
            payload = {}

        status_code, response_data = self.engine.evaluate(payload)

        resp = Response()
        resp.status_code = status_code
        resp.raw = io.BytesIO(json.dumps(response_data).encode("utf-8"))
        resp.headers["Content-Type"] = "application/json"
        resp.request = request
        return resp

    def close(self):
        pass


class MockServerHandler(BaseHTTPRequestHandler):
    """HTTP handler responding to /v1/detect."""

    engine: MockDetectorEngine = MockDetectorEngine()

    def do_POST(self):
        if self.path != "/v1/detect":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error": "Not Found"}')
            return

        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)

        try:
            payload = json.loads(post_data.decode("utf-8"))
        except Exception:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "Invalid JSON"}')
            return

        status_code, response_data = self.engine.evaluate(payload)

        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response_data).encode("utf-8"))

    def log_message(self, format, *args):
        pass


def run_mock_server(host: str = "127.0.0.1", port: int = 8080, engine: Optional[MockDetectorEngine] = None):
    """Runs the mock server blocking."""
    if engine:
        MockServerHandler.engine = engine
    server = ThreadingHTTPServer((host, port), MockServerHandler)
    print(f"[*] Mock EdgeSentry server listening on http://{host}:{port}/v1/detect")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


class BackgroundMockServer:
    """Helper to run mock server in a background thread for tests/CLI."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8088, engine: Optional[MockDetectorEngine] = None):
        self.host = host
        self.port = port
        self.engine = engine or MockDetectorEngine()
        self.server: Optional[ThreadingHTTPServer] = None
        self.thread: Optional[threading.Thread] = None

    def start(self):
        MockServerHandler.engine = self.engine
        self.server = ThreadingHTTPServer((self.host, self.port), MockServerHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        time.sleep(0.1)

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=1.0)
