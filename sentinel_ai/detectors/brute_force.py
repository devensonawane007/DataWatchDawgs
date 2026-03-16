"""
detectors/brute_force.py — Detects BruteForceSimulator traffic.

Signature: same IP sends 5+ POST requests to /login within 12 s.
"""

import time
from collections import defaultdict

from shared_state import state
from detectors.base import BaseDetector


class BruteForceDetector(BaseDetector):
    NAME     = "Brute Force"
    INTERVAL = 1.0

    ATTEMPT_THRESHOLD = 5
    TIME_WINDOW       = 12.0

    def analyse(self) -> None:
        attempts_by_ip: dict[str, int] = defaultdict(int)

        for evt in state.recent_events(self.TIME_WINDOW):
            if (
                evt.event_type == "http_request"
                and evt.method == "POST"
                and "/login" in (evt.path or "")
            ):
                attempts_by_ip[evt.src_ip] += 1

        for ip, count in attempts_by_ip.items():
            if count >= self.ATTEMPT_THRESHOLD:
                rate = count / self.TIME_WINDOW
                self._fire(
                    severity    = "HIGH",
                    attack_type = "Brute Force",
                    src_ip      = ip,
                    description = (
                        f"Credential stuffing — {count} POST /login attempts "
                        f"in {self.TIME_WINDOW:.0f}s ({rate:.1f} req/s)"
                    ),
                    auto_block  = True,
                )
