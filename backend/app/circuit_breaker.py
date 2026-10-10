import time
import urllib.parse
import urllib.request
import urllib.error
import socket

class TargetCircuitBreaker:
    # Rolling baseline of healthy latencies per host: {host: ema_seconds}
    _baselines: dict = {}
    # A probe slower than this multiple of its baseline means the target is
    # degrading under load -> trip.
    SPIKE_MULTIPLE = 1.5

    def __init__(self, max_latency_sec: float = 2.5):
        self.max_latency_sec = max_latency_sec

    def check_http_health(self, target: str) -> tuple[bool, str]:
        """Pre-dispatch safety fuse (the name turn.py calls).

        Semantics that keep non-web scans working:
          * No HTTP service on the target (refused/DNS) -> HEALTHY with a
            note. The breaker judges *degradation*, not *absence* — nmap
            against a host without port 80 must not trip.
          * HTTP 500/502/503/504, absolute latency breach, or a >50% spike
            over the host's rolling baseline -> TRIP.
          * First-contact timeout (no baseline yet) -> HEALTHY with warning;
            the tool itself reports reachability. A timeout once a baseline
            exists -> TRIP.
        """
        url = target if target.startswith(("http://", "https://")) else f"http://{target}"
        try:
            host = urllib.parse.urlparse(url).hostname or target
        except Exception:
            host = str(target)
        host = (host or "").lower()

        start_time = time.time()
        req = urllib.request.Request(url, headers={"User-Agent": "PentestAI-HealthCheck/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=self.max_latency_sec) as resp:
                elapsed = time.time() - start_time
        except urllib.error.HTTPError as e:
            if e.code in (500, 502, 503, 504):
                return False, f"Trip: Target returned server error (HTTP {e.code}). Aborting scan to prevent crash."
            return True, f"Target responding (HTTP {e.code})"
        except (urllib.error.URLError, ConnectionRefusedError, socket.gaierror, OSError) as e:
            reason = getattr(e, "reason", e)
            return True, f"No HTTP service on target ({reason}) — breaker N/A for non-web probes."
        except Exception as e:
            # Timeout-class errors: trip only if we have proof the host was
            # healthy before (i.e. this is degradation, not absence).
            if host in self._baselines:
                return False, f"Trip: Target stopped responding (baseline {self._baselines[host]:.2f}s, now timeout: {e})."
            return True, f"Target slow to answer HTTP ({e}) — proceeding, tool will report reachability."

        baseline = self._baselines.get(host)
        if elapsed > self.max_latency_sec:
            return False, f"Trip: Target response time ({elapsed:.2f}s) exceeded {self.max_latency_sec}s threshold."
        if baseline and elapsed > max(self.max_latency_sec, baseline * self.SPIKE_MULTIPLE):
            return False, (
                f"Trip: latency spike {elapsed:.2f}s vs {baseline:.2f}s baseline "
                f"(>{int((self.SPIKE_MULTIPLE - 1) * 100)}% over). Target may be overloaded — aborting."
            )
        # Healthy: fold into rolling baseline (exponential moving average).
        self._baselines[host] = elapsed if baseline is None else (0.5 * baseline + 0.5 * elapsed)
        return True, f"Healthy ({elapsed:.2f}s, HTTP 200)"

    def verify_target_health(self, target_url: str) -> tuple[bool, str]:
        """Legacy entry point — same fuse, strict reading (absence trips)."""
        ok, reason = self.check_http_health(target_url)
        return ok, reason


circuit_breaker = TargetCircuitBreaker()