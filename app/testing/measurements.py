from __future__ import annotations

import asyncio
import math
import re
import statistics
import subprocess
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx


class MeasurementSuite:
    def __init__(self, testing: dict[str, Any], timeout: float, socks_port: int = 10808,
                 target_host: str | None = None, target_port: int | None = None,
                 tcp_connect_timeout: float | None = None, transport: str = "tcp", *,
                 stop_callback: Callable[[], bool] | None = None):
        self.urls = list(testing.get("urls", []))
        self.latency_requests = int(testing.get("latency", {}).get("requests", 3))
        self.stability_requests = int(testing.get("stability", {}).get("requests", 5))
        self.ping = dict(testing.get("ping", {}))
        self.speed_test = dict(testing.get("speed_test", {}))
        self.target_host, self.target_port = target_host, target_port
        self.transport = transport
        self.stop_callback = stop_callback
        self.http = dict(testing.get("http", {}))
        self.http_expectations = dict(testing.get("http_expectations", {}))
        self.max_response_bytes = self._positive_integer(self.http.get("max_response_bytes", 65_536),
                                                         "testing.http.max_response_bytes")
        if self.latency_requests < 0 or self.stability_requests < 0:
            raise ValueError("HTTP request counts must be nonnegative")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("request timeout must be greater than zero")
        self.timeout = timeout
        self.tcp_connect_timeout = tcp_connect_timeout if tcp_connect_timeout is not None else timeout
        if not math.isfinite(self.tcp_connect_timeout) or self.tcp_connect_timeout <= 0:
            raise ValueError("TCP connect timeout must be greater than zero")
        self.proxy = f"socks5://127.0.0.1:{socks_port}"
        for target in self.urls:
            self._target(target)

    @staticmethod
    def _positive_integer(value: Any, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(f"{name} must be a positive integer")
        return value

    def _stopped(self) -> bool:
        return bool(self.stop_callback and self.stop_callback())

    @staticmethod
    def _public_url(url: str) -> str:
        parts = urlsplit(url)
        hostname = parts.hostname or ""
        if ":" in hostname:
            hostname = f"[{hostname}]"
        authority = f"{hostname}:{parts.port}" if parts.port is not None else hostname
        return urlunsplit((parts.scheme, authority, parts.path, "", ""))

    def _target(self, target: Any) -> tuple[str, dict[str, Any]]:
        if isinstance(target, dict):
            url = str(target.get("url", ""))
            local_options = {key: value for key, value in target.items() if key != "url"}
        else:
            url, local_options = str(target), {}
        if urlsplit(url).scheme not in {"http", "https"} or not urlsplit(url).hostname:
            raise ValueError("Measurement URLs must use HTTP or HTTPS and include a hostname")
        options = {**self.http, **self.http_expectations.get(url, {}), **local_options}
        status = options.get("expected_status")
        if status is not None:
            codes = status if isinstance(status, (list, tuple)) else [status]
            if (not codes or any(isinstance(code, bool) or not isinstance(code, int)
                                or not 100 <= code <= 599 for code in codes)):
                raise ValueError("expected_status must be an HTTP status integer or list of integers")
        if options.get("expected_content") is not None and not isinstance(options["expected_content"], (str, bytes)):
            raise ValueError("expected_content must be text or bytes")
        self._positive_integer(options.get("max_response_bytes", self.max_response_bytes), "max_response_bytes")
        return url, options

    def response_allowance(self, requests: int, *, urls: list[Any] | None = None) -> int:
        """Payload sampling allowance for the exact round-robin target sequence."""
        if isinstance(requests, bool) or not isinstance(requests, int) or requests < 0:
            raise ValueError("HTTP request count must be a nonnegative integer")
        targets = self.urls if urls is None else urls
        if not targets:
            raise ValueError("testing.urls must contain at least one URL")
        caps = [self._target(target)[1].get("max_response_bytes", self.max_response_bytes) for target in targets]
        cycles, remainder = divmod(requests, len(caps))
        return cycles * sum(caps) + sum(caps[:remainder])

    async def screen(self, requests: int = 1, *, urls: list[Any] | None = None) -> dict[str, Any]:
        """Cheap viability probe used before the complete measurement suite."""
        targets = self.urls if urls is None else urls
        if not targets:
            raise ValueError("testing.urls must contain at least one URL")
        metrics: dict[str, Any] = {}
        if self.target_host and self.target_port:
            metrics.update(await self._connectivity_metrics())
        async with httpx.AsyncClient(proxy=self.proxy, timeout=self.timeout, trust_env=False) as client:
            metrics.update(await self._http_metrics(client, requests, requests, urls=targets))
        return metrics

    async def run(self, *, include_ping: bool = True, include_speed: bool = True,
                  urls: list[Any] | None = None) -> dict[str, Any]:
        targets = self.urls if urls is None else urls
        if not targets:
            raise ValueError("testing.urls must contain at least one URL")
        metrics: dict[str, Any] = {}
        if self.target_host and self.target_port:
            metrics.update(await self._connectivity_metrics())
        if include_ping and self.target_host and self.ping.get("enabled", True):
            metrics.update(await self._icmp_ping())
        async with httpx.AsyncClient(proxy=self.proxy, timeout=self.timeout, trust_env=False) as client:
            metrics.update(await self._http_metrics(client, self.latency_requests, self.stability_requests, urls=targets))
            if include_speed and self.speed_test.get("enabled") and self.speed_test.get("url") and not self._stopped():
                metrics.update(await self._download_speed(client))
        return metrics

    async def _request_observation(self, client: httpx.AsyncClient, target: Any, number: int) -> dict[str, Any]:
        url, options = self._target(target)
        maximum = options.get("max_response_bytes", self.max_response_bytes)
        started = time.perf_counter()
        observation: dict[str, Any] = {"request_number": number + 1, "url": self._public_url(url),
                                       "started_at": datetime.now(UTC).isoformat(), "status_code": None,
                                       "successful": False, "sampled_bytes": 0, "received_bytes": 0,
                                       "body_truncated": False, "reason_code": "indeterminate"}
        response: httpx.Response | None = None
        body = bytearray()
        try:
            async with asyncio.timeout(self.timeout):
                async with client.stream("GET", url) as response:
                    observation["status_code"] = response.status_code
                    async for chunk in response.aiter_bytes():
                        if self._stopped():
                            observation["reason_code"] = "measurement_stopped"
                            break
                        remaining = maximum - len(body)
                        body.extend(chunk[:remaining])
                        if len(body) >= maximum:
                            observation["body_truncated"] = True
                            break
                    observation["sampled_bytes"] = len(body)
                    observation["received_bytes"] = response.num_bytes_downloaded
                    if observation["reason_code"] != "measurement_stopped":
                        expected = options.get("expected_status")
                        codes = (expected if isinstance(expected, (list, tuple)) else [expected]) if expected is not None else None
                        status_ok = response.status_code in codes if codes is not None else response.is_success
                        content = options.get("expected_content")
                        needle = content.encode("utf-8") if isinstance(content, str) else content
                        content_ok = needle is None or needle in body
                        observation["successful"] = status_ok and content_ok
                        observation["reason_code"] = "ok" if observation["successful"] else "http_semantic_failure"
                        if not status_ok:
                            observation["error_type"] = "HTTPStatusError"
                        elif not content_ok:
                            observation["error_type"] = "ContentMismatch"
        except (httpx.HTTPError, TimeoutError, OSError) as error:
            observation["error_type"] = type(error).__name__
            observation["reason_code"] = ("request_timeout" if isinstance(error, (httpx.TimeoutException, TimeoutError))
                                           else "e2e_connection_failure" if isinstance(error, httpx.ConnectError)
                                           else "http_transport_failure")
        finally:
            if response is not None:
                observation["received_bytes"] = response.num_bytes_downloaded or len(body)
            observation["sampled_bytes"] = len(body)
            observation["finished_at"] = datetime.now(UTC).isoformat()
            observation["duration_ms"] = (time.perf_counter() - started) * 1000
        return observation

    async def _http_metrics(self, client: httpx.AsyncClient, latency_requests: int,
                            stability_requests: int, *, urls: list[Any] | None = None) -> dict[str, Any]:
        targets = self.urls if urls is None else urls
        if not targets:
            raise ValueError("testing.urls must contain at least one URL")
        latencies: list[float] = []
        observations: list[dict[str, Any]] = []
        succeeded = failed = 0
        last_error: str | None = None
        for number in range(max(latency_requests, stability_requests)):
            if self._stopped():
                break
            observation = await self._request_observation(client, targets[number % len(targets)], number)
            observation["counted_for_latency"] = number < latency_requests
            observation["counted_for_stability"] = number < stability_requests
            observations.append(observation)
            if observation["successful"]:
                if number < latency_requests:
                    latencies.append(observation["duration_ms"])
                if number < stability_requests:
                    succeeded += 1
            elif observation["reason_code"] != "measurement_stopped":
                # Do not place an untrusted transport exception string in a result.
                last_error = f"{observation.get('error_type', 'HTTPError')}: {observation['reason_code']}"
                if number < stability_requests:
                    failed += 1
        result: dict[str, Any] = {"successful_requests": succeeded, "failed_requests": failed,
                                  "success_rate": succeeded / (succeeded + failed) if succeeded + failed else 0.0,
                                  "http_request_count": len(observations), "latency_sample_count": len(latencies),
                                  "http_bytes_received": sum(item["received_bytes"] for item in observations),
                                  "http_bytes_sampled": sum(item["sampled_bytes"] for item in observations),
                                  "observations": observations, "measurement_stopped": self._stopped(),
                                  "latency_metric": "bounded HTTP GET including proxy, TLS, headers and sampled response body"}
        if observations:
            result.update({"first_http_request_ms": observations[0]["duration_ms"],
                           "first_http_request_successful": observations[0]["successful"],
                           "connect_time_ms": observations[0]["duration_ms"],
                           "connect_time_metric": "legacy alias of first_http_request_ms; not TCP connect time"})
        if latencies:
            ordered = sorted(latencies)
            result.update({"latency_min_ms": min(latencies), "latency_avg_ms": statistics.mean(latencies),
                           "latency_median_ms": statistics.median(latencies), "latency_max_ms": max(latencies),
                           "latency_p95_ms": ordered[max(0, math.ceil(len(ordered) * .95) - 1)],
                           "latency_p95_sample_count": len(latencies), "latency_p95_limited": len(latencies) < 20,
                           "latency_p95_interpretation": "empirical percentile of successful samples; not a reliability confidence bound"})
        if last_error:
            result["last_http_error"] = last_error
        return result

    @staticmethod
    async def reference_check(urls: list[Any], timeout: float = 5, *, max_response_bytes: int = 65_536,
                              stop_callback: Callable[[], bool] | None = None) -> dict[str, Any]:
        """Direct URL availability control; it does not identify provider filtering."""
        suite = MeasurementSuite({"urls": urls, "http": {"max_response_bytes": max_response_bytes}},
                                 timeout, stop_callback=stop_callback)
        async with httpx.AsyncClient(timeout=timeout, trust_env=False) as client:
            result = await suite._http_metrics(client, len(urls), len(urls))
        return {"reference_ok": bool(result["successful_requests"]),
                "reference_all_ok": result["successful_requests"] == len(urls) and bool(urls),
                "reference_observations": result["observations"],
                "reference_bytes_received": result["http_bytes_received"],
                "reference_request_count": result["http_request_count"],
                "reference_interpretation": "direct URL availability only; no proof of provider blocking"}

    async def _tcp_connect(self) -> dict[str, Any]:
        if self._stopped():
            return {"measurement_stopped": True}
        started = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_host, self.target_port), timeout=self.tcp_connect_timeout,
            )
            elapsed = (time.perf_counter() - started) * 1000
            writer.close()
            await writer.wait_closed()
            return {"tcp_connect_ms": elapsed, "tcp_connect_ok": True}
        except (OSError, TimeoutError):
            return {"tcp_connect_ok": False}

    async def _connectivity_metrics(self) -> dict[str, Any]:
        # mKCP listens on UDP, so a TCP handshake cannot say anything about
        # whether that transport is reachable. The proxy request in screen/run
        # is the actual end-to-end check for KCP.
        if self.transport == "kcp":
            return {"tcp_connect_supported": False}
        return {"tcp_connect_supported": True, **await self._tcp_connect()}

    async def _icmp_ping(self) -> dict[str, Any]:
        requests = max(1, int(self.ping.get("requests", 4)))
        timeout_ms = max(100, int(float(self.ping.get("timeout", 2)) * 1000))
        times: list[float] = []
        sent = 0
        for _ in range(requests):
            if self._stopped():
                break
            sent += 1
            args = (["ping", "-n", "1", "-w", str(timeout_ms), self.target_host]
                    if sys.platform == "win32" else
                    ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), self.target_host])
            try:
                completed = await asyncio.wait_for(
                    asyncio.to_thread(subprocess.run, args, capture_output=True, timeout=timeout_ms / 1000 + 1),
                    timeout=timeout_ms / 1000 + 2,
                )
                output, returncode = completed.stdout + completed.stderr, completed.returncode
                text = output.decode("oem" if sys.platform == "win32" else "utf-8", errors="replace")
                match = re.search(r"(?:time|время)\s*[=<]\s*([0-9.,]+)\s*(?:ms|мс)", text, re.IGNORECASE)
                if returncode == 0:
                    times.append(float(match.group(1).replace(",", ".")) if match else 0.0)
            except (OSError, TimeoutError):
                pass
        received = len(times)
        result: dict[str, Any] = {"ping_sent": sent, "ping_received": received,
                                  "ping_packet_loss_pct": (sent - received) * 100 / sent if sent else 0.0}
        if times:
            result.update({"ping_min_ms": min(times), "ping_avg_ms": statistics.mean(times),
                           "ping_max_ms": max(times), "ping_jitter_ms": statistics.pstdev(times) if len(times) > 1 else 0.0})
        return result

    async def _download_speed(self, client: httpx.AsyncClient) -> dict[str, Any]:
        maximum = self._positive_integer(self.speed_test.get("max_bytes", 5_000_000), "speed_test.max_bytes")
        duration_limit = float(self.speed_test.get("max_duration_seconds", 10))
        if not math.isfinite(duration_limit) or duration_limit <= 0:
            raise ValueError("speed_test.max_duration_seconds must be greater than zero")
        downloaded = 0
        started = time.perf_counter()
        response: httpx.Response | None = None
        termination = "completed"
        error_type: str | None = None
        try:
            if self._stopped():
                termination = "stopped"
            else:
                async with asyncio.timeout(duration_limit):
                    async with client.stream("GET", str(self.speed_test["url"]),
                                             headers={"Accept-Encoding": "identity"}) as response:
                        response.raise_for_status()
                        async for chunk in response.aiter_bytes():
                            if self._stopped():
                                termination = "stopped"
                                break
                            downloaded += min(len(chunk), maximum - downloaded)
                            if downloaded >= maximum:
                                termination = "byte_limit"
                                break
        except TimeoutError:
            termination = "duration_limit"
        except httpx.TimeoutException as error:
            termination, error_type = "request_timeout", type(error).__name__
        except (httpx.HTTPError, OSError) as error:
            termination, error_type = "http_failure", type(error).__name__
        elapsed = time.perf_counter() - started
        result: dict[str, Any] = {"download_bytes": downloaded,
                                  "download_received_bytes": response.num_bytes_downloaded or downloaded if response is not None else downloaded,
                                  "download_seconds": elapsed, "download_termination_reason": termination,
                                  "download_max_bytes": maximum, "download_max_duration_seconds": duration_limit,
                                  "download_metric": "counted response payload bytes per total elapsed HTTP GET duration"}
        if termination in {"completed", "byte_limit", "duration_limit"} and downloaded:
            result["download_mbps"] = downloaded * 8 / elapsed / 1_000_000 if elapsed else 0.0
        if error_type:
            result["download_error"] = f"{error_type}: {termination}"
        return result
