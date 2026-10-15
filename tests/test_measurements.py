import asyncio
from datetime import datetime

import httpx
import pytest

from app.testing.measurements import MeasurementSuite


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], *, delay: float = 0) -> None:
        self.chunks, self.delay = chunks, delay
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            if self.delay:
                await asyncio.sleep(self.delay)
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def http_metrics(suite: MeasurementSuite, handler, latency: int, stability: int) -> dict:
    async def measure() -> dict:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await suite._http_metrics(client, latency, stability)
    return asyncio.run(measure())


def download_metrics(suite: MeasurementSuite, stream: Chunks) -> dict:
    async def measure() -> dict:
        async with httpx.AsyncClient(transport=httpx.MockTransport(
                lambda request: httpx.Response(200, stream=stream))) as client:
            return await suite._download_speed(client)
    return asyncio.run(measure())


def test_http_records_each_target_status_semantics_timestamps_and_sample_counts() -> None:
    suite = MeasurementSuite({"urls": [
        {"url": "https://fixture.test/ok", "expected_status": 200, "expected_content": "healthy"},
        {"url": "https://fixture.test/mismatch", "expected_status": [200, 204], "expected_content": "healthy"},
        {"url": "https://fixture.test/no-content", "expected_status": 204},
    ]}, timeout=1)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/no-content":
            return httpx.Response(204)
        return httpx.Response(200, content=b"healthy" if request.url.path == "/ok" else b"intercepted")

    metrics = http_metrics(suite, handler, 3, 3)
    assert metrics["successful_requests"] == 2
    assert metrics["failed_requests"] == 1
    assert metrics["latency_sample_count"] == 2
    assert metrics["latency_p95_sample_count"] == 2
    assert metrics["latency_p95_limited"] is True
    assert metrics["connect_time_ms"] == metrics["first_http_request_ms"]
    assert "not TCP" in metrics["connect_time_metric"]
    assert metrics["http_bytes_sampled"] == len(b"healthyintercepted")
    assert metrics["http_request_count"] == 3
    observations = metrics["observations"]
    assert [item["status_code"] for item in observations] == [200, 200, 204]
    assert observations[1]["reason_code"] == "http_semantic_failure"
    assert observations[1]["error_type"] == "ContentMismatch"
    for observation in observations:
        assert datetime.fromisoformat(observation["finished_at"]) >= datetime.fromisoformat(observation["started_at"])
        assert observation["duration_ms"] >= 0


def test_http_500_is_failure_even_when_network_request_succeeds() -> None:
    suite = MeasurementSuite({"urls": ["https://fixture.test/"]}, timeout=1)
    metrics = http_metrics(suite, lambda request: httpx.Response(500), 1, 1)
    assert metrics["failed_requests"] == 1
    assert metrics["latency_sample_count"] == 0
    assert metrics["observations"][0]["error_type"] == "HTTPStatusError"
    assert metrics["observations"][0]["status_code"] == 500
    assert metrics["first_http_request_successful"] is False


def test_http_timeout_reason_does_not_persist_exception_or_url_credentials() -> None:
    suite = MeasurementSuite({"urls": ["https://fake-user:FAKE_PASSWORD@fixture.test/check?token=FAKE_TOKEN"]}, timeout=1)

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("FAKE_EXCEPTION_SECRET", request=request)

    metrics = http_metrics(suite, timeout, 1, 1)
    observation = metrics["observations"][0]
    assert observation["reason_code"] == "request_timeout"
    assert observation["error_type"] == "ReadTimeout"
    assert observation["url"] == "https://fixture.test/check"
    assert "FAKE_" not in str(metrics)


def test_body_read_is_bounded_and_stream_closed_after_limit() -> None:
    stream = Chunks([b"a" * 20, b"b" * 20])
    suite = MeasurementSuite({"urls": ["https://fixture.test/"], "http": {"max_response_bytes": 7}}, timeout=1)
    metrics = http_metrics(suite, lambda request: httpx.Response(200, stream=stream), 1, 1)
    observation = metrics["observations"][0]
    assert observation["sampled_bytes"] == 7
    assert observation["received_bytes"] >= observation["sampled_bytes"]
    assert observation["body_truncated"] is True
    assert stream.closed


def test_expected_content_outside_bounded_sample_is_not_treated_as_verified() -> None:
    suite = MeasurementSuite({"urls": [{"url": "https://fixture.test/", "expected_content": "healthy"}],
                               "http": {"max_response_bytes": 4}}, timeout=1)
    metrics = http_metrics(suite, lambda request: httpx.Response(200, content=b"paddinghealthy"), 1, 1)
    assert metrics["failed_requests"] == 1
    assert metrics["observations"][0]["sampled_bytes"] == 4
    assert metrics["observations"][0]["body_truncated"]


def test_global_and_per_url_expectations_merge() -> None:
    suite = MeasurementSuite({"urls": ["https://fixture.test/"], "http": {"expected_status": 200},
                               "http_expectations": {"https://fixture.test/": {"expected_status": 202,
                                                                                "expected_content": "accepted"}}}, timeout=1)
    metrics = http_metrics(suite, lambda request: httpx.Response(202, content=b"accepted"), 1, 1)
    assert metrics["successful_requests"] == 1


def test_response_allowance_uses_exact_round_robin_sequence_and_option_precedence() -> None:
    first, second, third = (f"https://fixture.test/{name}" for name in ("first", "second", "third"))
    suite = MeasurementSuite({"urls": [first, {"url": second, "max_response_bytes": 40}, third],
        "http": {"max_response_bytes": 10},
        "http_expectations": {second: {"max_response_bytes": 20}, third: {"max_response_bytes": 7}}}, timeout=1)
    assert suite.response_allowance(0) == 0
    assert suite.response_allowance(1) == 10
    assert suite.response_allowance(5) == 107
    assert suite.response_allowance(2, urls=[third, second]) == 27
    assert suite.response_allowance(2, urls=[{"url": second, "max_response_bytes": 40}, first]) == 50


def test_reference_honors_expected_non_success_status_and_content(monkeypatch) -> None:
    real_client = httpx.AsyncClient
    def factory(**kwargs):
        return real_client(**kwargs, transport=httpx.MockTransport(
            lambda request: httpx.Response(404, content=b"healthy")))
    monkeypatch.setattr("app.testing.measurements.httpx.AsyncClient", factory)
    metrics = asyncio.run(MeasurementSuite.reference_check([
        {"url": "https://fixture.test/", "expected_status": 404,
         "expected_content": "healthy", "max_response_bytes": 20}], timeout=1))
    assert metrics["reference_ok"] and metrics["reference_all_ok"]


def test_stop_during_body_does_not_count_candidate_as_failed() -> None:
    state = {"stopped": False, "requests": 0}
    suite = MeasurementSuite({"urls": ["https://fixture.test/"]}, timeout=1,
                             stop_callback=lambda: state["stopped"])

    def handler(request: httpx.Request) -> httpx.Response:
        state["requests"] += 1
        state["stopped"] = True
        return httpx.Response(200, content=b"body")

    metrics = http_metrics(suite, handler, 5, 5)
    assert state["requests"] == 1
    assert metrics["measurement_stopped"] is True
    assert metrics["failed_requests"] == 0
    assert metrics["successful_requests"] == 0
    assert metrics["observations"][0]["reason_code"] == "measurement_stopped"


def test_speed_byte_cap_does_not_count_chunk_overshoot() -> None:
    stream = Chunks([b"a" * 19, b"b" * 19])
    suite = MeasurementSuite({"urls": ["https://fixture.test/"],
                               "speed_test": {"url": "https://fixture.test/download", "max_bytes": 7,
                                              "max_duration_seconds": 1}}, timeout=1)
    metrics = download_metrics(suite, stream)
    assert metrics["download_bytes"] == 7
    assert metrics["download_termination_reason"] == "byte_limit"
    assert metrics["download_mbps"] > 0
    assert metrics["download_received_bytes"] >= 7
    assert stream.closed


def test_speed_total_duration_caps_a_stream_with_continuous_slow_data() -> None:
    class SlowStream(Chunks):
        async def __aiter__(self):
            yield b"a"
            await asyncio.sleep(1)
            yield b"b"

    stream = SlowStream([])
    suite = MeasurementSuite({"urls": ["https://fixture.test/"],
                               "speed_test": {"url": "https://fixture.test/download", "max_bytes": 100,
                                              "max_duration_seconds": .035}}, timeout=1)
    metrics = download_metrics(suite, stream)
    assert metrics["download_termination_reason"] == "duration_limit"
    assert metrics["download_seconds"] < .5
    assert 0 < metrics["download_bytes"] <= 100
    assert metrics["download_mbps"] > 0
    assert stream.closed


def test_http_total_request_timeout_caps_body_stream() -> None:
    stream = Chunks([b"a"] * 10, delay=.01)
    suite = MeasurementSuite({"urls": ["https://fixture.test/"]}, timeout=.025)
    metrics = http_metrics(suite, lambda request: httpx.Response(200, stream=stream), 1, 1)
    assert metrics["observations"][0]["reason_code"] == "request_timeout"
    assert metrics["observations"][0]["duration_ms"] < 500
    assert stream.closed


def test_reference_uses_direct_client_and_reports_only_url_availability(monkeypatch) -> None:
    real_client = httpx.AsyncClient
    configurations: list[dict] = []

    def factory(**kwargs):
        configurations.append(kwargs.copy())
        return real_client(**kwargs, transport=httpx.MockTransport(lambda request: httpx.Response(200)))

    monkeypatch.setattr("app.testing.measurements.httpx.AsyncClient", factory)
    metrics = asyncio.run(MeasurementSuite.reference_check(["https://fixture.test/"], timeout=1))
    assert configurations == [{"timeout": 1, "trust_env": False}]
    assert metrics["reference_ok"]
    assert metrics["reference_all_ok"]
    assert "no proof" in metrics["reference_interpretation"]


def test_screen_keeps_socks_proxy_and_disables_environment_proxy(monkeypatch) -> None:
    real_client = httpx.AsyncClient
    configurations: list[dict] = []

    def factory(**kwargs):
        configurations.append(kwargs.copy())
        kwargs.pop("proxy", None)
        return real_client(**kwargs, transport=httpx.MockTransport(lambda request: httpx.Response(204)))

    monkeypatch.setattr("app.testing.measurements.httpx.AsyncClient", factory)
    suite = MeasurementSuite({"urls": ["https://fixture.test/"]}, timeout=1, socks_port=10809)
    metrics = asyncio.run(suite.screen())
    assert configurations == [{"proxy": "socks5://127.0.0.1:10809", "timeout": 1, "trust_env": False}]
    assert metrics["successful_requests"] == 1


@pytest.mark.parametrize("options", [{"expected_status": True}, {"expected_status": [200, 9]},
                                     {"max_response_bytes": .5}, {"expected_content": {"unsupported": True}}])
def test_invalid_http_expectations_rejected_before_network(options) -> None:
    with pytest.raises(ValueError):
        MeasurementSuite({"urls": [{"url": "https://fixture.test/", **options}]}, timeout=1)
