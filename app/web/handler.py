"""HTTP layer: request routing, error mapping and static serving."""
from __future__ import annotations

import inspect
import json
import re
import sys
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from app.security.masking import mask_secrets
from app.web.service import WebService


class RequestError(ValueError):
    def __init__(self, message: str, status: HTTPStatus = HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status = status


class Handler(BaseHTTPRequestHandler):
    service: WebService
    timeout = 30  # a hung client must not hold a worker thread forever
    MAX_REQUEST_BYTES = 2 * 1024 * 1024

    STATIC_ROOT = Path(__file__).resolve().parent.parent / "static"
    STATIC_TYPES = {".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}
    DOWNLOAD_STATUS = {
        ValueError: HTTPStatus.BAD_REQUEST,
        FileNotFoundError: HTTPStatus.NOT_FOUND,
        RuntimeError: HTTPStatus.CONFLICT,
    }

    def log_message(self, *_: object) -> None:
        return

    def _public_payload(self, value: Any) -> Any:
        redactor = getattr(self.service, "public_payload", mask_secrets)
        return redactor(value)

    def _json(self, payload: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(self._public_payload(payload), ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        if self.headers.get("Transfer-Encoding"):
            raise RequestError("Transfer-Encoding is not supported")
        lengths = self.headers.get_all("Content-Length", [])
        if len(lengths) != 1 or not re.fullmatch(r"[0-9]+", lengths[0]):
            raise RequestError("One valid Content-Length is required")
        length = int(lengths[0])
        if length > self.MAX_REQUEST_BYTES:
            self.close_connection = True
            raise RequestError("Request body is too large", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
        if self.headers.get_content_type() != "application/json":
            raise RequestError("Content-Type must be application/json", HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise RequestError("Incomplete request body")
        body = json.loads(raw)
        if not isinstance(body, dict):
            raise RequestError("Request JSON must be an object")
        return body

    def _check_request_origin(self) -> None:
        """Reject DNS rebinding and browser requests from another origin."""
        hosts = self.headers.get_all("Host", [])
        if len(hosts) != 1:
            raise RequestError("One loopback Host header is required", HTTPStatus.FORBIDDEN)
        try:
            host = urlsplit("http://" + hosts[0])
            port = host.port or 80
            if (host.hostname not in {"127.0.0.1", "localhost"} or
                    port != self.server.server_address[1] or host.username or host.password or
                    host.path or host.query or host.fragment):
                raise ValueError("Invalid loopback host")
            origins = self.headers.get_all("Origin", [])
            if len(origins) > 1:
                raise ValueError("Multiple origins")
            if origins:
                origin = urlsplit(origins[0])
                if (origin.scheme != "http" or origin.hostname != host.hostname or
                        (origin.port or 80) != port or origin.username or origin.password or
                        origin.path or origin.query or origin.fragment):
                    raise ValueError("Cross-origin request")
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                raise ValueError("Cross-site request")
        except ValueError:
            raise RequestError("Only same-origin loopback requests are allowed", HTTPStatus.FORBIDDEN) from None

    def _send_bytes(self, body: bytes, content_type: str, *, download: str | None = None) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        if download:
            self.send_header("Content-Disposition", f'attachment; filename="{download}"')
            self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # Dispatch is table-driven: (method, path) -> handler(self) / handler(self, body).
    def do_GET(self) -> None:  # noqa: N802
        self._dispatch(GET_ROUTES)

    def do_POST(self) -> None:  # noqa: N802
        try:
            self._check_request_origin()
            body = self._body()
        except (ValueError, UnicodeDecodeError) as error:
            self._json(self._error_payload(error), getattr(error, "status", HTTPStatus.BAD_REQUEST))
            return
        self._dispatch(POST_ROUTES, body)

    def _dispatch(self, routes: dict[str, Any], body: dict[str, Any] | None = None) -> None:
        try:
            self._check_request_origin()
            parsed = urlsplit(self.path)
            entry = routes.get(parsed.path)
            saved = SAVED_DASHBOARD_ROUTE.fullmatch(parsed.path)
            recovery = RECOVERY_ROUTE.fullmatch(parsed.path)
            continuation = CONTINUE_ROUTE.fullmatch(parsed.path)
            if self.command == "GET" and parsed.path == "/api/run/dashboard":
                self._json(self.service.run_dashboard(self._dashboard_query(parsed.query)))
            elif self.command == "GET" and saved is not None:
                self._json(self.service.saved_run_dashboard(saved.group(1), self._dashboard_query(parsed.query)))
            elif self.command == "POST" and recovery is not None:
                self._json(self.service.recover_run(recovery.group(1)), HTTPStatus.ACCEPTED)
            elif self.command == "POST" and continuation is not None:
                self._json(self.service.continue_run(continuation.group(1), body or {}), HTTPStatus.ACCEPTED)
            elif entry is not None:
                handler, status = entry
                result = handler(self.service) if body is None else handler(self.service, body)
                self._json(result, status)
            elif not self.path.startswith("/api/"):
                self._serve_page_or_static()
            elif (download := DOWNLOAD_ROUTE.fullmatch(self.path)) is not None:
                self._serve_download(download.group(1), download.group(2))
            else:
                self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)
        except Exception as error:
            status = error.status if isinstance(error, RequestError) else self.DOWNLOAD_STATUS.get(type(error), HTTPStatus.INTERNAL_SERVER_ERROR)
            self._json(self._error_payload(error, masked=status is HTTPStatus.INTERNAL_SERVER_ERROR), status)

    @staticmethod
    def _dashboard_query(query: str) -> dict[str, int]:
        parsed = parse_qs(query, keep_blank_values=True)
        values = {}
        for name, default in (("cursor", "0"), ("limit", "100")):
            raw = parsed.get(name, [default])
            if len(raw) != 1 or not re.fullmatch(r"[0-9]+", raw[0]):
                raise ValueError("Invalid dashboard pagination")
            values[name] = int(raw[0])
        if not 1 <= values["limit"] <= 200:
            raise ValueError("Dashboard limit must be in 1..200")
        return values

    def _error_payload(self, error: Exception, *, masked: bool = False) -> dict[str, Any]:
        if masked:
            print(self._public_payload(traceback.format_exc()), file=sys.stderr)
            return {"error": type(error).__name__, "message": "Internal server error"}
        return {"error": type(error).__name__, "message": str(error)}

    def _serve_page_or_static(self) -> None:
        if self.path == "/":
            self._send_bytes(PAGE.encode("utf-8"), "text/html; charset=utf-8")
            return
        static = self.STATIC_ROOT / self.path.removeprefix("/static/").lstrip("/")
        if self.path.startswith("/static/") and static.resolve().is_relative_to(self.STATIC_ROOT.resolve()) and static.is_file():
            self._send_bytes(static.read_bytes(), self.STATIC_TYPES.get(static.suffix, "application/octet-stream"))
        else:
            self._json({"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def _serve_download(self, run_id: str, filename: str) -> None:
        report = self.service.report_path(run_id, filename)
        content_type = {
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".csv": "text/csv; charset=utf-8",
            ".json": "application/json; charset=utf-8",
            ".jsonl": "application/x-ndjson; charset=utf-8",
            ".log": "text/plain; charset=utf-8",
            ".txt": "text/plain; charset=utf-8",
        }[report.suffix]
        body = report.read_bytes()
        if report.suffix == ".json":
            body = json.dumps(self._public_payload(json.loads(body.decode("utf-8"))), ensure_ascii=False).encode("utf-8")
        elif report.suffix == ".jsonl":
            lines = []
            for line in body.decode("utf-8").splitlines():
                try:
                    lines.append(json.dumps(self._public_payload(json.loads(line)), ensure_ascii=False))
                except ValueError:
                    lines.append(self._public_payload(line))
            body = ("\n".join(lines) + ("\n" if body.endswith(b"\n") else "")).encode("utf-8")
        elif report.suffix in {".txt", ".log", ".csv"}:
            body = self._public_payload(body.decode("utf-8")).encode("utf-8")
        self._send_bytes(body, content_type, download=report.name)


def _service_call(name: str) -> Any:
    return lambda service: getattr(service, name)()


def _service_post(name: str | Any) -> Any:
    """POST-обработчик: тело передаётся только методам, которые его принимают.

    Раньше тело передавалось всегда, и эндпоинт без аргумента (`stop_run`)
    падал с TypeError, который маскировался в «Internal server error».
    """
    method = name if callable(name) else getattr(WebService, name)
    if len(inspect.signature(method).parameters) > 1:
        return lambda service, body: method(service, body)
    return lambda service, body: method(service)


GET_ROUTES = {path: (_service_call(name), HTTPStatus.OK) for path, name in {
    "/api/config": "public_config",
    "/api/inbounds": "list_inbounds",
    "/api/registry": "registry",
    "/api/reality/default-candidates": "default_reality_candidates",
    "/api/run/status": "run_status",
    "/api/run/dashboard": "run_dashboard",
    "/api/runs": "list_runs",
}.items()}

POST_ROUTES = {path: (_service_post(name), status) for path, (name, status) in {
    "/api/config": ("save", HTTPStatus.OK),
    "/api/preview": ("preview", HTTPStatus.OK),
    "/api/inbounds": ("list_inbounds", HTTPStatus.OK),
    "/api/reality/import": (lambda service, body: WebService.import_reality_candidates(str(body.get("content", ""))), HTTPStatus.OK),
    "/api/run/start": ("start_run", HTTPStatus.ACCEPTED),
    "/api/run/stop": ("stop_run", HTTPStatus.ACCEPTED),
}.items()}

DOWNLOAD_ROUTE = re.compile(r"/api/runs/(\d{8}-\d{6}-[0-9a-f]{8})/download/([\w.-]+)\Z")
SAVED_DASHBOARD_ROUTE = re.compile(r"/api/runs/(\d{8}-\d{6}-[0-9a-f]{8})/dashboard\Z")
RECOVERY_ROUTE = re.compile(r"/api/runs/(\d{8}-\d{6}-[0-9a-f]{8})/recover\Z")
CONTINUE_ROUTE = re.compile(r"/api/runs/(\d{8}-\d{6}-[0-9a-f]{8})/continue\Z")


# Kept separate from the backend so the UI can evolve without mixing browser code and API code.
PAGE = (Path(__file__).resolve().parent.parent / "web_ui.html").read_text(encoding="utf-8")

