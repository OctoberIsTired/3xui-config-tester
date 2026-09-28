from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import httpx


class PanelAPIError(RuntimeError):
    pass


class ThreeXUIClient:
    """v3.8 adapter. Live OpenAPI discovery is mandatory before mutation."""

    REQUIRED_PATHS = {
        "/panel/api/inbounds/list", "/panel/api/inbounds/get/{id}",
        "/panel/api/inbounds/add", "/panel/api/inbounds/update/{id}",
        "/panel/api/inbounds/del/{id}", "/panel/api/server/status",
    }
    XRAY_LOG_PATH = "/panel/api/server/xraylogs/{count}"
    REALITY_SCAN_PATH = "/panel/api/server/scanRealityTarget"

    def __init__(self, panel: dict[str, Any], timeout: float = 10):
        url = str(panel.get("url", "")).rstrip("/")
        if not url:
            raise ValueError("panel.url is required")
        self.base_url = url
        self.panel = panel
        # A system proxy can silently intercept a private panel URL and turn a
        # working direct connection into a ConnectTimeout. Opt in explicitly
        # when the panel really needs environment proxy settings.
        self.client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=panel.get("verify_tls", True),
            trust_env=panel.get("trust_env", False),
        )
        self.openapi: dict[str, Any] | None = None
        self._csrf: str | None = None

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    async def discover(self) -> dict[str, Any]:
        response = await self.client.get(self._url("/panel/api/openapi.json"))
        response.raise_for_status()
        spec = response.json()
        paths = set(spec.get("paths", {}))
        missing = self.REQUIRED_PATHS - paths
        if missing:
            raise PanelAPIError(f"Panel OpenAPI lacks required paths: {', '.join(sorted(missing))}")
        self.openapi = spec
        return spec

    async def authenticate(self) -> None:
        token = self.panel.get("api_token")
        if token and not str(token).startswith("${"):
            self.client.headers["Authorization"] = f"Bearer {token}"
            return
        username, password = self.panel.get("username"), self.panel.get("password")
        if not username or not password or str(username).startswith("${") or str(password).startswith("${"):
            raise ValueError("Set panel.api_token or PANEL_USERNAME/PANEL_PASSWORD")
        response = await self.client.post(self._url("/login"), json={"username": username, "password": password})
        response.raise_for_status()
        data = response.json()
        if not data.get("success", False):
            raise PanelAPIError(f"Login rejected: {data.get('msg', 'unknown error')}")
        csrf = await self.client.get(self._url("/panel/api/csrf"))
        if csrf.is_success:
            self._csrf = csrf.json().get("obj")
            if self._csrf:
                self.client.headers["X-CSRF-Token"] = self._csrf

    @staticmethod
    def _obj(response: httpx.Response) -> Any:
        response.raise_for_status()
        data = response.json()
        if not data.get("success", False):
            raise PanelAPIError(str(data.get("msg", "panel API returned success=false")))
        return data.get("obj")

    async def list_inbounds(self) -> list[dict[str, Any]]:
        return list(self._obj(await self.client.get(self._url("/panel/api/inbounds/list"))))

    async def get_inbound(self, inbound_id: int) -> dict[str, Any]:
        result = self._obj(await self.client.get(self._url(f"/panel/api/inbounds/get/{inbound_id}")))
        if not result:
            raise PanelAPIError(f"Inbound {inbound_id} was not returned")
        return result

    async def create_inbound(self, payload: dict[str, Any]) -> dict[str, Any]:
        return self._obj(await self.client.post(self._url("/panel/api/inbounds/add"), json=payload))

    async def update_inbound(self, inbound_id: int, payload: dict[str, Any]) -> dict[str, Any]:
        return self._obj(await self.client.post(self._url(f"/panel/api/inbounds/update/{inbound_id}"), json=payload))

    async def delete_inbound(self, inbound_id: int) -> None:
        self._obj(await self.client.post(self._url(f"/panel/api/inbounds/del/{inbound_id}"), json={}))

    async def server_status(self) -> dict[str, Any]:
        return dict(self._obj(await self.client.get(self._url("/panel/api/server/status"))))

    async def scan_reality_target(self, target: str, sni: str, xver: int = 0) -> dict[str, Any]:
        if not self.openapi or "post" not in self.openapi.get("paths", {}).get(self.REALITY_SCAN_PATH, {}):
            raise PanelAPIError("Panel OpenAPI lacks scanRealityTarget; REALITY target checks require a newer panel")
        response = await self.client.post(self._url(self.REALITY_SCAN_PATH),
                                          data={"target": target, "sni": sni, "xver": str(xver), "allowPrivate": "false"},
                                          timeout=max(float(self.client.timeout.read or 10), 15))
        return dict(self._obj(response))

    async def xray_logs(self, count: int = 20) -> str | None:
        """Read optional server logs in memory; callers must only persist categories."""
        if not self.openapi or "post" not in self.openapi.get("paths", {}).get(self.XRAY_LOG_PATH, {}):
            return None
        count = max(1, min(int(count), 200))
        try:
            value = self._obj(await self.client.post(self._url(f"/panel/api/server/xraylogs/{count}")))
        except (httpx.HTTPError, PanelAPIError, ValueError, TypeError):
            return None
        if value is None:
            return None
        output = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
        return output[-64 * 1024:] or None

    async def aclose(self) -> None:
        await self.client.aclose()
