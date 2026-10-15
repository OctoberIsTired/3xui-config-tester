"""Configure this user's single-port adaptive search without printing credentials."""
from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.config import load_config
from app.security.private_files import secure_file


path = ROOT / "configs" / "local.yaml"
data = yaml.safe_load(path.read_text(encoding="utf-8"))
token = os.environ.get("PANEL_API_TOKEN")
if token:
    data.setdefault("panel", {})["api_token"] = token
data["inbound"].update({"mode": "clone", "topology": "direct", "test_port": 9443})
testing = data.setdefault("testing", {})
testing.update({"ports": [9443], "require_direct_route": True, "combination_strategy": "adaptive", "max_combinations": 120})
testing.pop("port_range", None)
timeouts = data.setdefault("timeouts", {})
timeouts["screening"] = max(float(timeouts.get("screening", 8)),
                           float(timeouts.get("tcp_connect", 3)) + float(timeouts.get("request", 5)) + 2)
testing["adaptive"] = {**testing.get("adaptive", {}), "goal": "first_confirmed", "time_budget_seconds": 600,
                       "request_budget": 600, "traffic_budget_bytes": 30_000_000, "confirmation_windows": 3,
                       "confirmation_requests": 5, "window_delay_seconds": 2}
testing["urls"] = list(dict.fromkeys([*testing.get("urls", []), "https://example.com", "https://www.gstatic.com/generate_204"]))
testing["confirmation_urls"] = ["https://www.gstatic.com/generate_204", "https://www.cloudflare.com/cdn-cgi/trace"]
for parameter in data.get("parameters", {}).values():
    if parameter.get("target", "inbound") == "inbound" and parameter.get("path", [])[-1:] == ["acceptProxyProtocol"]:
        parameter["values"] = [False]
        parameter["baseline"] = False
        parameter["mutate"] = False
temporary = path.with_name(f".local-{uuid.uuid4().hex}.tmp.yaml")
try:
    with temporary.open("x", encoding="utf-8") as handle:
        secure_file(temporary)
        yaml.safe_dump(data, handle, allow_unicode=True, sort_keys=False)
        handle.flush()
        os.fsync(handle.fileno())
    load_config(temporary)
    temporary.replace(path)
finally:
    temporary.unlink(missing_ok=True)
print("Local search configured: clone/direct, port 9443, adaptive, protected credentials; parameter domains preserved.")
