"""Bounded, explicitly real clone integration on the user's only open port, 9443.

Credentials are read only from the local configuration/environment. No source
payload or unredacted exception is printed. This is a development integration
tool; the application's entry point remains the local Web UI.
"""
from __future__ import annotations

import argparse
import asyncio
import copy
import json
import sys
import uuid
from dataclasses import replace
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from app.api.three_xui import ThreeXUIClient
from app.config import load_config
from app.parameters.generator import configuration_hash
from app.security.masking import SecretRedactor
from app.state.checkpoint import atomic_json
from app.testing.runner import ExperimentRunner


def source_fingerprint(inbound):
    fields = {key: inbound.get(key) for key in ("id", "enable", "protocol", "port", "listen", "settings",
                                               "streamSettings", "sniffing", "allocate")}
    for key in ("settings", "streamSettings", "sniffing", "allocate"):
        if isinstance(fields[key], str):
            try:
                fields[key] = json.loads(fields[key])
            except ValueError:
                pass
    return configuration_hash(fields)


async def main(mode: str, count: int, profiles: bool = False):
    original = load_config(ROOT / "configs" / "local.yaml")
    testing = copy.deepcopy(original.testing)
    testing.update({"ports": [9443], "combination_strategy": "adaptive", "max_combinations": count,
                    "require_direct_route": True, "validate_config": True})
    testing["speed_test"] = {**testing.get("speed_test", {}), "enabled": False}
    testing["urls"] = list(dict.fromkeys([*testing.get("urls", []), "https://example.com",
                                         "https://www.gstatic.com/generate_204"]))
    testing["confirmation_urls"] = ["https://www.gstatic.com/generate_204", "https://www.cloudflare.com/cdn-cgi/trace"]
    testing["adaptive"] = {**testing.get("adaptive", {}), "goal": "first_confirmed", "time_budget_seconds": 300,
                           "request_budget": 100, "apply_budget": 30, "traffic_budget_bytes": 5_000_000,
                           "confirmation_windows": 3, "confirmation_requests": 5,
                           "comparison_requests": 4, "window_delay_seconds": 2, "screening_retries": 1}
    run_id = f"{datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:8]}"
    output_dir = original.output_dir / "runs" / run_id
    if not output_dir.resolve().is_relative_to(ROOT):
        raise ValueError("This integration tool writes results only inside the project")
    parameters = () if mode == "baseline" else original.parameters
    if profiles and mode == "search":
        # Only this bounded integration broadens transport seeds. Preserve the
        # user's saved parameter choices and TLS policy in local.yaml.
        parameters = tuple(replace(item, values=("tcp", "ws", "grpc", "httpupgrade", "xhttp"), mutate=True)
                           if item.target == "inbound" and item.path == ("streamSettings", "network")
                           else item for item in parameters)
    config = replace(original, inbound={**original.inbound, "mode": "clone", "topology": "direct", "test_port": 9443},
                     parameters=parameters,
                     testing=testing, output={"directory": str(output_dir), "formats": ["json", "csv"]})
    redactor = SecretRedactor.from_config(config)
    panel = ThreeXUIClient(config.panel, config.api_timeout)
    runner = None
    try:
        await panel.authenticate()
        await panel.discover()
        source = await panel.get_inbound(int(config.inbound["source_id"]))
        before = source_fingerprint(source)
        ids_before = {item["id"] for item in await panel.list_inbounds()}
        redactor.add(source)
        def progress(event):
            print(json.dumps({key: event[key] for key in ("stage", "completed", "confirmed_candidates", "lifecycle_state")
                              if key in event}), flush=True)
        runner = ExperimentRunner(config, panel, progress)
        summary = await runner.run()
        after = source_fingerprint(await panel.get_inbound(int(config.inbound["source_id"])))
        ids_after = {item["id"] for item in await panel.list_inbounds()}
        summary.update({"kind": "real_clone_integration", "mode": mode, "transport_profiles": profiles, "test_port": 9443,
                        "source_unchanged": before == after, "panel_resource_ids_restored": ids_before == ids_after,
                        "run_id": run_id})
        public = redactor(summary)
        atomic_json(output_dir / "integration-summary.json", public)
        print(json.dumps(public, ensure_ascii=False), flush=True)
        return 0 if before == after and ids_before == ids_after and not summary.get("cleanup_pending") else 2
    except Exception as error:
        message = (runner.redactor if runner else redactor).redact_text(f"{type(error).__name__}: {error}")
        print(json.dumps({"kind": "real_clone_integration", "mode": mode, "error": message, "run_id": run_id}), flush=True)
        return 1
    finally:
        await panel.aclose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("baseline", "search"), default="baseline")
    parser.add_argument("--candidates", type=int, choices=range(1, 13), default=12)
    parser.add_argument("--profiles", action="store_true", help="Explore TCP/WS/gRPC/HTTPUpgrade/XHTTP without changing saved domains")
    args = parser.parse_args()
    raise SystemExit(asyncio.run(main(args.mode, args.candidates, args.profiles)))
