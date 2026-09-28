from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from rich import print
from rich.table import Table

from app.api.three_xui import ThreeXUIClient
from app.config import load_config, offline_warnings, REALITY_CANDIDATES_UNCHECKED_WARNING
from app.parameters.generator import CombinationGenerator
from app.security.masking import mask_parameter_values, mask_secrets
from app.testing.runner import ExperimentRunner

app = typer.Typer(no_args_is_help=True)
panel_app = typer.Typer(no_args_is_help=True)
inbound_app = typer.Typer(no_args_is_help=True)
combinations_app = typer.Typer(no_args_is_help=True)
parameters_app = typer.Typer(no_args_is_help=True)
app.add_typer(panel_app, name="panel")
app.add_typer(inbound_app, name="inbound")
app.add_typer(combinations_app, name="combinations")
app.add_typer(parameters_app, name="parameters")


async def _client(config_path: Path) -> tuple[ThreeXUIClient, object]:
    config = load_config(config_path)
    client = ThreeXUIClient(config.panel, config.api_timeout)
    await client.authenticate()
    await client.discover()
    return client, config


@panel_app.command("test")
def panel_test(config: Path = typer.Option(..., "--config", "-c", exists=True)) -> None:
    """Authenticate and print the version/state reported by the live panel."""
    async def action() -> dict:
        client, _ = await _client(config)
        try:
            return await client.server_status()
        finally:
            await client.aclose()
    print(json.dumps(mask_secrets(asyncio.run(action())), ensure_ascii=False, indent=2))


@inbound_app.command("list")
def inbound_list(config: Path = typer.Option(..., "--config", "-c", exists=True)) -> None:
    async def action() -> list[dict]:
        client, _ = await _client(config)
        try:
            return await client.list_inbounds()
        finally:
            await client.aclose()
    rows = asyncio.run(action())
    table = Table("ID", "Remark", "Protocol", "Port", "Enabled")
    for row in rows:
        table.add_row(str(row.get("id", "")), str(row.get("remark", "")), str(row.get("protocol", "")), str(row.get("port", "")), str(row.get("enable", "")))
    print(table)


@inbound_app.command("show")
def inbound_show(inbound_id: int, config: Path = typer.Option(..., "--config", "-c", exists=True)) -> None:
    async def action() -> dict:
        client, _ = await _client(config)
        try:
            return await client.get_inbound(inbound_id)
        finally:
            await client.aclose()
    print(json.dumps(mask_secrets(asyncio.run(action())), ensure_ascii=False, indent=2))


@parameters_app.command("list")
def parameters_list(config: Path = typer.Option(..., "--config", "-c", exists=True)) -> None:
    """List the declared parameter registry."""
    loaded = load_config(config)
    table = Table("Name", "Type", "Target", "Path", "Values", "Conditions")
    for item in loaded.parameters:
        value_text = ", ".join(map(str, item.iter_values()))
        table.add_row(item.name, item.type, item.target, ".".join(map(str, item.path)), value_text, json.dumps(item.conditions or {}, ensure_ascii=False))
    print(table)


@combinations_app.command("preview")
def combinations_preview(config: Path = typer.Option(..., "--config", "-c", exists=True), limit: int = typer.Option(10, min=1)) -> None:
    """Print raw count and the first valid normalized combinations without contacting the panel."""
    loaded = load_config(config)
    generator = CombinationGenerator(loaded.search_parameters())
    plan = (generator.mutations() if loaded.combination_strategy == "mutation" else
            generator.pairwise() if loaded.combination_strategy == "pairwise" else
            generator.preview(loaded.max_combinations))
    preview = plan[:limit]
    print(f"Strategy: {loaded.combination_strategy}\nRaw combinations: {generator.raw_count}\n"
          f"Planned combinations: {min(len(plan), loaded.max_combinations)} (limit {loaded.max_combinations})")
    for number, item in enumerate(preview, 1):
        print(f"{number:>3}. {json.dumps(mask_parameter_values(item.values, generator.parameters), ensure_ascii=False)}")
    for warning in offline_warnings(loaded):
        print(f"Warning: {warning}")
    if loaded.has_reality_candidates:
        print(f"Warning: {REALITY_CANDIDATES_UNCHECKED_WARNING}")


@app.command("test")
def test(config: Path = typer.Option(..., "--config", "-c", exists=True), dry_run: bool = typer.Option(False),
         resume: bool = typer.Option(False), max_tests: int | None = typer.Option(None, min=1)) -> None:
    """Run or dry-run a sequential, resumable experiment."""
    loaded = load_config(config)

    async def action() -> dict:
        client = ThreeXUIClient(loaded.panel, loaded.api_timeout)
        runner = ExperimentRunner(loaded, client)
        loop = asyncio.get_running_loop()
        for signal_number in (getattr(__import__("signal"), "SIGINT"), getattr(__import__("signal"), "SIGTERM")):
            try:
                loop.add_signal_handler(signal_number, runner.request_stop)
            except (NotImplementedError, RuntimeError):  # Windows uses KeyboardInterrupt; Ubuntu uses the handlers.
                pass
        try:
            return await runner.run(dry_run=dry_run, resume=resume, max_tests=max_tests)
        finally:
            await client.aclose()
    result = asyncio.run(action())
    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
