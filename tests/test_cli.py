from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from app.main import app

EXAMPLE_CONFIG = Path(__file__).resolve().parents[1] / "configs" / "example.yaml"
runner = CliRunner()


def test_combinations_preview_prints_the_plan_without_a_panel(monkeypatch) -> None:
    """`combinations preview` is the documented panel-free check of a plan."""
    monkeypatch.setenv("COLUMNS", "200")
    result = runner.invoke(app, ["combinations", "preview", "-c", str(EXAMPLE_CONFIG), "--limit", "2"])

    assert result.exit_code == 0, result.output
    assert "Strategy: pairwise" in result.stdout
    assert "Raw combinations: 7200" in result.stdout
    assert "Planned combinations: 50 (limit 50)" in result.stdout
    listed = [line for line in result.stdout.splitlines() if line.strip().startswith("1.")]
    assert json.loads(listed[0].split(". ", 1)[1])["network"] == "tcp"


def test_parameters_list_prints_the_declared_registry(monkeypatch) -> None:
    monkeypatch.setenv("COLUMNS", "200")
    result = runner.invoke(app, ["parameters", "list", "-c", str(EXAMPLE_CONFIG)])

    assert result.exit_code == 0, result.output
    for name in ("network", "tls_fingerprint", "mux_concurrency"):
        assert name in result.stdout
    assert "client" in result.stdout


def test_missing_config_path_fails_before_any_work(tmp_path: Path) -> None:
    assert runner.invoke(app, ["combinations", "preview", "-c", str(tmp_path / "missing.yaml")]).exit_code != 0
    assert runner.invoke(app, ["parameters", "list", "-c", str(tmp_path / "missing.yaml")]).exit_code != 0
