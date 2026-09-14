from __future__ import annotations

from pathlib import Path

import pytest

from npm_adaptive import cli


def test_cli_forwards_explicit_harness_opt_in(monkeypatch, capsys, tmp_path: Path):
    received = {}

    def _scan(specifier, **kwargs):
        received["specifier"] = specifier
        received.update(kwargs)
        return {"ok": True}

    monkeypatch.setattr(cli, "scan", _scan)

    assert cli.main([
        "scan", "demo-package", "--run-harness", "--planner", "ollama", "--state-dir", str(tmp_path)
    ]) == 0
    assert received["specifier"] == "demo-package"
    assert received["run_harness"] is True
    assert received["planner_provider"] == "ollama"
    assert received["static_only"] is False
    assert '"ok": true' in capsys.readouterr().out


def test_cli_rejects_static_only_harness_combination():
    with pytest.raises(SystemExit) as error:
        cli.main(["demo-package", "--static-only", "--run-harness"])

    assert error.value.code == 2


def test_cli_rejects_static_only_planner_combination():
    with pytest.raises(SystemExit) as error:
        cli.main(["demo-package", "--static-only", "--planner", "ollama"])

    assert error.value.code == 2


def test_cli_accepts_compact_specifier_form(monkeypatch, capsys):
    monkeypatch.setattr(cli, "scan", lambda specifier, **_kwargs: {"specifier": specifier})

    assert cli.main(["demo-package"]) == 0
    assert '"specifier": "demo-package"' in capsys.readouterr().out
