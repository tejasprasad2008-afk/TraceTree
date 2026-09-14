from __future__ import annotations

from pathlib import Path

from npm_adaptive.environment import prepare_environment, redact_directory


def test_developer_profile_contains_only_synthetic_per_run_canaries(tmp_path: Path):
    environment = prepare_environment("developer-workstation-v1", tmp_path / "profile")

    assert environment.container_environment["HOME"] == "/input/profile/home"
    assert (environment.root / "home" / ".npmrc").is_file()
    assert (environment.root / "home" / ".aws" / "credentials").is_file()
    assert (environment.root / "home" / ".ssh" / "id_ed25519").is_file()
    assert all(value.startswith("tt_") or "TraceTreeSynthetic" in value or value.startswith("TTIA") for value in environment.secret_values.values())


def test_redaction_removes_synthetic_values_before_output_persistence(tmp_path: Path):
    environment = prepare_environment("developer-workstation-v1", tmp_path / "profile")
    output = tmp_path / "output"
    output.mkdir()
    token = environment.secret_values["npm_token"]
    (output / "stdout.log").write_text(f"package printed {token}", encoding="utf-8")

    redact_directory(output, environment)

    text = (output / "stdout.log").read_text(encoding="utf-8")
    assert token not in text
    assert "[REDACTED:npm_token]" in text


def test_scenario_profiles_materialize_only_synthetic_canaries(tmp_path: Path):
    cases = {
        "ci-runner-v1": ("ci_github_token", "GITHUB_TOKEN", "event.json"),
        "cloud-service-v1": ("cloud_access_key", "AWS_ACCESS_KEY_ID", "credentials"),
        "commerce-client-v1": ("payment_token", "PAYMENT_TOKEN", "session.json"),
    }
    for profile_id, (secret_label, environment_key, expected_file) in cases.items():
        environment = prepare_environment(profile_id, tmp_path / profile_id)
        assert secret_label in environment.secret_values
        assert environment.secret_values[secret_label] == environment.container_environment[environment_key]
        assert any(path.name == expected_file for path in environment.root.rglob("*"))
        assert all(
            value.startswith("tt_") or value.startswith("TTIA")
            for value in environment.secret_values.values()
        )
