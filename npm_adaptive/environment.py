"""Synthetic profile materialisation and output redaction.

Nothing in this module accesses the developer's home, keychain, cloud CLI, or
real credentials.  Every value is generated per run and is deliberately fake.
"""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Dict

from .models import PreparedEnvironment
from .profiles import get_profile


def prepare_environment(profile_id: str, destination: Path) -> PreparedEnvironment:
    """Create an owner-only synthetic profile directory for one sandbox run."""

    profile = get_profile(profile_id)
    root = Path(destination).resolve()
    if root.exists():
        raise FileExistsError(f"environment destination already exists: {root}")
    root.mkdir(parents=True, mode=0o700)

    if profile_id == "node-library-v1":
        return PreparedEnvironment(
            profile_id=profile.profile_id,
            profile_version=profile.version,
            root=root,
            container_environment={
                "HOME": "/input/profile/home",
                "TMPDIR": "/tmp",
                "CI": "false",
            },
            fixture_labels=[],
            secret_values={},
        )
    if profile_id == "developer-workstation-v1":
        return _prepare_developer_workstation(profile.profile_id, profile.version, root)
    if profile_id == "ci-runner-v1":
        return _prepare_ci_runner(profile.profile_id, profile.version, root)
    if profile_id == "cloud-service-v1":
        return _prepare_cloud_service(profile.profile_id, profile.version, root)
    if profile_id == "commerce-client-v1":
        return _prepare_commerce_client(profile.profile_id, profile.version, root)
    raise ValueError(f"profile materialisation is not implemented: {profile_id}")


def _prepare_developer_workstation(
    profile_id: str, profile_version: str, root: Path
) -> PreparedEnvironment:
    token_suffix = secrets.token_urlsafe(18)
    values = {
        "npm_token": f"tt_npm_{token_suffix}",
        "github_token": f"tt_gh_{token_suffix}",
        "aws_access_key": f"TTIA{secrets.token_hex(8).upper()}",
        "aws_secret": f"tt_aws_secret_{secrets.token_urlsafe(24)}",
        "ssh_private_key": (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"TraceTreeSynthetic-{secrets.token_urlsafe(20)}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        ),
    }

    home = root / "home"
    _mkdir(home / ".aws")
    _mkdir(home / ".ssh")
    _mkdir(home / ".config" / "gh")
    _write(
        home / ".npmrc",
        f"//registry.npmjs.org/:_authToken={values['npm_token']}\n",
    )
    _write(
        home / ".git-credentials",
        f"https://x-access-token:{values['github_token']}@github.com\n",
    )
    _write(
        home / ".aws" / "credentials",
        "[default]\n"
        f"aws_access_key_id = {values['aws_access_key']}\n"
        f"aws_secret_access_key = {values['aws_secret']}\n",
    )
    _write(home / ".ssh" / "id_ed25519", values["ssh_private_key"])
    _write(home / ".config" / "gh" / "hosts.yml", f"github.com:\n  oauth_token: {values['github_token']}\n")
    _write(
        home / ".env",
        f"GITHUB_TOKEN={values['github_token']}\nNPM_TOKEN={values['npm_token']}\n",
    )

    return PreparedEnvironment(
        profile_id=profile_id,
        profile_version=profile_version,
        root=root,
        container_environment={
            "HOME": "/input/profile/home",
            "TMPDIR": "/tmp",
            "CI": "false",
            "GITHUB_TOKEN": values["github_token"],
            "NPM_TOKEN": values["npm_token"],
        },
        fixture_labels=sorted(values),
        secret_values=values,
    )


def _prepare_ci_runner(profile_id: str, profile_version: str, root: Path) -> PreparedEnvironment:
    values = {
        "ci_github_token": f"tt_ci_gh_{secrets.token_urlsafe(18)}",
        "ci_job_token": f"tt_ci_job_{secrets.token_urlsafe(18)}",
    }
    home = root / "home"
    workspace = root / "workspace" / "example-org" / "demo-repo"
    _mkdir(home)
    _mkdir(workspace / ".github" / "workflows")
    _write(
        root / "event.json",
        '{"action":"opened","repository":{"full_name":"example-org/demo-repo"},"sender":{"login":"synthetic-user"}}\n',
    )
    _write(workspace / ".github" / "workflows" / "ci.yml", "name: synthetic-ci\non: push\n")
    _write(home / ".npmrc", f"//registry.npmjs.org/:_authToken={values['ci_job_token']}\n")
    return PreparedEnvironment(
        profile_id=profile_id,
        profile_version=profile_version,
        root=root,
        container_environment={
            "HOME": "/input/profile/home",
            "TMPDIR": "/tmp",
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "GITHUB_WORKSPACE": "/input/profile/workspace/example-org/demo-repo",
            "GITHUB_EVENT_PATH": "/input/profile/event.json",
            "GITHUB_TOKEN": values["ci_github_token"],
        },
        fixture_labels=sorted(values),
        secret_values=values,
    )


def _prepare_cloud_service(profile_id: str, profile_version: str, root: Path) -> PreparedEnvironment:
    values = {
        "cloud_access_key": f"TTIA{secrets.token_hex(8).upper()}",
        "cloud_secret": f"tt_cloud_secret_{secrets.token_urlsafe(24)}",
        "cloud_session_token": f"tt_cloud_session_{secrets.token_urlsafe(24)}",
    }
    home = root / "home"
    _mkdir(home / ".aws")
    _mkdir(root / "serviceaccount")
    _write(
        home / ".aws" / "credentials",
        "[default]\n"
        f"aws_access_key_id = {values['cloud_access_key']}\n"
        f"aws_secret_access_key = {values['cloud_secret']}\n"
        f"aws_session_token = {values['cloud_session_token']}\n",
    )
    _write(root / "serviceaccount" / "token", f"{values['cloud_session_token']}\n")
    _write(root / "serviceaccount" / "namespace", "synthetic-namespace\n")
    return PreparedEnvironment(
        profile_id=profile_id,
        profile_version=profile_version,
        root=root,
        container_environment={
            "HOME": "/input/profile/home",
            "TMPDIR": "/tmp",
            "CI": "false",
            "AWS_REGION": "us-tracetree-1",
            "AWS_ACCESS_KEY_ID": values["cloud_access_key"],
            "AWS_SECRET_ACCESS_KEY": values["cloud_secret"],
            "AWS_SESSION_TOKEN": values["cloud_session_token"],
            "KUBERNETES_SERVICE_HOST": "kubernetes.synthetic.invalid",
            "KUBERNETES_SERVICEACCOUNT_TOKEN_FILE": "/input/profile/serviceaccount/token",
        },
        fixture_labels=sorted(values),
        secret_values=values,
    )


def _prepare_commerce_client(
    profile_id: str, profile_version: str, root: Path
) -> PreparedEnvironment:
    values = {
        "payment_token": f"tt_payment_{secrets.token_urlsafe(24)}",
        "customer_session": f"tt_customer_session_{secrets.token_urlsafe(18)}",
    }
    home = root / "home"
    _mkdir(home)
    _mkdir(root / "checkout")
    _write(
        root / "checkout" / "session.json",
        "{\n"
        '  "customer_email": "synthetic-customer@example.invalid",\n'
        f'  "payment_token": "{values["payment_token"]}",\n'
        f'  "session": "{values["customer_session"]}"\n'
        "}\n",
    )
    return PreparedEnvironment(
        profile_id=profile_id,
        profile_version=profile_version,
        root=root,
        container_environment={
            "HOME": "/input/profile/home",
            "TMPDIR": "/tmp",
            "CI": "false",
            "CHECKOUT_SESSION_PATH": "/input/profile/checkout/session.json",
            "PAYMENT_TOKEN": values["payment_token"],
            "CUSTOMER_SESSION": values["customer_session"],
        },
        fixture_labels=sorted(values),
        secret_values=values,
    )


def redact_directory(root: Path, environment: PreparedEnvironment) -> None:
    """Redact generated canaries from textual runner output before persistence."""

    for path in Path(root).rglob("*"):
        if not path.is_file() or path.stat().st_size > 10 * 1024 * 1024:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        redacted = environment.redact(text)
        if redacted != text:
            path.write_text(redacted, encoding="utf-8")
            path.chmod(0o600)


def _mkdir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)


def _write(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(0o600)
