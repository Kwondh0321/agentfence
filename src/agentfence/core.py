"""Rule engine for agent configuration files."""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SECRET_WORDS = ("api_key", "apikey", "access_token", "secret", "password", "private_key")
BROAD_PATHS = {"/", "/*", "~", "~/", "$home", "${home}", ".", "..", "../"}
SHELLS = {"bash", "sh", "zsh", "fish", "cmd", "cmd.exe", "powershell", "pwsh"}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    location: str
    remediation: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def load_config(path: Path) -> dict[str, Any]:
    """Load a JSON or TOML configuration."""
    raw = path.read_bytes()
    if path.suffix.lower() == ".toml":
        value = tomllib.loads(raw.decode("utf-8"))
    else:
        value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object at the top level")
    return value


def discover_configs(target: Path) -> list[Path]:
    """Find likely MCP/agent configuration files below *target*."""
    if target.is_file():
        return [target]
    if not target.exists():
        raise FileNotFoundError(target)

    files: set[Path] = set()
    exact_names = {".mcp.json", "mcp.json", "mcp-config.json", "config.toml"}
    ignored = {".git", "node_modules", ".venv", "dist", "build"}
    for path in target.rglob("*"):
        if any(part in ignored for part in path.parts) or not path.is_file():
            continue
        lower = path.name.lower()
        if lower in exact_names or ("mcp" in lower and path.suffix.lower() in {".json", ".toml"}):
            files.add(path)
        elif path.name == "config.toml" and ".codex" in path.parts:
            files.add(path)
    return sorted(files)


def _walk(value: Any, path: tuple[str, ...] = ()) -> Iterable[tuple[tuple[str, ...], Any]]:
    yield path, value
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk(child, path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk(child, path + (str(index),))


def _location(path: tuple[str, ...]) -> str:
    return ".".join(path) if path else "$"


def _is_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    return (
        not lowered
        or lowered.startswith(("${", "$", "<", "{{", "env:"))
        or lowered in {"redacted", "changeme", "example", "your-token-here"}
    )


def _first_package(args: list[Any]) -> str | None:
    for item in args:
        if not isinstance(item, str) or item.startswith("-"):
            continue
        return item
    return None


def _is_unpinned_package(package: str) -> bool:
    if package.startswith("@"):
        return package.count("@") == 1
    return "@" not in package


def scan_config(config: dict[str, Any], source: str = "config") -> list[Finding]:
    """Run deterministic security rules against a parsed configuration."""
    findings: list[Finding] = []

    def add(rule: str, severity: str, message: str, path: tuple[str, ...], remediation: str) -> None:
        findings.append(Finding(rule, severity, message, f"{source}:{_location(path)}", remediation))

    for path, value in _walk(config):
        key = path[-1].lower() if path else ""
        key_path = ".".join(part.lower() for part in path)

        if isinstance(value, str) and any(word in key for word in SECRET_WORDS) and not _is_placeholder(value):
            add(
                "AF001",
                "critical",
                "A credential-like field contains a literal value.",
                path,
                "Remove the literal and inject the credential from a secret store or environment variable.",
            )

        if isinstance(value, str) and key in {"command", "cmd", "executable"}:
            command = Path(value).name.lower()
            if command in SHELLS:
                add(
                    "AF002",
                    "high",
                    f"The server launches a general-purpose shell ({command}).",
                    path,
                    "Invoke a narrowly scoped executable directly and validate every argument.",
                )

        if isinstance(value, str) and "args" in key_path and value.strip().lower() in BROAD_PATHS:
            add(
                "AF003",
                "high",
                f"A tool is granted a broad filesystem path ({value!r}).",
                path,
                "Grant only the smallest project directory required by the tool.",
            )

        if key in {"allowed_origins", "origins", "cors_origins"}:
            values = value if isinstance(value, list) else [value]
            if "*" in values:
                add(
                    "AF004",
                    "high",
                    "A network origin allowlist contains a wildcard.",
                    path,
                    "List trusted HTTPS origins explicitly.",
                )

        if "token_passthrough" in key or "forward_authorization" in key:
            enabled = value is True or (isinstance(value, str) and value.lower() in {"true", "enabled", "yes"})
            if enabled:
                add(
                    "AF005",
                    "critical",
                    "Token passthrough appears to be enabled.",
                    path,
                    "Issue a separate audience-bound token for every downstream resource.",
                )

        if isinstance(value, str) and value.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1)(:|/|$)", value):
            add(
                "AF006",
                "medium",
                "A remote endpoint uses plaintext HTTP.",
                path,
                "Use HTTPS and validate the remote endpoint identity.",
            )

    for path, value in _walk(config):
        if not isinstance(value, dict):
            continue
        command = value.get("command") or value.get("cmd")
        args = value.get("args", [])
        if isinstance(command, str) and Path(command).name.lower() == "npx" and isinstance(args, list):
            package = _first_package(args)
            if package and _is_unpinned_package(package):
                add(
                    "AF007",
                    "medium",
                    f"npx package {package!r} is not pinned to a version.",
                    path + ("args",),
                    "Pin an exact reviewed package version and update it deliberately.",
                )

    unique = {(f.rule_id, f.location, f.message): f for f in findings}
    return sorted(unique.values(), key=lambda item: (-SEVERITY_ORDER[item.severity], item.location, item.rule_id))


def to_sarif(findings: list[Finding]) -> dict[str, Any]:
    """Convert findings to SARIF 2.1.0 for code-scanning systems."""
    level = {"low": "note", "medium": "warning", "high": "error", "critical": "error"}
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for finding in findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "shortDescription": {"text": finding.message},
                "help": {"text": finding.remediation},
                "properties": {"security-severity": str(SEVERITY_ORDER[finding.severity] * 2.5)},
            },
        )
        source, _, logical = finding.location.partition(":")
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": level[finding.severity],
                "message": {"text": f"{finding.message} {finding.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {"artifactLocation": {"uri": source}},
                        "logicalLocations": [{"name": logical or "$"}],
                    }
                ],
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "AgentFence", "version": "0.1.0", "rules": list(rules.values())}},
                "results": results,
            }
        ],
    }

