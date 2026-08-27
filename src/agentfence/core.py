"""Rule engine for agent configuration files."""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SECRET_WORDS = (
    "api_key",
    "apikey",
    "access_token",
    "secret",
    "password",
    "private_key",
)
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
        raise TypeError(f"{path} must contain an object at the top level")
    return value


def discover_configs(target: Path) -> list[Path]:
    """Find likely MCP/agent configuration files below *target*."""
    if target.is_file():
        return [target]
    if not target.exists():
        raise FileNotFoundError(target)

    files: set[Path] = set()
    exact_names = {".mcp.json", "mcp.json", "mcp-config.json"}
    ignored = {".git", "node_modules", ".venv", "dist", "build"}
    for path in target.rglob("*"):
        if (
            any(part in ignored for part in path.parts)
            or path.is_symlink()
            or not path.is_file()
        ):
            continue
        lower = path.name.lower()
        if (
            lower in exact_names
            or ("mcp" in lower and path.suffix.lower() in {".json", ".toml"})
            or path.name == "config.toml"
            and ".codex" in path.parts
        ):
            files.add(path)
    return sorted(files)


def _walk(
    value: Any, path: tuple[str, ...] = ()
) -> Iterable[tuple[tuple[str, ...], Any]]:
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
    separator = package.rfind("@")
    if separator <= 0:
        return True
    version = package[separator + 1 :].strip().lower()
    return (
        not version
        or version in {"*", "latest", "next", "canary"}
        or any(char in version for char in "^~<>")
    )


def scan_config(config: dict[str, Any], source: str = "config") -> list[Finding]:
    """Run deterministic security rules against a parsed configuration."""
    findings: list[Finding] = []

    def add(
        rule: str, severity: str, message: str, path: tuple[str, ...], remediation: str
    ) -> None:
        findings.append(
            Finding(rule, severity, message, f"{source}:{_location(path)}", remediation)
        )

    for path, value in _walk(config):
        key = path[-1].lower() if path else ""
        key_path = ".".join(part.lower() for part in path)

        if (
            isinstance(value, str)
            and any(word in key for word in SECRET_WORDS)
            and not _is_placeholder(value)
        ):
            add(
                "AF001",
                "critical",
                "인증정보로 보이는 필드에 실제 값이 직접 기록돼 있습니다.",
                path,
                "직접 기록한 값을 제거하고 비밀 저장소 또는 환경변수로 주입하세요.",
            )

        if isinstance(value, str) and key in {"command", "cmd", "executable"}:
            command = Path(value).name.lower()
            if command in SHELLS:
                add(
                    "AF002",
                    "high",
                    f"서버가 범용 셸({command})을 실행합니다.",
                    path,
                    "범위가 제한된 실행 파일을 직접 호출하고 모든 인수를 검증하세요.",
                )

        if (
            isinstance(value, str)
            and "args" in key_path
            and value.strip().lower() in BROAD_PATHS
        ):
            add(
                "AF003",
                "high",
                f"도구에 지나치게 넓은 파일시스템 경로({value!r})가 허용됐습니다.",
                path,
                "도구에 필요한 최소 프로젝트 폴더만 허용하세요.",
            )

        if key in {"allowed_origins", "origins", "cors_origins"}:
            values = value if isinstance(value, list) else [value]
            if "*" in values:
                add(
                    "AF004",
                    "high",
                    "네트워크 Origin 허용 목록에 와일드카드가 포함돼 있습니다.",
                    path,
                    "신뢰하는 HTTPS Origin을 명시적으로 나열하세요.",
                )

        if "token_passthrough" in key or "forward_authorization" in key:
            enabled = value is True or (
                isinstance(value, str) and value.lower() in {"true", "enabled", "yes"}
            )
            if enabled:
                add(
                    "AF005",
                    "critical",
                    "토큰 패스스루가 활성화된 것으로 보입니다.",
                    path,
                    "각 하위 리소스마다 대상이 제한된 별도 토큰을 발급하세요.",
                )

        if (
            isinstance(value, str)
            and value.startswith("http://")
            and not re.match(r"http://(localhost|127\.0\.0\.1)(:|/|$)", value)
        ):
            add(
                "AF006",
                "medium",
                "외부 엔드포인트가 평문 HTTP를 사용합니다.",
                path,
                "HTTPS를 사용하고 외부 엔드포인트의 신원을 검증하세요.",
            )

    for path, value in _walk(config):
        if not isinstance(value, dict):
            continue
        command = value.get("command") or value.get("cmd")
        args = value.get("args", [])
        if (
            isinstance(command, str)
            and Path(command).name.lower() == "npx"
            and isinstance(args, list)
        ):
            package = _first_package(args)
            if package and _is_unpinned_package(package):
                add(
                    "AF007",
                    "medium",
                    f"npx 패키지 {package!r}의 버전이 고정되지 않았습니다.",
                    path + ("args",),
                    "검토한 정확한 버전을 고정하고 의도적으로 업데이트하세요.",
                )

    unique = {(f.rule_id, f.location, f.message): f for f in findings}
    return sorted(
        unique.values(),
        key=lambda item: (-SEVERITY_ORDER[item.severity], item.location, item.rule_id),
    )


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
                "properties": {
                    "security-severity": str(SEVERITY_ORDER[finding.severity] * 2.5)
                },
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
                "tool": {
                    "driver": {
                        "name": "AgentFence",
                        "version": "0.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
