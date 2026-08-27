"""Command-line interface for AgentFence."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import SEVERITY_ORDER, discover_configs, load_config, scan_config, to_sarif


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MCP와 AI 에이전트 설정 파일의 보안 위험을 검사합니다.")
    parser.add_argument("target", nargs="?", default=".", help="검사할 설정 파일 또는 폴더")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--output", type=Path, help="보고서를 저장할 파일")
    parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="high",
        help="지정한 심각도 이상이면 종료 코드 1을 반환합니다",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        paths = discover_configs(Path(args.target))
        findings = []
        for path in paths:
            findings.extend(scan_config(load_config(path), str(path)))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"agentfence: {error}", file=sys.stderr)
        return 2

    if args.format == "json":
        rendered = json.dumps({"files_scanned": len(paths), "findings": [f.as_dict() for f in findings]}, indent=2)
    elif args.format == "sarif":
        rendered = json.dumps(to_sarif(findings), indent=2)
    else:
        lines = [f"AgentFence 검사 완료: 파일 {len(paths)}개, 발견 항목 {len(findings)}개"]
        lines.extend(f"[{f.severity.upper()}] {f.rule_id} {f.location}\n  {f.message}\n  조치: {f.remediation}" for f in findings)
        rendered = "\n".join(lines)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    else:
        print(rendered)

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    return 1 if any(SEVERITY_ORDER[f.severity] >= threshold for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
