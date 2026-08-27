# AgentFence

[한국어](README.md) | English | [Changelog / 변경 기록](CHANGELOG.md)

AgentFence is a deterministic, local-first security scanner for MCP and AI-agent configuration files. It detects literal credentials, general-purpose shell launchers, overly broad filesystem grants, wildcard origins, token passthrough, plaintext remote HTTP endpoints, and unpinned `npx` packages.

No model or API key is required. Reports are available as text, JSON, or SARIF for code-scanning systems.

## Install and run

```bash
git clone https://github.com/Kwondh0321/agentfence.git
cd agentfence
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install .
agentfence .
agentfence .mcp.json --format sarif --output agentfence.sarif
```

The default policy exits with status 1 for `high` or `critical` findings. Use `--fail-on medium`, `--fail-on low`, or `--fail-on none` to change it. Invalid input or I/O errors return status 2.

## Rules

| Rule | Severity | Detects |
| --- | --- | --- |
| AF001 | Critical | Literal values in credential-like fields |
| AF002 | High | General-purpose shell launchers |
| AF003 | High | Broad filesystem scopes |
| AF004 | High | Wildcard origin allowlists |
| AF005 | Critical | Token passthrough settings |
| AF006 | Medium | Plaintext non-local HTTP endpoints |
| AF007 | Medium | Unpinned or mutable `npx` packages |

AgentFence identifies review signals; it does not prove that a server is safe.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
agentfence examples/mcp.json --fail-on none
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Licensed under MIT.
