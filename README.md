# AgentFence

AgentFence is a deterministic, local-first security scanner for MCP and AI-agent configuration files. It identifies literal credentials, broad filesystem grants, shell launchers, wildcard origins, plaintext remote endpoints, token passthrough, and unpinned `npx` packages.

No model or API key is required. Reports can be emitted as human-readable text, JSON, or SARIF for GitHub code scanning.

## Install and run

```bash
python -m pip install -e .
agentfence .
agentfence .mcp.json --format sarif --output agentfence.sarif
```

The default exit policy fails on `high` and `critical` findings. Use `--fail-on medium`, `--fail-on low`, or `--fail-on none` to change it.

## Rules

| Rule | Severity | Detects |
| --- | --- | --- |
| AF001 | Critical | Literal values in credential-like fields |
| AF002 | High | General-purpose shell launchers |
| AF003 | High | Broad filesystem scopes in tool arguments |
| AF004 | High | Wildcard origin allowlists |
| AF005 | Critical | Token passthrough settings |
| AF006 | Medium | Plaintext non-local HTTP endpoints |
| AF007 | Medium | Unpinned packages executed through `npx` |

AgentFence reports configuration risks; it does not prove that a server is safe. Review findings in context and test changes before deployment.

## Development

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
agentfence examples/mcp.json --fail-on none
```

## License

MIT
