# Contributing

[한국어](CONTRIBUTING.md) | English

Thank you for improving this project.

1. Open an issue that describes the bug, use case, or proposed behavior before a large change.
2. Work on a focused branch. Add or update tests whenever behavior changes.
3. Run the checks below from the repository root.
4. Open a pull request that explains the reason for the change and includes representative input and output.

```bash
python -m unittest discover -s tests -v\nagentfence examples/mcp.json --fail-on none
```

Keep pull requests small enough to review. Preserve backward compatibility for documented CLI options and machine-readable fields unless the change is explicitly discussed. Update both `README.md` and `README.en.md` when user-facing behavior changes.

Never commit real credentials, personal data, or confidential material. Use synthetic examples or data with a clearly compatible public license.
