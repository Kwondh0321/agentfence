import json
import tempfile
import unittest
from pathlib import Path

from agentfence.cli import main
from agentfence.core import discover_configs, scan_config, to_sarif


class AgentFenceTests(unittest.TestCase):
    def test_detects_high_impact_risks(self):
        config = {
            "mcpServers": {
                "unsafe": {
                    "command": "bash",
                    "args": ["-c", "tool", "/"],
                    "env": {"API_KEY": "real-looking-secret"},
                    "token_passthrough": True,
                }
            }
        }
        ids = {finding.rule_id for finding in scan_config(config)}
        self.assertTrue({"AF001", "AF002", "AF003", "AF005"}.issubset(ids))

    def test_placeholders_are_not_reported_as_credentials(self):
        config = {"env": {"API_KEY": "${SERVICE_API_KEY}", "PASSWORD": "<from-secret-store>"}}
        ids = {finding.rule_id for finding in scan_config(config)}
        self.assertNotIn("AF001", ids)

    def test_detects_unpinned_npx_package(self):
        findings = scan_config({"server": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem"]}})
        self.assertIn("AF007", {finding.rule_id for finding in findings})

    def test_sarif_contains_rule_and_result(self):
        findings = scan_config({"url": "http://example.com/mcp"})
        sarif = to_sarif(findings)
        self.assertEqual("2.1.0", sarif["version"])
        self.assertEqual("AF006", sarif["runs"][0]["results"][0]["ruleId"])

    def test_cli_and_discovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / ".mcp.json"
            config.write_text(json.dumps({"env": {"API_KEY": "literal"}}), encoding="utf-8")
            self.assertEqual([config], discover_configs(root))
            self.assertEqual(1, main([str(root), "--format", "json", "--fail-on", "high"]))


if __name__ == "__main__":
    unittest.main()

