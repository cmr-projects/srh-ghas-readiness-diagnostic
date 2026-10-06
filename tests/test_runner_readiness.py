import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import runner_readiness as readiness


class RunnerReadinessTests(unittest.TestCase):
    def test_standalone_report_skips_unverifiable_settings_and_network(self):
        with patch.object(readiness.platform, "system", return_value="Linux"), \
                patch.object(readiness.platform, "machine", return_value="x86_64"), \
                patch.object(readiness, "tool"), patch.object(readiness, "docker"), \
                patch.object(readiness, "environment"), \
                patch.object(readiness, "runner_version"):
            rows = readiness.report(["gradle"], probe_network=False)
        self.assertEqual(next(row["status"] for row in rows
                              if row["name"] == "Linux x64 for Dependabot"), "yes")
        self.assertEqual(next(row["status"] for row in rows
                              if row["name"] == "Runner labels and group access"), "unknown")
        self.assertEqual(next(row["status"] for row in rows
                              if row["name"] == "HTTPS probes"), "unknown")

    def test_network_failure_does_not_repeat_proxy_credentials(self):
        from urllib.error import URLError

        rows = []
        with patch.object(readiness.urllib.request, "urlopen",
                          side_effect=URLError("https://secret@proxy.example failed")):
            readiness.network(rows, "Network", "github.com", "runner")
        self.assertEqual(rows[0]["status"], "no")
        self.assertNotIn("secret", json.dumps(rows))

    def test_network_403_means_connection_not_authorization(self):
        from urllib.error import HTTPError

        rows = []
        with patch.object(readiness.urllib.request, "urlopen",
                          side_effect=HTTPError("https://github.com/", 403, "Forbidden", {}, None)):
            readiness.network(rows, "Network", "github.com", "runner")
        self.assertEqual(rows[0]["status"], "yes")
        self.assertIn("does not verify access", rows[0]["detail"])

    def test_environment_never_exposes_credentials(self):
        rows = []
        with patch.dict(readiness.os.environ, {
            "HTTPS_PROXY": "https://secret@proxy.example",
            "GRADLE_PLUGIN_REPOSITORY_PASSWORD": "my-secret-password",
        }, clear=True):
            readiness.environment(rows)
        output = json.dumps(rows)
        self.assertNotIn("my-secret-password", output)
        self.assertNotIn("secret@proxy", output)

    def test_runner_version_threshold(self):
        with tempfile.TemporaryDirectory() as root:
            temp = Path(root) / "_work" / "_temp"
            temp.mkdir(parents=True)
            binary = Path(root) / "bin" / "Runner.Listener"
            binary.parent.mkdir()
            binary.touch()
            rows = []
            result = readiness.subprocess.CompletedProcess([], 0, "2.327.1\n", "")
            with patch.dict(readiness.os.environ, {"RUNNER_TEMP": str(temp)}), \
                    patch.object(readiness.subprocess, "run", return_value=result):
                readiness.runner_version(rows)
            self.assertEqual(rows[0]["status"], "yes")

    def test_markdown_escapes_table_content(self):
        rows = []
        readiness.add(rows, "Runner", "setting", "test|name", "unknown",
                      "line|value", "runner")
        self.assertIn("test\\|name", readiness.markdown(rows))
        self.assertIn("line\\|value", readiness.markdown(rows))

    def test_docker_without_client_is_not_mistaken_for_daemon_failure(self):
        rows = []
        with patch.object(readiness.shutil, "which", return_value=None):
            readiness.docker(rows)
        self.assertEqual([r["status"] for r in rows], ["no", "unknown"])

    def test_high_runner_concurrency_reports_missing_address_pools(self):
        with patch.object(readiness.platform, "system", return_value="Linux"), \
                patch.object(readiness.platform, "machine", return_value="x86_64"), \
                patch.object(readiness, "tool"), patch.object(readiness, "docker"), \
                patch.object(readiness, "environment"), \
                patch.object(readiness, "runner_version"), \
                patch.object(readiness.Path, "is_file", return_value=False):
            rows = readiness.report([], probe_network=False, concurrent_runners=20)
        pool = next(r for r in rows if r["name"] == "Docker network address pools")
        self.assertEqual(pool["status"], "no")
        self.assertIn("required above 14", pool["detail"])

    def test_glibc_below_supported_minimum_is_reported(self):
        with patch.object(readiness.platform, "system", return_value="Linux"), \
                patch.object(readiness.platform, "machine", return_value="x86_64"), \
                patch.object(readiness.platform, "libc_ver", return_value=("glibc", "2.16")), \
                patch.object(readiness, "tool"), patch.object(readiness, "docker"), \
                patch.object(readiness, "environment"), patch.object(readiness, "resources"), \
                patch.object(readiness, "runner_version"):
            rows = readiness.report([], probe_network=False)
        self.assertEqual(next(r["status"] for r in rows if r["name"] == "glibc >= 2.17"), "no")


if __name__ == "__main__":
    unittest.main()
