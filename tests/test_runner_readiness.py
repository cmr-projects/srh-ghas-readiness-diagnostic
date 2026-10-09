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

    def test_report_probes_each_hostname_with_its_source(self):
        from urllib.error import HTTPError

        with patch.object(readiness, "tool"), patch.object(readiness, "docker"), \
                patch.object(readiness, "environment"), patch.object(readiness, "resources"), \
                patch.object(readiness, "runner_version"), \
                patch.object(readiness.urllib.request, "urlopen",
                             side_effect=HTTPError("https://example.com/", 403, "Forbidden", {}, None)):
            rows = readiness.report(["go"], probe_network=True)
        probes = {r["name"]: r for r in rows if r["kind"] == "network"}
        self.assertEqual(set(probes), set(readiness.ENDPOINTS["common"]) |
                         set(readiness.ENDPOINTS["go"]))
        self.assertTrue(all(r["status"] == "yes" for r in probes.values()))
        self.assertEqual(probes["dependabot-actions.githubapp.com"]["source"],
                         readiness.DOCS["dependabot"])
        self.assertEqual(probes["go.dev"]["source"], readiness.DOCS["autosubmit"])

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
        self.assertEqual(next(r["source"] for r in rows
                              if r["name"] == "HTTPS_PROXY / https_proxy"),
                         readiness.DOCS["proxy"])
        self.assertEqual(next(r["source"] for r in rows
                              if r["name"] == "NODE_EXTRA_CA_CERTS"),
                         readiness.DOCS["node_ca"])

    def test_runner_identity_and_requested_label_are_visible_in_both_reports(self):
        values = {
            "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
            "RUNNER_NAME": "customer-runner-01", "RUNNER_ENVIRONMENT": "self-hosted",
            "RUNNER_TEMP": "/opt/actions/_work/_temp",
            "RUNNER_TOOL_CACHE": "/opt/actions/_work/_tool",
        }
        rows = []
        with patch.dict(readiness.os.environ, {
            **values, "READINESS_RUNNER_LABEL": "customer-diagnostic",
            "GITHUB_TOKEN": "not-for-the-report",
        }, clear=True):
            readiness.environment(rows)
        by_name = {r["name"]: r for r in rows}
        text = readiness.markdown(rows)
        self.assertIn("## Runner context", text)
        self.assertIn("**Requested runner label:** customer-diagnostic", text)
        self.assertIn("**RUNNER_ENVIRONMENT:** self-hosted", text)
        for name, value in values.items():
            self.assertEqual(by_name[name]["status"], "yes")
            self.assertEqual(by_name[name]["detail"], value)
            self.assertIn(value, text)
        self.assertEqual(by_name["Requested runner label"]["detail"], "customer-diagnostic")
        self.assertNotIn("not-for-the-report", text + json.dumps(rows))

    def test_noncredential_variables_are_visible_and_url_credentials_are_redacted(self):
        rows = []
        values = {
            "JAVA_HOME": "/opt/private-jdk",
            "NODE_EXTRA_CA_CERTS": "/opt/private-ca.pem",
            "SSL_CERT_FILE": "/opt/private-ssl.pem",
            "GH_DEPENDENCY_SUBMISSION_SKIP_CACHE": "true",
            "NO_PROXY": "localhost,registry.example",
            "GRADLE_PLUGIN_REPOSITORY_URL": "https://user:password@registry.example",
            "GRADLE_PLUGIN_REPOSITORY_USERNAME": "private-user",
            "GRADLE_PLUGIN_REPOSITORY_PASSWORD": "private-password",
        }
        with patch.dict(readiness.os.environ, values, clear=True):
            readiness.environment(rows)
        output = json.dumps(rows) + readiness.markdown(rows)
        for name in ("JAVA_HOME", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE",
                     "GH_DEPENDENCY_SUBMISSION_SKIP_CACHE", "NO_PROXY"):
            self.assertIn(values[name], output)
        self.assertIn("https://[redacted]@registry.example", output)
        self.assertNotIn("user:password", output)
        self.assertNotIn("private-user", output)
        self.assertNotIn("private-password", output)

    def test_proxy_credentials_and_url_query_parameters_are_redacted(self):
        rows = []
        with patch.dict(readiness.os.environ, {
            "https_proxy": "http://user:private-password@proxy.example:8080?token=secret-token",
            "GRADLE_PLUGIN_REPOSITORY_URL": "https://registry.example/plugins?token=secret-token#secret",
        }, clear=True):
            readiness.environment(rows)
        output = readiness.markdown(rows) + json.dumps(rows)
        self.assertIn("proxy.example:8080", output)
        self.assertIn("registry.example/plugins", output)
        self.assertNotIn("private-password", output)
        self.assertNotIn("secret-token", output)
        self.assertNotIn("#secret", output)

    def test_malformed_proxy_url_is_reported_without_echoing_its_value(self):
        value = "http://secret@[malformed"
        self.assertEqual(readiness.redact_url_credentials(value),
                         "Set (malformed URL; value redacted)")

    def test_lowercase_proxy_is_detected_without_disclosing_credentials(self):
        rows = []
        with patch.dict(readiness.os.environ, {"https_proxy": "http://secret@proxy.example"},
                        clear=True):
            readiness.environment(rows)
        proxy = next(r for r in rows if r["name"] == "HTTPS_PROXY / https_proxy")
        self.assertEqual(proxy["status"], "yes")
        self.assertIn("lowercase", proxy["detail"])
        self.assertIn("proxy.example", proxy["detail"])
        self.assertNotIn("secret", json.dumps(rows))

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
        readiness.add(rows, "Private registry", "network", "test|name", "unknown",
                      "line|value", "runner")
        output = readiness.markdown(rows)
        self.assertIn("test\\|name", output)
        self.assertIn("line\\|value", output)
        self.assertIn("| Check | Result | Observed value / finding |", output)
        self.assertIn("**Why check it?**", output)
        self.assertIn("**Self-hosted consideration:**", output)
        self.assertIn("**Source documentation:**", output)
        self.assertIn("](https://docs.github.com/", output)

    def test_compact_table_links_to_details_and_preserves_full_values(self):
        rows = []
        value = "/opt/" + "runner-tool-cache/" * 10
        readiness.add(rows, "Environment", "variable", "RUNNER_TOOL_CACHE", "yes",
                      value, "variables")
        readiness.add(rows, "GitHub settings", "manual", "Runner labels and group access",
                      "unknown", "Verify repository access to the requested label.", "autosubmit_setup")
        output = readiness.markdown(rows)
        table = output.split("## Results", 1)[1].split("## Check details", 1)[0]
        self.assertIn("[RUNNER_TOOL_CACHE](#check-1)", table)
        self.assertIn("...", table)
        self.assertNotIn(value, table)
        self.assertIn("Manual verification required", table)
        self.assertIn("### check-1", output)
        self.assertIn("### check-2", output)
        self.assertIn(f"**Observed value / finding:** {value}", output)
        self.assertIn("Verify repository access to the requested label.", output)
        self.assertIn(f"**Why check it?** {rows[0]['why']}", output)
        self.assertIn(f"**Self-hosted consideration:** {rows[1]['self_hosted']}", output)

    def test_markdown_link_targets_exactly_match_unique_heading_text(self):
        rows = []
        for index in range(12):
            readiness.add(rows, "Private registry", "network", "registry.example.com",
                          "yes", f"HTTPS response {index}", "autosubmit_setup")
        output = readiness.markdown(rows)
        targets = [line[4:] for line in output.splitlines() if line.startswith("### ")]
        self.assertEqual(targets, [f"check-{index}" for index in range(1, 13)])
        self.assertEqual(len(set(targets)), len(rows))
        for target in targets:
            self.assertEqual(output.count(f"](#{target})"), 1)

    def test_all_checks_include_reason_self_hosted_context_and_sources(self):
        from urllib.error import HTTPError

        with patch.object(readiness, "tool"), patch.object(readiness, "docker"), \
                patch.object(readiness, "runner_version"), \
                patch.object(readiness.urllib.request, "urlopen",
                             side_effect=HTTPError("https://example.com/", 403, "Forbidden", {}, None)):
            rows = readiness.report(readiness.ECOSYSTEMS, registries=("registry.example.com",),
                                    concurrent_runners=20)
        self.assertTrue(rows)
        self.assertTrue(all(r["why"] and r["self_hosted"] and r["sources"] and
                            r["source"] == r["sources"][0] for r in rows))
        self.assertIn("registry.example.com", {r["name"] for r in rows})
        output = readiness.markdown(rows)
        self.assertEqual(output.count("### check-"), len(rows))
        for index, row in enumerate(rows, 1):
            self.assertIn(f"](#check-{index})", output)
            self.assertIn(row["why"], output)
            self.assertIn(row["self_hosted"], output)
            for label, source in zip(row["source_labels"], row["sources"]):
                self.assertIn(f"[{label}]({source})", output)

    def test_docker_without_client_is_not_mistaken_for_daemon_failure(self):
        rows = []
        with patch.object(readiness.shutil, "which", return_value=None):
            readiness.docker(rows)
        self.assertEqual([r["status"] for r in rows], ["no", "unknown"])

    def test_docker_rootless_mode_reports_observed_value(self):
        for code, options, status, detail in (
            (0, '["name=rootless"]', "yes", "Enabled"),
            (0, '["name=seccomp"]', "no", "Not enabled"),
            (1, "", "unknown", "Unable to determine Docker security options"),
        ):
            with self.subTest(status=status):
                rows = []
                results = [
                    readiness.subprocess.CompletedProcess([], 0, "29.0.0", ""),
                    readiness.subprocess.CompletedProcess([], code, options, ""),
                ]
                with patch.object(readiness.shutil, "which", return_value="/usr/bin/docker"), \
                        patch.object(readiness, "tool"), \
                        patch.object(readiness.subprocess, "run", side_effect=results):
                    readiness.docker(rows)
                row = next(r for r in rows if r["name"] == "Docker rootless mode")
                self.assertEqual(row["status"], status)
                self.assertTrue(row["detail"].startswith(detail))

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
