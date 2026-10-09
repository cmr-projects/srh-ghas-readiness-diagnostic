# Self-hosted runner readiness diagnostic

A read-only report of tools, environment variables, system settings, and outbound HTTPS access relevant to automatic dependency submission, Dependabot updates, dependency review, and CodeQL default setup. This first version targets self-hosted runners **without Actions Runner Controller (ARC)**.

## Run on a self-hosted runner

In this repository, open **Actions → Self-hosted runner readiness → Run workflow**. Choose a label that targets the runner you want to inspect, and enter only the package ecosystems your repositories use. If more than 14 Dependabot runners share a host, enter the host's runner count to inspect its Docker network-pool setting. The job summary contains a Markdown table, and the run uploads the JSON report as an artifact.

The workflow requires Python 3 on the runner and uses `actions/checkout@v4` and `actions/upload-artifact@v4`. Run the command directly as the Actions runner user if the workflow cannot start:

```bash
python3 scripts/runner_readiness.py --ecosystems go,maven,gradle,dotnet,python,npm,ruby \
  --concurrent-runners 20 --registry-url https://registry.example.com \
  --json-file runner-readiness.json --markdown-file runner-readiness.md
```

`--concurrent-runners`, `--registry-url`, and output paths are optional; `--registry-url` may be repeated for HTTPS registry origins without credentials or paths. Use `--no-network` to avoid outbound probes. The script does not download dependencies, start containers, or query GitHub settings with a token. It prints the checked environment-variable values except credentials. Registry usernames/passwords are redacted; proxy and registry URLs retain their locations but redact embedded credentials, query parameters, and fragments. Malformed URLs are reported without echoing their values. It never dumps the entire environment.

The job logs, summary, and JSON artifact show `RUNNER_NAME`, `RUNNER_OS`, `RUNNER_ARCH`, `RUNNER_ENVIRONMENT`, `RUNNER_TEMP`, and `RUNNER_TOOL_CACHE` values, plus Java/certificate paths, proxy configuration, and other noncredential settings. `RUNNER_ENVIRONMENT` distinguishes `github-hosted` from `self-hosted`; the workflow also records the requested runner label for comparison. These identify the job environment, not every label or runner group. Review runner names, local paths, and internal hostnames before sharing reports externally. Standalone execution reports unset Actions variables rather than inventing runner identity.

**Interpretation:** Yes/no reports an observed check; unknown means this host cannot prove the setting. Missing optional software from the [Ubuntu 26.04 runner image](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2604-Readme.md) is not necessarily a blocker: actions can download toolchains. Network probes test TLS/HTTPS reachability to the named origins, not authorization, wildcard/CDN coverage, or every path. The runner may need additional internal registries, proxies, certificates, and build tools for specific repositories. Confirm GitHub feature enablement, runner labels/groups, policies, and workflow routing separately; then run each managed feature against a representative repository. This tool cannot guarantee end-to-end success of those workflows.

Every check includes **why it is checked**, **when it matters on a self-hosted runner**, and clickable **source documentation** in the job summary. The JSON artifact includes `why`, `self_hosted`, and `sources` for each row alongside the original `source` URL. Optional variables marked "no" are not automatically blockers. Proxy rows check both uppercase and lowercase forms, preferring lowercase on Linux and macOS as [GitHub's runner proxy guidance](https://docs.github.com/en/actions/how-tos/manage-runners/use-proxy-servers) recommends. `SSL_CERT_FILE` is an optional Python/OpenSSL trust override, not a GitHub feature requirement; its source is the current [Python SSL documentation](https://docs.python.org/3/library/ssl.html#ssl.get_default_verify_paths).

### References

- [Self-hosted runner network and software requirements](https://docs.github.com/en/enterprise-cloud@latest/actions/reference/runners/self-hosted-runners)
- [Dependabot on self-hosted runners](https://docs.github.com/en/enterprise-cloud@latest/code-security/reference/supply-chain-security/dependabot-on-actions#requirements-for-using-dependabot-with-self-hosted-runners)
- [Configuring automatic dependency submission on self-hosted runners](https://docs.github.com/en/enterprise-cloud@latest/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/submit-dependencies-automatically) and [network requirements](https://docs.github.com/en/enterprise-cloud@latest/code-security/reference/supply-chain-security/automatic-dependency-submission)
- [Code scanning default setup](https://docs.github.com/en/enterprise-cloud@latest/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configure-code-scanning) and [CodeQL system requirements](https://codeql.github.com/docs/codeql-overview/system-requirements/)
- [Dependency review action runner requirements](https://github.com/actions/dependency-review-action/blob/main/README.md)

To run the local tests: `python3 -m unittest discover -s tests`.
