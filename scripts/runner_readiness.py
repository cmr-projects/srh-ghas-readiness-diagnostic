#!/usr/bin/env python3
"""Report self-hosted runner prerequisites without modifying the runner."""

import argparse
import json
import os
import platform
import re
import shutil
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


DOCS = {
    "runner": "https://docs.github.com/en/enterprise-cloud@latest/actions/reference/runners/self-hosted-runners",
    "dependabot": "https://docs.github.com/en/enterprise-cloud@latest/code-security/reference/supply-chain-security/dependabot-on-actions#requirements-for-using-dependabot-with-self-hosted-runners",
    "autosubmit": "https://docs.github.com/en/enterprise-cloud@latest/code-security/reference/supply-chain-security/automatic-dependency-submission",
    "codeql": "https://docs.github.com/en/enterprise-cloud@latest/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configure-code-scanning",
    "review": "https://github.com/actions/dependency-review-action/blob/main/README.md",
    "image": "https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2604-Readme.md",
    "codeql_system": "https://codeql.github.com/docs/codeql-overview/system-requirements/",
    "autosubmit_setup": "https://docs.github.com/en/enterprise-cloud@latest/code-security/how-tos/secure-your-supply-chain/secure-your-dependencies/submit-dependencies-automatically",
}

ECOSYSTEMS = ("go", "maven", "gradle", "dotnet", "python", "npm", "ruby")
TOOLS = {
    "common": (("git", "--version"), ("curl", "--version"), ("tar", "--version"),
               ("unzip", "-v"), ("node", "--version"), ("jq", "--version"),
               ("bash", "--version"), ("gcc", "--version"), ("g++", "--version"),
               ("make", "--version"), ("clang", "--version"), ("cargo", "--version"),
               ("rustup", "--version")),
    "go": (("go", "version"),),
    "maven": (("java", "-version"), ("mvn", "-version")),
    "gradle": (("java", "-version"), ("gradle", "--version")),
    "dotnet": (("dotnet", "--version"),),
    "python": (("python3", "--version"), ("pip3", "--version")),
    "npm": (("npm", "--version"),),
    "ruby": (("ruby", "--version"), ("bundle", "--version")),
}
ENDPOINTS = {
    "common": ("github.com", "api.github.com", "codeload.github.com",
               "raw.githubusercontent.com", "github-releases.githubusercontent.com",
               "objects.githubusercontent.com", "objects-origin.githubusercontent.com",
               "results-receiver.actions.githubusercontent.com",
               "dependabot-actions.githubapp.com"),
    "go": ("go.dev", "golang.org", "proxy.golang.org"),
    "maven": ("repo.maven.apache.org", "api.adoptium.net"),
    "gradle": ("repo.maven.apache.org", "api.adoptium.net", "plugins.gradle.org",
               "plugins-artifacts.gradle.org"),
    "dotnet": ("aka.ms", "builds.dotnet.microsoft.com", "ci.dot.net"),
    "python": ("python.org",),
}


def add(rows, area, kind, name, status, detail, source):
    rows.append(dict(area=area, kind=kind, name=name, status=status,
                     detail=detail, source=DOCS[source]))


def tool(rows, area, name, arg, required=False, source="image"):
    path = shutil.which(name)
    if not path:
        add(rows, area, "tool", name, "no",
            "Not on PATH" + ("" if required else "; may be supplied by an action"), source)
        return
    try:
        result = subprocess.run([path, arg], capture_output=True, text=True, timeout=5,
                                check=False)
        output = [line for line in (result.stdout or result.stderr).splitlines() if line.strip()]
        detail = output[0][:160] if output else "Version unavailable"
    except (OSError, subprocess.TimeoutExpired) as exc:
        add(rows, area, "tool", name, "no", f"Cannot execute: {type(exc).__name__}", source)
        return
    add(rows, area, "tool", name, "yes" if result.returncode == 0 else "no",
        f"{path}: {detail}", source)


def network(rows, area, host, source):
    url = f"https://{host}/"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=5) as response:
            code = response.status
    except urllib.error.HTTPError as exc:
        code = exc.code
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        category = ("TLS certificate error" if isinstance(reason, ssl.SSLError)
                    else "Timeout" if isinstance(reason, TimeoutError)
                    else type(exc).__name__)
        add(rows, area, "network", host, "no",
            f"HTTPS failed ({category}); check DNS, proxy, firewall and certificate trust", source)
        return
    # 403/404 on a probe path still proves TLS connectivity, not authorization.
    add(rows, area, "network", host, "unknown" if code >= 500 else "yes",
        f"HTTPS responded ({code}); does not verify access to every path or CDN target",
        source)


def environment(rows):
    for name in ("RUNNER_OS", "RUNNER_ARCH", "RUNNER_NAME", "RUNNER_TEMP",
                 "RUNNER_TOOL_CACHE", "JAVA_HOME", "NODE_EXTRA_CA_CERTS",
                 "SSL_CERT_FILE", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
                 "GH_DEPENDENCY_SUBMISSION_SKIP_CACHE", "GRADLE_PLUGIN_REPOSITORY_URL",
                 "GRADLE_PLUGIN_REPOSITORY_USERNAME", "GRADLE_PLUGIN_REPOSITORY_PASSWORD"):
        value = os.environ.get(name)
        # Never print variable contents: proxy URLs and even paths can contain credentials.
        add(rows, "Environment", "variable", name, "yes" if value else "no",
            "Set (value redacted)" if value else "Not set (may be optional)", "autosubmit")
    for name in ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"):
        value = os.environ.get(name)
        if value:
            add(rows, "Environment", "certificate", name + " file",
                "yes" if Path(value).is_file() and os.access(value, os.R_OK) else "no",
                "Readable" if Path(value).is_file() and os.access(value, os.R_OK)
                else "Not readable", "dependabot")
    add(rows, "Environment", "setting", "Running in Actions",
        "yes" if os.environ.get("GITHUB_ACTIONS") == "true" else "no",
        "Runner context available" if os.environ.get("GITHUB_ACTIONS") == "true"
        else "Standalone inspection; runner labels cannot be inferred", "runner")


def docker(rows):
    path = shutil.which("docker")
    if not path:
        add(rows, "Dependabot updates", "tool", "docker", "no",
            "Docker client not on PATH", "dependabot")
        add(rows, "Dependabot updates", "setting", "Docker daemon access", "unknown",
            "Docker client unavailable; cannot test daemon access as runner user", "dependabot")
        return
    tool(rows, "Dependabot updates", "docker", "--version", required=True)
    try:
        result = subprocess.run([path, "info", "--format", "{{.ServerVersion}}"],
                                capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        add(rows, "Dependabot updates", "setting", "Docker daemon access", "no",
            f"Cannot query Docker: {type(exc).__name__}", "dependabot")
        return
    add(rows, "Dependabot updates", "setting", "Docker daemon access",
        "yes" if result.returncode == 0 else "no",
        f"Server {result.stdout.strip()}" if result.returncode == 0
        else "Runner user cannot query Docker daemon", "dependabot")
    if result.returncode == 0:
        try:
            security = subprocess.run([path, "info", "--format", "{{json .SecurityOptions}}"],
                                      capture_output=True, text=True, timeout=8, check=False)
            add(rows, "Dependabot updates", "setting", "Docker rootless mode",
                "yes" if security.returncode == 0 and "rootless" in security.stdout else
                "no" if security.returncode == 0 else "unknown",
                "Recommended, not required; privileged daemon access is an alternative",
                "dependabot")
        except (OSError, subprocess.TimeoutExpired) as exc:
            add(rows, "Dependabot updates", "setting", "Docker rootless mode", "unknown",
                f"Cannot inspect Docker security options: {type(exc).__name__}", "dependabot")


def runner_version(rows):
    temp = os.environ.get("RUNNER_TEMP")
    if not temp:
        add(rows, "Runner", "tool", "Actions runner version", "unknown",
            "Run inside a job to locate the runner installation", "runner")
        return
    binary = Path(temp).resolve().parent.parent / "bin" / "Runner.Listener"
    if not binary.is_file():
        add(rows, "Runner", "tool", "Actions runner version", "unknown",
            "Runner.Listener not found relative to RUNNER_TEMP", "runner")
        return
    try:
        result = subprocess.run([str(binary), "--version"], capture_output=True,
                                text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        result = None
    version = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", result.stdout + result.stderr) if result and result.returncode == 0 else None
    add(rows, "Runner", "tool", "Actions runner version",
        "yes" if version and tuple(map(int, version.groups())) >= (2, 327, 1) else
        "no" if version else "unknown",
        f"{version.group(0)} (dependency-review-action v5 requires >= 2.327.1)"
        if version else "Unable to determine version", "review")


def resources(rows):
    cpu = os.cpu_count()
    add(rows, "Runner", "resource", "CPU", "yes" if cpu else "unknown",
        f"{cpu} logical CPUs (required capacity depends on workload)" if cpu
        else "Unable to determine CPU count", "dependabot")
    temp = os.environ.get("RUNNER_TEMP", "/tmp")
    try:
        space = shutil.disk_usage(temp)
        add(rows, "Runner", "resource", "Free temporary storage", "yes",
            f"{space.free / (1024 ** 3):.1f} GiB available in runner temp filesystem; no universal minimum",
            "runner")
    except OSError as exc:
        add(rows, "Runner", "resource", "Free temporary storage", "unknown",
            f"Cannot inspect runner temp filesystem: {type(exc).__name__}", "runner")
    if platform.system() == "Linux":
        try:
            meminfo = Path("/proc/meminfo").read_text()
            match = re.search(r"^MemTotal:\s+(\d+) kB$", meminfo, re.MULTILINE)
            if match:
                add(rows, "Runner", "resource", "RAM", "yes",
                    f"{int(match.group(1)) / (1024 ** 2):.1f} GiB total; capacity depends on workload",
                    "dependabot")
            else:
                add(rows, "Runner", "resource", "RAM", "unknown",
                    "MemTotal not found", "dependabot")
        except OSError as exc:
            add(rows, "Runner", "resource", "RAM", "unknown",
                f"Cannot inspect /proc/meminfo: {type(exc).__name__}", "dependabot")


def report(ecosystems, probe_network=True, concurrent_runners=None, registries=()):
    rows = []
    system = platform.system()
    arch = platform.machine().lower()
    add(rows, "Runner", "setting", "Linux x64 for Dependabot",
        "yes" if system == "Linux" and arch in ("x86_64", "amd64") else "no",
        f"{system} / {arch}; required for Dependabot updates", "dependabot")
    libc, version = platform.libc_ver()
    match = re.match(r"(\d+)\.(\d+)", version)
    add(rows, "CodeQL", "setting", "glibc >= 2.17",
        "yes" if system == "Linux" and libc == "glibc" and match and
        tuple(map(int, match.groups())) >= (2, 17) else
        "no" if system == "Linux" and libc and match else "unknown",
        f"{libc or 'unavailable'} {version or ''}; applies to compiled languages and Ruby on Linux",
        "codeql_system")
    runner_version(rows)
    environment(rows)
    resources(rows)
    for name, arg in TOOLS["common"]:
        tool(rows, "Shared tools (informational except git)", name, arg,
             name == "git", "codeql_system" if name in ("git", "node", "cargo", "rustup") else "image")
    for eco in ecosystems:
        for name, arg in TOOLS[eco]:
            if name not in {item["name"] for item in rows if item["kind"] == "tool"}:
                tool(rows, f"{eco} tooling (informational)", name, arg,
                     source="codeql_system" if name in ("java", "python3") else "image")
    if "maven" in ecosystems or "gradle" in ecosystems:
        home = os.environ.get("JAVA_HOME")
        add(rows, "CodeQL", "setting", "JAVA_HOME JDK",
            "yes" if home and (Path(home) / "bin" / "java").is_file() else "no",
            "Points to a JDK with bin/java" if home and (Path(home) / "bin" / "java").is_file()
            else "Not set or bin/java missing; required for CodeQL Java extraction", "codeql_system")
    docker(rows)
    if concurrent_runners is not None:
        path = Path("/etc/docker/daemon.json")
        try:
            config = json.loads(path.read_text()) if path.is_file() else {}
            pools = config.get("default-address-pools")
            status = "yes" if isinstance(pools, list) and pools else "no"
            detail = "Address pools configured" if status == "yes" else "No default-address-pools configured"
        except (OSError, ValueError) as exc:
            status, detail = "unknown", f"Cannot inspect daemon.json: {type(exc).__name__}"
        add(rows, "Dependabot updates", "setting", "Docker network address pools", status,
            detail + ("; required above 14 concurrent runners" if concurrent_runners > 14
                      else "; only required above 14 concurrent runners"), "dependabot")
    else:
        add(rows, "Dependabot updates", "setting", "Docker network address pools", "unknown",
            "Pass --concurrent-runners to check whether increased Docker network capacity is required",
            "dependabot")
    if probe_network:
        hosts = dict.fromkeys(ENDPOINTS["common"], "runner")
        hosts["dependabot-actions.githubapp.com"] = "dependabot"
        for eco in ecosystems:
            for host in ENDPOINTS.get(eco, ()):
                hosts[host] = "autosubmit"
        for host, source in hosts.items():
            network(rows, "Network", host, source)
        for host in registries:
            network(rows, "Private registry", host, "autosubmit_setup")
    else:
        add(rows, "Network", "setting", "HTTPS probes", "unknown",
            "Skipped by --no-network", "runner")
    for area, name, detail, source in (
        ("Network", "*.actions.githubusercontent.com / *.blob.core.windows.net",
         "Wildcard and CDN destinations must be allowlisted; one probe cannot cover them", "runner"),
        ("Network", "Internal package registries and proxy policy",
         "Validate from the runner with your organization-specific endpoints", "dependabot"),
        ("Network", "GitHub Enterprise data residency",
         "If using GHE.com, verify its additional domain requirements for runner communication", "runner"),
        ("GitHub settings", "Runner labels and group access",
         "Verify dependabot, code-scanning and dependency-submission labels (or custom labels) and repository access", "autosubmit_setup"),
        ("GitHub settings", "Actions, dependency graph and security features",
         "Verify enabled for each repository; local host inspection cannot determine these", "codeql"),
        ("GitHub settings", "Dependency review workflow",
         "Verify pull_request trigger, contents: read and intended runs-on label", "review"),
        ("GitHub settings", "Default setup runner selection",
         "Default setup must be configured to use this runner; existing setup may need reconfiguration", "codeql"),
        ("GitHub settings", "Dependabot updates runner selection",
         "Confirm Dependabot on Actions and labeled runner settings at repository or organization level", "dependabot"),
        ("GitHub settings", "Automatic dependency submission runner selection",
         "Confirm dependency graph is enabled and automatic submission uses labeled runners", "autosubmit_setup"),
        ("Environment", "Private registry certificates",
         "If self-signed, install trusted CA for Docker/OS and configure Node.js trust", "dependabot"),
        ("Environment", "Gradle internal plugin repository",
         "If configured, verify the internal mirror is reachable; public Gradle Plugin Portal may not be needed",
         "autosubmit"),
        ("GitHub settings", "Python .python-version",
         "For Python auto-submission, verify the repository specifies the Python version", "autosubmit"),
        ("CodeQL", "Compiled-language build tools",
         "Confirm project-specific compilers/build commands work; preinstalled tools alone cannot prove this", "codeql_system"),
        ("Runner", "CodeQL action bundle",
         "Downloaded by the action; preinstallation from the Ubuntu image is not required", "image"),
    ):
        add(rows, area, "manual", name, "unknown", detail, source)
    return rows


def markdown(rows):
    def cell(value):
        return str(value).replace("|", "\\|").replace("\n", " ")

    lines = ["# Self-hosted runner readiness", "",
             "Yes/no describes the observed host or HTTPS response, not end-to-end workflow success.",
             "Unknown requires GitHub configuration or a workload-specific check. Optional tools are inventory, not blockers.", "",
             "| Area | Type | Check | Present/accessible | Detail |",
             "|---|---|---|---|---|"]
    lines.extend("| " + " | ".join(map(cell, (r["area"], r["kind"], r["name"],
                                            r["status"], r["detail"]))) + " |" for r in rows)
    lines += ["", "## Sources", ""]
    lines.extend(f"- {url}" for url in dict.fromkeys(r["source"] for r in rows))
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ecosystems", default=",".join(ECOSYSTEMS),
                        help="Comma-separated ecosystems: " + ", ".join(ECOSYSTEMS))
    parser.add_argument("--no-network", action="store_true", help="Skip HTTPS probes")
    parser.add_argument("--concurrent-runners", type=int, help="Runner count on this host")
    parser.add_argument("--registry-url", action="append", default=[],
                        help="Extra HTTPS registry origin to probe (repeatable; no credentials)")
    parser.add_argument("--json-file", type=Path, help="Write machine-readable report")
    parser.add_argument("--markdown-file", type=Path, help="Write Markdown report")
    args = parser.parse_args()
    ecosystems = [value.strip() for value in args.ecosystems.split(",") if value.strip()]
    if not ecosystems or set(ecosystems) - set(ECOSYSTEMS):
        parser.error("ecosystems must be a nonempty comma-separated subset of: " + ", ".join(ECOSYSTEMS))
    if args.concurrent_runners is not None and args.concurrent_runners < 1:
        parser.error("--concurrent-runners must be positive")
    registries = []
    for url in args.registry_url:
        try:
            parsed = urllib.parse.urlsplit(url)
            host = parsed.hostname
            port = parsed.port
            username = parsed.username
            password = parsed.password
        except ValueError:
            parser.error("--registry-url must be a valid HTTPS origin without credentials")
        if parsed.scheme != "https" or not host or username is not None or password is not None or \
                parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            parser.error("--registry-url must be an HTTPS origin without credentials or paths")
        registries.append(f"{host}:{port}" if port else host)
    rows = report(dict.fromkeys(ecosystems), not args.no_network, args.concurrent_runners, registries)
    text = markdown(rows)
    if args.json_file:
        args.json_file.write_text(json.dumps({"checks": rows}, indent=2) + "\n")
    if args.markdown_file:
        args.markdown_file.write_text(text)
    print(text)


if __name__ == "__main__":
    main()
