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
    "variables": "https://docs.github.com/en/actions/reference/workflows-and-actions/variables",
    "proxy": "https://docs.github.com/en/actions/how-tos/manage-runners/use-proxy-servers",
    "node_ca": "https://github.com/nodejs/node/blob/main/doc/api/cli.md#node_extra_ca_certsfile",
    "python_ssl": "https://docs.python.org/3/library/ssl.html#ssl.get_default_verify_paths",
    "residency": "https://docs.github.com/en/enterprise-cloud@latest/admin/data-residency/network-details-for-ghecom",
}

SOURCE_LABELS = {
    "runner": "Runner reference", "dependabot": "Dependabot requirements",
    "autosubmit": "Autosubmission reference", "codeql": "Code scanning default setup",
    "review": "Dependency review action", "image": "Ubuntu image inventory",
    "codeql_system": "CodeQL system requirements", "autosubmit_setup": "Autosubmission setup",
    "variables": "Actions variables", "proxy": "Runner proxy guidance",
    "node_ca": "Node.js CA configuration", "python_ssl": "Python SSL paths",
    "residency": "GHE.com network requirements",
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

# Explanations apply to observations, not to their yes/no values.
CONTEXT = {
    "RUNNER_OS": ("Identify the job's runner OS.", "A self-hosted OS may differ from GitHub's managed images."),
    "RUNNER_ARCH": ("Identify the job's CPU architecture.", "Dependabot updates require Linux x64."),
    "RUNNER_NAME": ("Identify the runner that executed this job.", "Helps distinguish several self-hosted machines; it does not prove runner labels."),
    "RUNNER_ENVIRONMENT": ("Identify whether this job ran on a GitHub-hosted or self-hosted runner.", "Shows the actual runner environment rather than inferring it from the requested label."),
    "Requested runner label": ("Record the runs-on input selected for this diagnostic workflow.", "Compare the requested target with RUNNER_ENVIRONMENT and RUNNER_NAME; this does not prove all runner labels."),
    "RUNNER_TEMP": ("Find the job's writable temporary directory and runner installation when possible.", "Custom runner installations can use different paths."),
    "RUNNER_TOOL_CACHE": ("Inspect the Actions tool-cache location.", "Self-hosted images may have no pre-populated tool cache."),
    "JAVA_HOME": ("CodeQL Java extraction expects a JDK at JAVA_HOME.", "A custom image may need a JDK configured; hosted images provide one."),
    "JAVA_HOME JDK": ("Verify that JAVA_HOME points to a JDK containing bin/java.", "Java analysis needs a usable JDK, not just a variable name."),
    "NODE_EXTRA_CA_CERTS": ("One way to make Node.js trust additional certificate authorities for actions.", "Relevant for internal registries or TLS interception; not required with trusted certificates."),
    "SSL_CERT_FILE": ("Optional OpenSSL CA-file override for Python HTTPS probes and compatible tools.", "A custom CA may need configuring; system trust can make this variable unnecessary."),
    "HTTPS_PROXY / https_proxy": ("Report HTTPS proxy settings used for outbound runner traffic.", "Needed only behind a proxy; the runner prefers lowercase on Linux and macOS."),
    "HTTP_PROXY / http_proxy": ("Report HTTP proxy settings for clients that use HTTP.", "Needed only if HTTP traffic must pass through a proxy."),
    "NO_PROXY / no_proxy": ("Report hosts that bypass a configured proxy.", "Useful for direct access to internal registries; unnecessary without a proxy."),
    "GH_DEPENDENCY_SUBMISSION_SKIP_CACHE": ("Optionally disable autosubmission's built-in package cache.", "Useful when self-hosted infrastructure manages its own cache; unset is normal."),
    "GRADLE_PLUGIN_REPOSITORY_URL": ("Point the autosubmission Gradle plugin at an internal mirror.", "Only needed if the public plugin portal is unavailable or disallowed."),
    "GRADLE_PLUGIN_REPOSITORY_USERNAME": ("Authenticate to the internal Gradle plugin mirror.", "Only needed if that mirror requires authentication."),
    "GRADLE_PLUGIN_REPOSITORY_PASSWORD": ("Authenticate to the internal Gradle plugin mirror.", "Only needed if that mirror requires authentication; never print its value."),
    "NODE_EXTRA_CA_CERTS file": ("Check that the configured Node.js CA bundle can be read.", "A set variable with an unreadable file cannot provide the intended private CA."),
    "SSL_CERT_FILE file": ("Check that the configured OpenSSL CA bundle can be read.", "A set variable with an unreadable file cannot provide the intended private CA."),
    "Running in Actions": ("Distinguish job execution from a standalone invocation.", "The job has runner context; local execution cannot establish GitHub routing."),
    "Linux x64 for Dependabot": ("Dependabot updates require Linux x64 on self-hosted runners.", "Unlike a hosted label, you provision the OS and architecture yourself."),
    "glibc >= 2.17": ("CodeQL extraction for compiled languages and Ruby requires glibc on Linux.", "Minimal or musl-based self-hosted images may not meet this requirement."),
    "Actions runner version": ("Dependency review action v5 requires runner version 2.327.1 or newer.", "You manage self-hosted runner updates; version detection may be unavailable in containers."),
    "CPU": ("Record CPU capacity for workload planning.", "Concurrent self-hosted jobs share resources; this is not a pass/fail threshold."),
    "Free temporary storage": ("Record space available for downloads, builds, and analysis.", "Self-hosted storage sizing and cleanup are your responsibility; no universal minimum."),
    "RAM": ("Record memory capacity for workload planning.", "Concurrent self-hosted jobs share memory; this is not a pass/fail threshold."),
    "git": ("CodeQL actions require Git on PATH.", "Install it on the runner image; hosted images include it."),
    "curl": ("Inventory a common download and HTTP diagnostic tool from the Ubuntu image.", "Only needed if your jobs or troubleshooting use it; not a universal prerequisite."),
    "tar": ("Inventory an archive extraction tool from the Ubuntu image.", "Useful for downloaded tools; not a universal prerequisite."),
    "unzip": ("Inventory an archive extraction tool from the Ubuntu image.", "Useful for downloaded tools; not a universal prerequisite."),
    "node": ("CodeQL TypeScript extraction requires Node.js; also inventory host Node.js.", "JavaScript actions bundle their runtime; host Node may still be needed for analysis or builds."),
    "jq": ("Inventory JSON-processing tooling from the Ubuntu image.", "Only needed if a job uses it; not a security-feature prerequisite."),
    "bash": ("The provided workflow runs its diagnostic step with Bash.", "A custom runner image must provide the workflow's shell."),
    "gcc": ("Inventory a C compiler for repository-specific builds.", "Needed only when a build requires it; default setup may use no-build mode."),
    "g++": ("Inventory a C++ compiler for repository-specific builds.", "Needed only when a build requires it; default setup may use no-build mode."),
    "make": ("Inventory a build driver for repository-specific builds.", "Needed only when a build invokes Make."),
    "clang": ("Inventory a compiler for repository-specific builds.", "Needed only when a build invokes Clang."),
    "cargo": ("CodeQL Rust extraction requires Cargo.", "Custom images need to provide it for Rust analysis."),
    "rustup": ("CodeQL Rust extraction requires rustup.", "Custom images need to provide it for Rust analysis."),
    "go": ("Inventory the Go toolchain for Go dependency and build jobs.", "Setup actions may download it; restricted runners may need it preinstalled."),
    "java": ("CodeQL Java extraction requires Java and a matching JAVA_HOME.", "Setup actions may download a JDK; custom images may need one preinstalled."),
    "mvn": ("Inventory Maven for Java dependency and build jobs.", "Optional with a project wrapper or action-provided toolchain."),
    "gradle": ("Inventory Gradle for Java dependency and build jobs.", "Optional with a project wrapper or action-provided toolchain."),
    "dotnet": ("Inventory the .NET SDK for .NET dependency and build jobs.", "Setup actions may download it; a restricted runner may need it preinstalled."),
    "python3": ("Python 3 runs this diagnostic and supports Python analysis.", "Must exist to run this workflow on a custom image."),
    "pip3": ("Inventory Python package tooling.", "Only needed when project-specific jobs invoke pip."),
    "npm": ("Inventory Node.js package tooling.", "Only needed when project-specific jobs invoke npm."),
    "ruby": ("Inventory Ruby for Ruby dependency and build jobs.", "Only needed for repositories that analyze or build Ruby."),
    "bundle": ("Inventory Bundler for Ruby dependency jobs.", "Only needed when the repository uses Bundler."),
    "docker": ("Dependabot updates need a Docker client and accessible daemon.", "Install and grant runner-user access on self-hosted infrastructure."),
    "Docker daemon access": ("Actually query Docker as the job user, not just detect the CLI.", "Dependabot updates cannot run containers without accessible Docker."),
    "Docker rootless mode": ("Report whether Docker follows GitHub's rootless recommendation.", "Rootless is recommended, not required; authorized daemon access is an alternative."),
    "Docker network address pools": ("Inspect Docker network capacity when concurrent runner count is provided.", "Above 14 concurrent Dependabot runners per VM, GitHub requires expanded pools."),
    "HTTPS probes": ("Report whether outbound endpoint checks ran.", "Restricted egress often differs from GitHub-hosted connectivity."),
    "*.actions.githubusercontent.com / *.blob.core.windows.net": ("Runner operations and artifacts use wildcard/CDN destinations.", "Firewall rules must cover wildcard and changing backing endpoints; a HEAD probe cannot."),
    "Internal package registries and proxy policy": ("Dependencies may come from private registries rather than public feeds.", "Check organization-specific routes, credentials, and egress rules separately."),
    "GitHub Enterprise data residency": ("GHE.com runners have additional network destinations.", "Only relevant if the enterprise uses data residency."),
    "Runner labels and group access": ("Managed security jobs must be routed to an accessible runner.", "Verify feature labels or custom labels and repository access for each self-hosted pool."),
    "Actions, dependency graph and security features": ("The four features require appropriate Actions and security settings.", "GitHub-hosted vs self-hosted does not change repository eligibility."),
    "Dependency review workflow": ("Review runs from a configured pull-request workflow.", "Its runs-on selection must target a runner with access to the repository."),
    "Default setup runner selection": ("Code scanning default setup must target the intended runner.", "Adding a runner after enabling setup may require reconfiguration."),
    "Dependabot updates runner selection": ("Dependabot must be enabled to use the labeled runner.", "The org or repository setting determines where its update jobs run."),
    "Automatic dependency submission runner selection": ("Autosubmission requires the dependency graph and labeled-runner selection.", "The dependency-submission runner must be available to the repository."),
    "Private registry certificates": ("Dependabot needs to trust self-signed registry certificates, including in Node.js.", "A private CA may need installing on custom runners; public certs typically do not."),
    "Gradle internal plugin repository": ("An internal mirror can replace the public Gradle plugin portal.", "Useful on restricted networks; separate from project dependency registry settings."),
    "Python .python-version": ("Python autosubmission uses setup-python to select a version.", "This is a repository requirement, not an inherent runner difference."),
    "Compiled-language build tools": ("Some CodeQL languages or build modes need project-specific builds.", "Install only the tools required by the repositories assigned to this runner."),
    "CodeQL action bundle": ("Distinguish the hosted image's bundle from a required preinstallation.", "CodeQL actions can download the bundle on self-hosted runners."),
    "github.com": ("Actions and autosubmission need GitHub source and action downloads.", "Allow outbound HTTPS from restricted self-hosted networks."),
    "api.github.com": ("Dependency submission and runner workflows call the GitHub API.", "Allow outbound API access from restricted runner networks."),
    "codeload.github.com": ("The runner downloads action source from this host.", "Allow it through self-hosted egress controls."),
    "raw.githubusercontent.com": ("Autosubmission downloads action and tool source from GitHub.", "Restricted runners must allow the source host or provide an approved alternative."),
    "github-releases.githubusercontent.com": ("Runner updates and action tooling may download GitHub releases.", "Allow the release host on restricted networks."),
    "objects.githubusercontent.com": ("Runner updates and action downloads can use this host.", "Allow the GitHubusercontent endpoint through restricted egress."),
    "objects-origin.githubusercontent.com": ("Runner software updates can use this host.", "Allow the runner-update endpoint through restricted egress."),
    "results-receiver.actions.githubusercontent.com": ("Runner logs, artifacts, and caches use the results service.", "Allow this service for self-hosted job results."),
    "dependabot-actions.githubapp.com": ("Dependabot security update jobs require this endpoint.", "Explicitly allow it for Dependabot self-hosted runners."),
    "go.dev": ("Go autosubmission can download the Go toolchain.", "Allow it when Go jobs use public downloads."),
    "golang.org": ("Alternate Go download host for autosubmission.", "Allow it when Go jobs use public downloads."),
    "proxy.golang.org": ("The official Go module proxy supplies dependencies.", "Allow it or use an approved internal Go proxy."),
    "repo.maven.apache.org": ("Maven Central supplies Java dependencies.", "Allow it if Java jobs resolve packages there."),
    "api.adoptium.net": ("setup-java may fetch the default JDK distribution here.", "Allow it or supply a JDK via another approved source."),
    "plugins.gradle.org": ("Gradle autosubmission obtains plugin metadata here.", "Allow it unless the submission plugin is mirrored internally."),
    "plugins-artifacts.gradle.org": ("Gradle autosubmission fetches plugin artifacts here.", "Allow it unless the submission plugin is mirrored internally."),
    "aka.ms": ("The .NET setup/download flow may start at this redirector.", "Allow it for .NET downloads on restricted networks."),
    "builds.dotnet.microsoft.com": ("The .NET SDK and runtime download feed.", "Allow it for .NET downloads on restricted networks."),
    "ci.dot.net": ("Secondary .NET build download feed.", "Allow it for .NET downloads on restricted networks."),
    "python.org": ("Python autosubmission may download an interpreter here.", "Allow it when Python toolchains are downloaded."),
}


def add(rows, area, kind, name, status, detail, source):
    if kind == "network" and area == "Private registry":
        why = "Probe a registry origin explicitly requested for dependency jobs."
        self_hosted = "Private registries may only be reachable from the self-hosted network; HTTPS does not prove authentication."
    else:
        why, self_hosted = CONTEXT[name]
    sources = (source,) if isinstance(source, str) else source
    rows.append(dict(area=area, kind=kind, name=name, status=status,
                     detail=detail, why=why, self_hosted=self_hosted,
                     source=DOCS[sources[0]], sources=[DOCS[key] for key in sources],
                     source_labels=[SOURCE_LABELS[key] for key in sources]))


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


def redact_url_credentials(value):
    has_scheme = "://" in value
    try:
        parsed = urllib.parse.urlsplit(value if has_scheme else "//" + value)
        if not parsed.hostname:
            return "Set (malformed URL; value redacted)"
        parsed.port
    except ValueError:
        return "Set (malformed URL; value redacted)"
    netloc = parsed.netloc
    if "@" in netloc:
        netloc = "[redacted]@" + netloc.rsplit("@", 1)[1]
    result = urllib.parse.urlunsplit((
        parsed.scheme, netloc, parsed.path,
        "[redacted]" if parsed.query else "", "[redacted]" if parsed.fragment else "",
    ))
    return result if has_scheme else result[2:]


def environment(rows):
    variable_sources = {
        "RUNNER_OS": "variables", "RUNNER_ARCH": "variables",
        "RUNNER_NAME": "variables", "RUNNER_ENVIRONMENT": "variables", "RUNNER_TEMP": "variables",
        "RUNNER_TOOL_CACHE": "variables", "JAVA_HOME": "codeql_system",
        "NODE_EXTRA_CA_CERTS": ("node_ca", "dependabot"),
        "SSL_CERT_FILE": "python_ssl",
        "GH_DEPENDENCY_SUBMISSION_SKIP_CACHE": "autosubmit",
        "GRADLE_PLUGIN_REPOSITORY_URL": "autosubmit",
        "GRADLE_PLUGIN_REPOSITORY_USERNAME": "autosubmit",
        "GRADLE_PLUGIN_REPOSITORY_PASSWORD": "autosubmit",
    }
    for name, source in variable_sources.items():
        value = os.environ.get(name)
        if name in ("GRADLE_PLUGIN_REPOSITORY_USERNAME", "GRADLE_PLUGIN_REPOSITORY_PASSWORD"):
            detail = "Set (credential redacted)"
        elif name == "GRADLE_PLUGIN_REPOSITORY_URL" and value:
            detail = redact_url_credentials(value)
        else:
            detail = value
        add(rows, "Environment", "variable", name, "yes" if value else "no",
            detail if value else "Not set (may be optional)", source)
    requested_label = os.environ.get("READINESS_RUNNER_LABEL")
    if requested_label:
        add(rows, "Runner", "setting", "Requested runner label", "yes",
            requested_label, "runner")
    for upper, lower in (("HTTPS_PROXY", "https_proxy"), ("HTTP_PROXY", "http_proxy"),
                         ("NO_PROXY", "no_proxy")):
        value = os.environ.get(lower) or os.environ.get(upper)
        add(rows, "Environment", "variable", f"{upper} / {lower}",
            "yes" if value else "no",
            ((value if upper == "NO_PROXY" else redact_url_credentials(value)) +
             " (" + ("lowercase" if os.environ.get(lower) else "uppercase") + ")")
            if value else "Neither case set (optional)", "proxy")
    for name in ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"):
        value = os.environ.get(name)
        if value:
            add(rows, "Environment", "certificate", name + " file",
                "yes" if Path(value).is_file() and os.access(value, os.R_OK) else "no",
                "Readable" if Path(value).is_file() and os.access(value, os.R_OK)
                else "Not readable", ("node_ca", "dependabot")
                if name == "NODE_EXTRA_CA_CERTS" else "python_ssl")
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
    tool(rows, "Dependabot updates", "docker", "--version", required=True, source="dependabot")
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
         "If using GHE.com, verify its additional domain requirements for runner communication", "residency"),
        ("GitHub settings", "Runner labels and group access",
         "Verify dependabot, code-scanning and dependency-submission labels (or custom labels) and repository access", "autosubmit_setup"),
        ("GitHub settings", "Actions, dependency graph and security features",
         "Verify enabled for each repository; local host inspection cannot determine these",
         ("codeql", "autosubmit_setup")),
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
             "Unknown requires GitHub configuration or a workload-specific check. Optional tools are inventory, not blockers.",
             "An unset optional variable is not an unmet requirement. A network response does not prove registry authorization.", "",
             "| Area | Type | Check | Present/accessible | Detail | Why check it? | Self-hosted consideration | Source documentation |",
             "|---|---|---|---|---|---|---|---|"]
    lines.extend("| " + " | ".join(map(cell, (r["area"], r["kind"], r["name"],
                                            r["status"], r["detail"], r["why"],
                                            r["self_hosted"]))) +
                 " | " + ", ".join(f"[{cell(label)}]({url})" for label, url in
                                 zip(r["source_labels"], r["sources"])) + " |" for r in rows)
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
