# Maintaining the runner readiness diagnostic

This repository checks **non-ARC self-hosted runners** from a manually dispatched Actions workflow and from a direct Python 3 invocation. Keep `scripts/runner_readiness.py`, `.github/workflows/runner-readiness.yml`, `tests/test_runner_readiness.py`, and `README.md` in sync.

- Before changing a requirement, check the current GitHub documentation and GitHub-owned repositories linked in `README.md` and `DOCS` in the script. Verify the live Ubuntu runner-image inventory rather than pinning its example versions as minimums. If using a source outside GitHub Docs or GitHub repositories, verify its freshness first.
- Distinguish **required** conditions from optional image inventory and ecosystem-specific toolchains. Automatic dependency submission may download tools during managed jobs. Do not label every missing Ubuntu-image tool as a blocker.
- Run checks as the Actions job user without root privileges; do not install dependencies, change host settings, start containers, or require ARC. Keep direct CLI use working outside Actions.
- Never print proxy credentials, registry credentials, GitHub tokens, or environment-variable values. Limit registry probes to explicit HTTPS origins without embedded credentials. Network success proves connection to one origin, not authentication, wildcard allowlist completeness, or a working managed job.
- Use `unknown` for remote GitHub configuration and anything that cannot be inspected reliably from the job; do not infer runner labels or repository feature settings from local variables. Document any newly added manual checks.
- Keep probes bounded by timeouts and report per-check failures rather than stopping the whole report. Make new checks and status semantics explicit in JSON and Markdown, with a source URL.
- After changing the script, run `python3 -m unittest discover -s tests` and a local CLI smoke test with `--no-network`. Add focused tests for thresholds, failures, redaction, and output shape. The real runner workflow needs a later run on representative infrastructure.
