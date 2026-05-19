# Agent Diff Risk

Local-first risk scoring for AI coding-agent diffs. It reads a Git diff, flags risky change patterns, and prints a short checklist before you let an agent commit or merge.

Why it exists: AI coding agents are fast, but humans still need a cheap pre-flight check for "did this touch auth, CI, secrets, migrations, or huge generated files?" This tool is deterministic, offline, and CI-friendly.

## Install

```bash
pipx install agent-diff-risk
# or from a clone
python -m pip install -e .
```

## Use

Score the current working tree:

```bash
git diff --cached | agent-diff-risk
# or
agent-diff-risk --diff-file patch.diff
```

Fail CI when risk is high:

```bash
git diff origin/main...HEAD | agent-diff-risk --fail-on high
```

JSON output for bots:

```bash
git diff origin/main...HEAD | agent-diff-risk --json
```

## What it checks

- Sensitive file paths: auth, payments, migrations, infra, CI, lockfiles.
- Diff shape: large diffs, many files, deletions, executable/script changes.
- Risky text: secret-looking additions, permission/auth keywords, network and shell execution calls.
- Test signal: whether tests changed alongside source changes.

It does **not** send code anywhere or call an LLM.

## Example

```text
Risk: HIGH (score 15)
Files changed: 4 (+120/-35)

Findings:
- HIGH: secret-looking value added in src/config.py
- MEDIUM: auth/security-sensitive path changed: src/auth/session.py
- LOW: source changed without nearby test changes

Suggested review checklist:
- Inspect all high findings before running or merging.
- Ask the agent to explain each sensitive-file change.
- Run the affected test suite and a smoke test.
```

## GitHub Actions

```yaml
name: diff-risk
on: [pull_request]
jobs:
  risk:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-python@v5
        with: { python-version: '3.x' }
      - run: python -m pip install agent-diff-risk
      - run: git diff origin/${{ github.base_ref }}...HEAD | agent-diff-risk --fail-on critical
```

## Commercial optionality

The open-source CLI can stay free while a hosted/team product could add policy packs, PR comments, historical risk trends, and per-repo dashboards.

## License

MIT
