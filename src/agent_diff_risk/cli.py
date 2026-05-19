from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import PurePosixPath
from typing import Iterable


SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|secret|token|password|passwd|private[_-]?key|access[_-]?key)\s*[:=]\s*['\"]?[^'\"\s]{12,}"
)
RISKY_TEXT = [
    ("auth/permission keyword added", re.compile(r"(?i)\b(auth|oauth|jwt|session|permission|rbac|csrf|cors)\b"), 2),
    ("payment/billing keyword added", re.compile(r"(?i)\b(stripe|payment|billing|invoice|checkout|webhook)\b"), 2),
    ("shell/process execution added", re.compile(r"(?i)\b(subprocess|exec\(|eval\(|shell=True|child_process|os\.system)\b"), 3),
    ("network call added", re.compile(r"(?i)\b(fetch\(|requests\.|urllib|axios\.|http\.client|net/http)\b"), 1),
]
SENSITIVE_PATHS = [
    ("auth/security-sensitive path", re.compile(r"(?i)(^|/)(auth|oauth|security|session|permission|rbac|csrf|cors)(/|\.|$)"), 4),
    ("payment-sensitive path", re.compile(r"(?i)(^|/)(billing|payment|payments|stripe|checkout|invoice)(/|\.|$)"), 4),
    ("database migration changed", re.compile(r"(?i)(^|/)(migrations?|schema)(/|\.|$)"), 3),
    ("infrastructure/deploy config changed", re.compile(r"(?i)(^|/)(terraform|helm|k8s|deploy|infra|\.github/workflows)(/|\.|$)"), 3),
    ("dependency lockfile changed", re.compile(r"(?i)(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|poetry\.lock|uv\.lock|requirements.*\.txt|go\.sum|Cargo\.lock)$"), 2),
    ("environment config touched", re.compile(r"(?i)(^|/)\.env(\.|$)|config\.(ya?ml|json|toml)$"), 3),
]
SOURCE_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb", ".php", ".cs"}
TEST_RE = re.compile(r"(?i)(^|/)(tests?|spec|__tests__)(/|$)|(_test|\.test|\.spec)\.")


@dataclass
class Finding:
    severity: str
    points: int
    message: str
    file: str | None = None
    line: int | None = None


@dataclass
class Score:
    level: str
    points: int
    files_changed: int
    additions: int
    deletions: int
    findings: list[Finding]
    checklist: list[str]


def severity(points: int) -> str:
    if points >= 5:
        return "critical"
    if points >= 3:
        return "high"
    if points >= 2:
        return "medium"
    return "low"


def risk_level(points: int) -> str:
    if points >= 20:
        return "critical"
    if points >= 10:
        return "high"
    if points >= 5:
        return "medium"
    if points > 0:
        return "low"
    return "none"


def parse_diff(diff: str) -> tuple[dict[str, dict[str, int]], list[tuple[str, int, str]]]:
    files: dict[str, dict[str, int]] = {}
    additions: list[tuple[str, int, str]] = []
    current: str | None = None
    new_line = 0
    for raw in diff.splitlines():
        if raw.startswith("diff --git "):
            parts = raw.split()
            current = parts[3][2:] if len(parts) >= 4 and parts[3].startswith("b/") else None
            if current:
                files.setdefault(current, {"additions": 0, "deletions": 0})
            continue
        if raw.startswith("+++ b/"):
            current = raw[6:]
            files.setdefault(current, {"additions": 0, "deletions": 0})
            continue
        if raw.startswith("@@"):
            match = re.search(r"\+(\d+)", raw)
            new_line = int(match.group(1)) if match else 0
            continue
        if current is None:
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            files[current]["additions"] += 1
            additions.append((current, new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-") and not raw.startswith("---"):
            files[current]["deletions"] += 1
        else:
            new_line += 1
    return files, additions


def score_diff(diff: str) -> Score:
    files, additions = parse_diff(diff)
    findings: list[Finding] = []
    total_additions = sum(v["additions"] for v in files.values())
    total_deletions = sum(v["deletions"] for v in files.values())

    for path, stats in files.items():
        normalized = path.replace("\\", "/")
        for label, pattern, points in SENSITIVE_PATHS:
            if pattern.search(normalized):
                findings.append(Finding(severity(points), points, f"{label} changed", normalized))
        suffix = PurePosixPath(normalized).suffix
        if suffix in {".sh", ".ps1", ".bat"}:
            findings.append(Finding("medium", 2, "executable/script file changed", normalized))
        if stats["deletions"] >= 80:
            findings.append(Finding("medium", 2, f"large deletion block ({stats['deletions']} removed lines)", normalized))

    if len(files) >= 20:
        findings.append(Finding("high", 3, f"wide diff touches {len(files)} files"))
    if total_additions + total_deletions >= 600:
        findings.append(Finding("high", 3, f"large diff has {total_additions + total_deletions} changed lines"))

    for path, line_no, text in additions:
        if SECRET_RE.search(text):
            findings.append(Finding("critical", 8, "secret-looking value added", path, line_no))
        for label, pattern, points in RISKY_TEXT:
            if pattern.search(text):
                findings.append(Finding(severity(points), points, label, path, line_no))

    changed_paths = set(files)
    has_source = any(PurePosixPath(p).suffix in SOURCE_EXTS for p in changed_paths)
    has_tests = any(TEST_RE.search(p.replace("\\", "/")) for p in changed_paths)
    if has_source and not has_tests:
        findings.append(Finding("low", 1, "source changed without nearby test changes"))

    points = sum(f.points for f in findings)
    checklist = [
        "Inspect all critical/high findings before running or merging.",
        "Ask the agent to explain each sensitive-file change.",
        "Run the affected test suite and at least one smoke test.",
    ]
    level = risk_level(points)
    if any(f.severity == "critical" for f in findings):
        level = "critical"
        checklist.insert(0, "Treat critical findings as blocking until manually cleared.")
    return Score(level, points, len(files), total_additions, total_deletions, findings, checklist)


def read_diff(args: argparse.Namespace) -> str:
    if args.diff_file:
        with open(args.diff_file, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    if not sys.stdin.isatty():
        return sys.stdin.read()
    try:
        return subprocess.check_output(["git", "diff", "--cached"], text=True)
    except Exception:
        return ""


def score_to_dict(score: Score) -> dict:
    data = asdict(score)
    data["findings"] = [asdict(f) for f in score.findings]
    return data


def print_human(score: Score) -> None:
    print(f"Risk: {score.level.upper()} (score {score.points})")
    print(f"Files changed: {score.files_changed} (+{score.additions}/-{score.deletions})")
    if score.findings:
        print("\nFindings:")
        for finding in score.findings:
            loc = f" in {finding.file}" if finding.file else ""
            if finding.line:
                loc += f":{finding.line}"
            print(f"- {finding.severity.upper()}: {finding.message}{loc}")
    else:
        print("\nFindings: none")
    print("\nSuggested review checklist:")
    for item in score.checklist:
        print(f"- {item}")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score AI coding-agent Git diffs for review risk.")
    parser.add_argument("--diff-file", help="Read a unified diff from a file instead of stdin/git diff --cached.")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    parser.add_argument("--fail-on", choices=["low", "medium", "high", "critical"], help="Exit 2 if risk is at or above this level.")
    args = parser.parse_args(list(argv) if argv is not None else None)

    score = score_diff(read_diff(args))
    if args.json:
        print(json.dumps(score_to_dict(score), indent=2, sort_keys=True))
    else:
        print_human(score)

    order = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if args.fail_on and order[score.level] >= order[args.fail_on]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
