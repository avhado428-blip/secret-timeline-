import os
import subprocess
import re
from dataclasses import dataclass

from app.detectors import scan_line, LineFinding


@dataclass
class ScanResult:
    secret_type: str
    detection_method: str
    secret_hash: str
    file_path: str
    line_number: int
    commit_hash: str
    commit_date: str
    author: str


def run_git(args: list[str], cwd: str) -> str:
    result = subprocess.run(
        ["git"] + args, cwd=cwd, capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {result.stderr}")
    return result.stdout


def get_commit_list(repo_dir: str, limit: int | None = None) -> list[tuple[str, str, str, str]]:
    if limit is not None:
        args = ["log", "--all", f"-{limit}", "--pretty=format:%H|%aI|%an|%s"]
    else:
        args = ["log", "--all", "--reverse", "--pretty=format:%H|%aI|%an|%s"]

    output = run_git(args, cwd=repo_dir)
    commits = []
    for line in output.splitlines():
        if not line.strip():
            continue
        parts = line.split("|", 3)
        commit_hash, date, author = parts[0], parts[1], parts[2]
        message = parts[3] if len(parts) > 3 else ""
        commits.append((commit_hash, date, author, message))

    if limit is not None:
        commits.reverse()

    return commits


HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


def get_added_lines(repo_dir: str, commit_hash: str) -> list[tuple[str, int, str]]:
    diff = run_git(["show", "--unified=0", "--no-color", commit_hash], cwd=repo_dir)

    added_lines = []
    current_file = None
    current_line_no = None

    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            current_file = path[2:] if path.startswith("b/") else path
            continue

        hunk_match = HUNK_RE.match(line)
        if hunk_match:
            current_line_no = int(hunk_match.group(1))
            continue

        if line.startswith("+") and not line.startswith("+++"):
            if current_file and current_line_no is not None:
                added_lines.append((current_file, current_line_no, line[1:]))
                current_line_no += 1
        elif line.startswith("-") and not line.startswith("---"):
            pass

    return added_lines


def scan_repo(repo_dir: str, commits: list[tuple[str, str, str, str]] | None = None) -> list[ScanResult]:
    results: list[ScanResult] = []
    if commits is None:
        commits = get_commit_list(repo_dir)

    for commit_hash, date, author, message in commits:
        added_lines = get_added_lines(repo_dir, commit_hash)
        for file_path, line_number, content in added_lines:
            findings: list[LineFinding] = scan_line(content)
            for f in findings:
                results.append(ScanResult(
                    secret_type=f.secret_type,
                    detection_method=f.detection_method,
                    secret_hash=f.secret_hash,
                    file_path=file_path,
                    line_number=line_number,
                    commit_hash=commit_hash,
                    commit_date=date,
                    author=author,
                ))

    return results


def get_current_secret_hashes(repo_dir: str) -> set[str]:
    """Hashes of every secret found in the files as they exist right now (checked-out HEAD)."""
    hashes: set[str] = set()
    for rel_path in run_git(["ls-files", "-z"], cwd=repo_dir).split("\0"):
        if not rel_path:
            continue
        full_path = os.path.join(repo_dir, rel_path)
        try:
            if os.path.getsize(full_path) > 1_000_000:  # skip huge/binary blobs
                continue
            with open(full_path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    for finding in scan_line(line.rstrip("\n")):
                        hashes.add(finding.secret_hash)
        except OSError:  # submodule folders, broken symlinks, ...
            continue
    return hashes