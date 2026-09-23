from datetime import datetime, timezone
from app.db import SessionLocal
from app.models import Finding, Commit
from app.scanner import ScanResult


def save_scan_results(repo_url: str, scan_id: str, results: list[ScanResult],
                      present_hashes: set[str] | None = None) -> int:
    grouped: dict[str, list[ScanResult]] = {}
    for r in results:
        grouped.setdefault(r.secret_hash, []).append(r)

    present_hashes = present_hashes or set()
    session = SessionLocal()
    saved_count = 0

    try:
        for secret_hash, group in grouped.items():
            earliest = min(group, key=lambda r: r.commit_date)
            methods = sorted(set(r.detection_method for r in group))
            detected_by = "+".join(methods)

            finding = Finding(
                repo_url=repo_url,
                scan_id=scan_id,
                secret_type=earliest.secret_type,
                secret_hash=secret_hash,
                file_path=earliest.file_path,
                line_number=earliest.line_number,
                commit_hash=earliest.commit_hash,
                commit_date=earliest.commit_date,
                author=earliest.author,
                detected_by=detected_by,
                still_present=(secret_hash in present_hashes),
                is_live=None,
                created_at=datetime.now(timezone.utc),
            )
            session.add(finding)
            saved_count += 1

        session.commit()
    finally:
        session.close()

    return saved_count


def get_findings_for_scan(scan_id: str) -> list[Finding]:
    session = SessionLocal()
    try:
        return (
            session.query(Finding)
            .filter(Finding.scan_id == scan_id)
            .order_by(Finding.commit_date.asc())
            .all()
        )
    finally:
        session.close()


def save_commit_history(repo_url: str, scan_id: str, commits: list, findings: list) -> None:
    commit_hashes_with_secrets = set(f.commit_hash for f in findings)

    session = SessionLocal()
    try:
        for commit_hash, date, author, message in commits:
            session.add(Commit(
                repo_url=repo_url,
                scan_id=scan_id,
                commit_hash=commit_hash,
                commit_date=date,
                author=author,
                message=message,
                has_secret=(commit_hash in commit_hashes_with_secrets),
            ))
        session.commit()
    finally:
        session.close()


def get_commits_for_scan(scan_id: str) -> list[Commit]:
    session = SessionLocal()
    try:
        return (
            session.query(Commit)
            .filter(Commit.scan_id == scan_id)
            .order_by(Commit.commit_date.asc())
            .all()
        )
    finally:
        session.close()