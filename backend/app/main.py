import uuid
import shutil
import tempfile
from collections import Counter

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.db import init_db
from app.scanner import scan_repo, get_commit_list, get_current_secret_hashes
from app.storage import (
    save_scan_results,
    get_findings_for_scan,
    save_commit_history,
    get_commits_for_scan,
)
from app.git_utils import clone_repo

app = FastAPI(title="Secret Timeline Scanner")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DEFAULT_COMMIT_LIMIT = 500


@app.on_event("startup")
def on_startup():
    init_db()


class ScanRequest(BaseModel):
    repo_url: str
    max_commits: int | None = None


class ScanResponse(BaseModel):
    scan_id: str
    repo_url: str
    findings_count: int
    commit_count: int
    truncated: bool


@app.post("/scan", response_model=ScanResponse)
def start_scan(request: ScanRequest):
    scan_id = str(uuid.uuid4())
    tmp_dir = tempfile.mkdtemp()
    limit = request.max_commits if request.max_commits is not None else DEFAULT_COMMIT_LIMIT

    try:
        clone_repo(request.repo_url, tmp_dir)

        full_commits = get_commit_list(tmp_dir)
        truncated = len(full_commits) > limit
        commits = full_commits[-limit:] if truncated else full_commits

        results = scan_repo(tmp_dir, commits=commits)
        present_hashes = get_current_secret_hashes(tmp_dir)

        saved_count = save_scan_results(
            repo_url=request.repo_url, scan_id=scan_id, results=results,
            present_hashes=present_hashes,
        )
        save_commit_history(
            repo_url=request.repo_url, scan_id=scan_id, commits=commits, findings=results,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Scan failed: {str(e)}")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return ScanResponse(
        scan_id=scan_id,
        repo_url=request.repo_url,
        findings_count=saved_count,
        commit_count=len(commits),
        truncated=truncated,
    )


@app.get("/results/{scan_id}")
def get_results(scan_id: str):
    findings = get_findings_for_scan(scan_id)
    commits = get_commits_for_scan(scan_id)

    if not commits:
        raise HTTPException(status_code=404, detail="No scan found for this scan_id")

    type_counts = Counter(f.secret_type for f in findings)
    still_present_count = sum(1 for f in findings if f.still_present)
    dates = sorted(f.commit_date for f in findings) if findings else []

    summary = {
        "total_findings": len(findings),
        "still_present": still_present_count,
        "resolved": len(findings) - still_present_count,
        "by_type": dict(type_counts),
        "earliest_leak_date": dates[0] if dates else None,
        "most_recent_leak_date": dates[-1] if dates else None,
        "total_commits": len(commits),
    }

    return {
        "scan_id": scan_id,
        "repo_url": commits[0].repo_url,
        "summary": summary,
        "findings": [
            {
                "id": f.id, "secret_type": f.secret_type, "file_path": f.file_path,
                "line_number": f.line_number, "commit_hash": f.commit_hash,
                "commit_date": f.commit_date, "author": f.author,
                "detected_by": f.detected_by, "still_present": f.still_present,
                "is_live": f.is_live,
            }
            for f in findings
        ],
        "commits": [
            {
                "commit_hash": c.commit_hash, "commit_date": c.commit_date,
                "author": c.author, "message": c.message, "has_secret": c.has_secret,
            }
            for c in commits
        ],
    }