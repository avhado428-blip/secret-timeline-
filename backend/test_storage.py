import uuid
from app.db import init_db
from app.scanner import scan_repo
from app.storage import save_scan_results, get_findings_for_scan

# Re-use the same throwaway repo trick from test_scanner.py
import subprocess, tempfile, os

tmp_dir = tempfile.mkdtemp()
subprocess.run(["git", "init"], cwd=tmp_dir, check=True)
subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_dir, check=True)
subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_dir, check=True)

with open(os.path.join(tmp_dir, "config.py"), "w") as f:
    f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True)
subprocess.run(["git", "commit", "-m", "add config"], cwd=tmp_dir, check=True)

print("Initializing database...")
init_db()

print("Scanning repo...")
results = scan_repo(tmp_dir)
print(f"Raw results found: {len(results)}")

scan_id = str(uuid.uuid4())
saved = save_scan_results(repo_url="local-test-repo", scan_id=scan_id, results=results)
print(f"Unique findings saved after dedup: {saved}")

print("\nFetching back from DB:")
findings = get_findings_for_scan(scan_id)
for f in findings:
    print(f"  [{f.secret_type}] {f.file_path}:{f.line_number} detected_by={f.detected_by} commit={f.commit_hash[:8]}")