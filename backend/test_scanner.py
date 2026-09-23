import subprocess
import tempfile
import os

from app.scanner import scan_repo

# Build a tiny throwaway git repo with a fake leaked secret in one commit
tmp_dir = tempfile.mkdtemp()
subprocess.run(["git", "init"], cwd=tmp_dir, check=True)
subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=tmp_dir, check=True)
subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_dir, check=True)

# Commit 1: normal file
with open(os.path.join(tmp_dir, "app.py"), "w") as f:
    f.write("def hello():\n    print('hello world')\n")
subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True)
subprocess.run(["git", "commit", "-m", "initial commit"], cwd=tmp_dir, check=True)

# Commit 2: accidentally add an AWS key
with open(os.path.join(tmp_dir, "config.py"), "w") as f:
    f.write('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True)
subprocess.run(["git", "commit", "-m", "add config"], cwd=tmp_dir, check=True)

# Commit 3: remove the key (but it's still in history!)
with open(os.path.join(tmp_dir, "config.py"), "w") as f:
    f.write('AWS_KEY = os.environ["AWS_KEY"]\n')
subprocess.run(["git", "add", "."], cwd=tmp_dir, check=True)
subprocess.run(["git", "commit", "-m", "remove hardcoded key"], cwd=tmp_dir, check=True)

print(f"Test repo created at: {tmp_dir}")
print("Scanning...\n")

results = scan_repo(tmp_dir)
for r in results:
    print(f"[{r.secret_type}] {r.file_path}:{r.line_number} in commit {r.commit_hash[:8]} ({r.commit_date})")