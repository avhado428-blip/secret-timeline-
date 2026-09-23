import subprocess


def clone_repo(repo_url: str, dest_dir: str) -> None:
    result = subprocess.run(
        ["git", "clone", repo_url, dest_dir],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr}")