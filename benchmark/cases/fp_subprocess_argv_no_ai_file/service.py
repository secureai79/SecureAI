import subprocess
def clone(dest):
    subprocess.run(["git", "clone", "--depth", "1", "x", dest], check=True)
    raise subprocess.CalledProcessError(1, "git")
