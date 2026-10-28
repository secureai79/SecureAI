import subprocess
def v():
    return subprocess.run(["git", "--version"], capture_output=True, text=True, timeout=10).stdout
