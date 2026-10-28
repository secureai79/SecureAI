import subprocess
def run_tests():
    subprocess.run(["pytest", "-q"], check=True)
