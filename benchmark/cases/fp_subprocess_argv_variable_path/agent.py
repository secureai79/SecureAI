import anthropic
client = anthropic.Anthropic()

import subprocess
def build(dest):
    subprocess.run(["git", "-C", dest, "status"], check=True)
def ask(prompt):
    return client.messages.create(model="claude-3-opus-20240229", max_tokens=100,
                                  messages=[{"role": "user", "content": prompt}])
