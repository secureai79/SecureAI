import anthropic
client = anthropic.Anthropic()

import subprocess
def go(prompt):
    out = client.messages.create(model="claude-3-opus-20240229", max_tokens=100,
                                 messages=[{"role": "user", "content": prompt}])
    subprocess.run(["sh", "-c", out.content[0].text])
