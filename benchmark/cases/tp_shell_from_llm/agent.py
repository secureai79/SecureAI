import anthropic
client = anthropic.Anthropic()

import os
def go(prompt):
    out = client.messages.create(model="claude-3-opus-20240229", max_tokens=100,
                                 messages=[{"role": "user", "content": prompt}])
    os.system(out.content[0].text)
