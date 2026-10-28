import subprocess
from . import models
def save(db):
    agent = models.Agent(name="x")
    db.add(agent)
    subprocess.run(["git", "status"])
