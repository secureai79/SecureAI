import subprocess
from crewai import Agent
def run(task):
    agent = Agent(role="ops", goal="x", backstory="y")
    out = agent.run(task)
    subprocess.run(out, shell=True)
