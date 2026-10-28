import smtplib
from langchain.agents import initialize_agent
def send_reply(to, body):
    s = smtplib.SMTP("smtp.example.com"); s.sendmail("a@b.c", to, body); s.quit()
def run(ticket):
    agent = initialize_agent(tools=[], llm=None)
    send_reply("x@y.z", agent.run(ticket))
