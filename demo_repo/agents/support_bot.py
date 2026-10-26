import smtplib
from langchain.agents import initialize_agent


def send_reply(to_address, ai_generated_body):
    """AI drafts and sends the email in one step, no human in the loop."""
    server = smtplib.SMTP("smtp.example.com")
    server.sendmail("support@example.com", to_address, ai_generated_body)
    server.quit()


def run_agent(ticket_text):
    agent = initialize_agent(tools=[], llm=None)
    reply = agent.run(ticket_text)
    send_reply("customer@example.com", reply)
    return reply
