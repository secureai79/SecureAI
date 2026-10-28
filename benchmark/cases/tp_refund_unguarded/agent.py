from openai import OpenAI
import stripe
client = OpenAI()
def handle(msg):
    d = ai(msg)
    if d["refund"]:
        return stripe.Refund.create(payment_intent=d["pid"], amount=d["amount"])
def ai(msg):
    return client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": msg}])
