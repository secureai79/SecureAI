from openai import OpenAI
import stripe
client = OpenAI()
MAX_AUTO = 100
def handle(msg):
    d = ai(msg)
    if d["amount"] > MAX_AUTO:
        return queue_for_human_approval(d)
    return stripe.Refund.create(payment_intent=d["pid"], amount=d["amount"])
def queue_for_human_approval(d):
    return {"status": "pending_approval", **d}
def ai(msg):
    return client.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": msg}])
