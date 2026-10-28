from openai import OpenAI
import stripe
client = OpenAI()
def r(m):
    d = client.chat.completions.create(model="gpt-4", messages=[{"role":"user","content":m}])
    return stripe.Refund.create(payment_intent="pi_1", amount=99999)
