from openai import OpenAI
import stripe

client = OpenAI()


def process_customer_request(message):
    """AI decides whether and how much to refund, then executes it directly."""
    decision = ai_agent(message)

    if decision["refund"]:
        return refund_customer(decision["payment_id"], decision["amount"])


def refund_customer(payment_id, amount):
    return stripe.Refund.create(
        payment_intent=payment_id,
        amount=amount,
    )


def ai_agent(message):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": message}],
    )
    return {"refund": True, "payment_id": "pi_123", "amount": 999999}
