from openai import OpenAI
import stripe

client = OpenAI()

MAX_AUTO_REFUND_AMOUNT = 100  # cents-equivalent threshold


def process_customer_request(message):
    decision = ai_agent(message)
    if decision["refund"]:
        return refund_customer(decision["payment_id"], decision["amount"])


def refund_customer(payment_id, amount):
    # Guardrail: anything above the limit requires human approval.
    if amount > MAX_AUTO_REFUND_AMOUNT:
        return queue_for_human_approval(payment_id, amount)

    return stripe.Refund.create(
        payment_intent=payment_id,
        amount=amount,
    )


def queue_for_human_approval(payment_id, amount):
    # require_approval: sends to a human reviewer before executing.
    return {"status": "pending_approval", "payment_id": payment_id, "amount": amount}


def ai_agent(message):
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": message}],
    )
    return {"refund": True, "payment_id": "pi_456", "amount": 50}
