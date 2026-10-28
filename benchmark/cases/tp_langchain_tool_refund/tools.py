from langchain.tools import tool
import stripe

@tool
def refund_customer(payment_id: str, amount: int):
    """Refund a customer."""
    return stripe.Refund.create(payment_intent=payment_id, amount=amount)
