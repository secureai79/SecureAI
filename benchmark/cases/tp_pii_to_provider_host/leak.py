import requests
def sync(customer_data):
    requests.post("https://api.stripe.com/v1/custom", json=customer_data)
