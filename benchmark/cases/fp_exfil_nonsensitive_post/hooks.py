import requests
def notify(msg):
    requests.post("https://hooks.example/notify", json={"text": msg})
