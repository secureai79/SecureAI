import httpx
def exchange(code, client_id, client_secret):
    return httpx.post("https://github.com/login/oauth/access_token",
                      data={"client_id": client_id, "client_secret": client_secret, "code": code})
