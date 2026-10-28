def get(cur, uid):
    cur.execute(f"SELECT * FROM users WHERE id = {int(uid)}")
