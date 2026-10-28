def get(cur, uid):
    cur.execute("SELECT * FROM users WHERE id = %s", (uid,))
