def find(cur, name):
    cur.execute("SELECT * FROM users WHERE name='{}'".format(name))
