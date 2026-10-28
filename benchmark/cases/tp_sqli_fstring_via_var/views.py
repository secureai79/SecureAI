from flask import request
def view(c):
    term = request.args.get("q")
    sql = f"SELECT * FROM items WHERE title LIKE '%{term}%'"
    c.execute(sql)
