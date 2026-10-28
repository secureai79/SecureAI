from flask import request
import sqlite3
def handler():
    uid = request.args["id"]
    cur = sqlite3.connect("a.db").cursor()
    cur.execute("SELECT * FROM users WHERE id=" + uid)
