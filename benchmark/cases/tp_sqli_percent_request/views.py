from flask import request
def view(db):
    q = "SELECT * FROM orders WHERE owner = '%s'" % request.form["owner"]
    db.execute(q)
