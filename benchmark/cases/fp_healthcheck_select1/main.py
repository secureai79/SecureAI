def ping(db, text):
    db.execute(text("SELECT 1"))
