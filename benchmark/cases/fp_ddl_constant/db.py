def migrate(conn, text):
    conn.execute(text("ALTER TABLE users ADD COLUMN locked_until TIMESTAMP"))
