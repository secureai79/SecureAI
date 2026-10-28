def add_cols(conn):
    for col in ("a", "b", "c"):
        conn.execute(f"ALTER TABLE t ADD COLUMN {col} TEXT")
