def migrate(conn, text, cols):
    missing = {"consequence", "impact_level"} - cols
    for name in sorted(missing):
        conn.execute(text(f"ALTER TABLE findings ADD COLUMN {name} VARCHAR"))
