from psycopg2 import sql
def add(cur, table):
    cur.execute(sql.SQL("DELETE FROM {}").format(sql.Identifier(table)))
