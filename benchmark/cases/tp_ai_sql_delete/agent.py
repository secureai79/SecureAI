import anthropic
client = anthropic.Anthropic()

import psycopg2

def cleanup(user_id):
    conn = psycopg2.connect("dbname=prod")
    cur = conn.cursor()
    cur.execute(f"DELETE FROM users WHERE id={user_id}")
    conn.commit()

def run(prompt):
    return client.messages.create(model="claude-3-opus-20240229", max_tokens=100,
                                  messages=[{"role": "user", "content": prompt}])
