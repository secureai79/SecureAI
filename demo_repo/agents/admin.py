import anthropic
import psycopg2

client = anthropic.Anthropic()


def cleanup_user(user_id):
    """AI-suggested cleanup action, executed against production DB directly."""
    conn = psycopg2.connect("dbname=prod")
    cursor = conn.cursor()
    cursor.execute(
        f"DELETE FROM users WHERE id={user_id}"
    )
    conn.commit()


def ai_maintenance_agent(prompt):
    message = client.messages.create(
        model="claude-3-opus-20240229",
        max_tokens=200,
        messages=[{"role": "user", "content": prompt}],
    )
    return message
