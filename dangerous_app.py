import os
import ast

# 1. Environment Variables (No hardcoded secrets)
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")

# 2. Parameterized SQL query
def get_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# 3. ast.literal_eval safe parsing
def run_code(code):
    try:
        return ast.literal_eval(code)
    except Exception:
        return 0
