import os
import ast

# 1. Təhlükəsiz - Mühit dəyişənləri
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")

# 2. Təhlükəsiz - Parametrləşdirilmiş SQL
def get_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# 3. Təhlükəsiz - ast.literal_eval
def run_code(code):
    try:
        return ast.literal_eval(code)
    except Exception:
        return 0
