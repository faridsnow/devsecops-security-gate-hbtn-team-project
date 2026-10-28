import os

# 🚨 1. SIZMIŞ GİZLİ AÇARLAR (Secret Leaks)
OPENAI_API_KEY = "sk-proj-9999888877776666555544443333222211110000"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# 🚨 2. SQL INJECTION BOŞLUĞU
def get_user(user_id):
    return f"SELECT * FROM users WHERE id = {user_id}"

# 🚨 3. REMOTE CODE EXECUTION (eval RCE)
def run_code(code):
    return eval(code)
