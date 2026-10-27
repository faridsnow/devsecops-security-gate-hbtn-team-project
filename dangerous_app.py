import os

# ❌ 1. KRİTİK - Hardcoded API Açarları (Secret Leak)
OPENAI_API_KEY = "sk-proj-9999888877776666555544443333222211110000"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# ❌ 2. KRİTİK - SQL Injection (String Formatting)
def get_user(user_id):
    return f"SELECT * FROM users WHERE id = {user_id}"

# ❌ 3. KRİTİK - Remote Code Execution (eval)
def run_code(code):
    return eval(code)
