# from flask import Flask, request
# import sqlite3
# import subprocess
# import os
# # demo: trigger pipeline

# app = Flask(__name__)

# # ❌ VULNERABILIDADE 1: SQL Injection
# @app.route('/user')
# def get_user():
#     user_id = request.args.get('id')
#     conn = sqlite3.connect('users.db')
#     # INSECURE: concatenação direta de input do usuário
#     query = "SELECT * FROM users WHERE id = " + user_id
#     result = conn.execute(query).fetchall()
#     return str(result)

# # ❌ VULNERABILIDADE 2: Command Injection
# @app.route('/ping')
# def ping():
#     host = request.args.get('host')
#     # INSECURE: execução direta de comando com input do usuário
#     output = subprocess.check_output(f"ping -c 1 {host}", shell=True)
#     return output

# # ❌ VULNERABILIDADE 3: Hardcoded Secret
# SECRET_KEY = "minha-senha-super-secreta-123"
# DB_PASSWORD = "admin123"

# # ✅ CORRETO: SQL com parâmetros
# @app.route('/user/safe')
# def get_user_safe():
#     user_id = request.args.get('id')
#     conn = sqlite3.connect('users.db')
#     result = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
#     return str(result)

# if __name__ == '__main__':
#     app.run(debug=True)

from flask import Flask, request
import sqlite3
import subprocess
import os

app = Flask(__name__)

# ✅ Fix 1: SQL com parâmetros (sem SQL Injection)
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    result = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
    return str(result)

# ✅ Fix 2: Sem shell=True (sem Command Injection)
@app.route('/ping')
def ping():
    host = request.args.get('host')
    output = subprocess.check_output(["ping", "-c", "1", host])
    return output

# ✅ Fix 3: Secrets via variáveis de ambiente
SECRET_KEY = os.environ.get("SECRET_KEY")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

@app.route('/user/safe')
def get_user_safe():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    result = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
    return str(result)

# ✅ Fix 4: Sem Path Traversal — valida o nome do arquivo
ALLOWED_FILES = {"report.txt", "status.txt"}

@app.route('/file')
def read_file():
    filename = request.args.get('name')
    if filename not in ALLOWED_FILES:
        return "File not allowed", 403
    filepath = os.path.join("/var/data", filename)
    with open(filepath, 'r') as f:
        return f.read()

if __name__ == '__main__':
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)