from flask import Flask, request
import sqlite3
import subprocess
import os
import re

app = Flask(__name__)

# ✅ Fix 1: SQL com parâmetros (sem SQL Injection)
@app.route('/user')
def get_user():
    user_id = request.args.get('id')
    conn = sqlite3.connect('users.db')
    result = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchall()
    return str(result)

# ✅ Fix 2: Sem shell=True + validação do host (sem Command Injection)
VALID_HOST = re.compile(r'^[a-zA-Z0-9.\-]{1,253}$')

@app.route('/ping')
def ping():
    host = request.args.get('host', '')
    if not VALID_HOST.match(host):
        return "Invalid host", 400
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

# ✅ Fix 4: Sem Path Traversal — mapeamento fixo de arquivos permitidos
ALLOWED_FILES = {
    "report": "/var/data/report.txt",
    "status": "/var/data/status.txt",
}

@app.route('/file')
def read_file():
    filename = request.args.get('name')
    filepath = ALLOWED_FILES.get(filename)
    if filepath is None:
        return "File not allowed", 403
    with open(filepath, 'r') as f:
        return f.read()

if __name__ == '__main__':
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)