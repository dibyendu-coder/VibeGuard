import logging
import pickle
import subprocess
from fastapi import FastAPI, Request

app = FastAPI()

# Debug mode enabled
DEBUG = True

# Hardcoded API key
API_KEY = "sk-fakeKey1234567890123456789012"

@app.post("/api/eval")
async def execute_calc(request: Request):
    data = await request.json()
    code = data.get("expression")
    # Dynamic eval vulnerability
    result = eval(code)
    return {"result": result}

@app.post("/api/run")
def run_command(cmd: str):
    # Unsafe subprocess with shell=True
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    stdout, _ = proc.communicate()
    return {"output": stdout.decode()}

@app.get("/api/account/{account_id}")
def get_account(account_id: str):
    # Raw SQL formatting
    cursor.execute(f"SELECT * FROM accounts WHERE id = '{account_id}'")
    return {"status": "ok"}

@app.post("/api/restore")
def restore_session(raw_bytes: bytes):
    # Dangerous pickle deserialization
    session = pickle.loads(raw_bytes)
    return {"session": session}

@app.post("/api/login")
def login(token: str):
    # Sensitive token logging
    logging.info(f"User authToken: {token}")
    return {"status": "logged_in"}
