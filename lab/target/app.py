"""
Mini-SOC Lab Vulnerable Target Application
Simulates a realistic corporate web and authentication service for testing detection rules.
Runs safely within the isolated lab environment.
"""

import os
import logging
from typing import Optional
from fastapi import FastAPI, Query, HTTPException, Request, Form
from fastapi.responses import JSONResponse, PlainTextResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [LAB-TARGET] %(message)s")
logger = logging.getLogger("lab.target")

app = FastAPI(
    title="Mini-SOC Lab Vulnerable Target Service",
    description="Deliberately vulnerable test application for IDS/SIEM detection validation",
    version="1.0.0"
)

# Simulated in-memory database
USERS_DB = {
    1: {"id": 1, "username": "admin", "role": "administrator", "email": "admin@lab.corp"},
    2: {"id": 2, "username": "jdoe", "role": "analyst", "email": "jdoe@lab.corp"}
}


@app.get("/")
def home(request: Request):
    user_agent = request.headers.get("user-agent", "Unknown")
    logger.info(f"Root hit by {request.client.host} with User-Agent: {user_agent}")
    return {
        "service": "Mini-SOC Corporate Portal",
        "status": "online",
        "client_ip": request.client.host,
        "security_monitoring": "Active (Suricata Network IDS Enforced)"
    }


@app.post("/login")
def simulated_login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    """
    Vulnerable to credential brute force (T1110).
    Logs all attempts so IDS and log collectors capture failed login volume.
    """
    client_ip = request.client.host
    if username == "admin" and password == "SecretMiniSoc2026!":
        logger.info(f"Successful authentication for {username} from {client_ip}")
        return {"status": "authenticated", "token": "session-token-admin-lab"}

    logger.warning(f"FAILED LOGIN attempt for user '{username}' from {client_ip}")
    return JSONResponse(
        status_code=401,
        content={"status": "error", "message": "Invalid credentials provided"}
    )


@app.get("/api/users")
def get_user_query(request: Request, id: str = Query(...)):
    """
    Simulates SQL Injection Vulnerability (T1190).
    """
    client_ip = request.client.host
    logger.info(f"User query '{id}' from {client_ip}")

    # Detect blatant SQLi payloads for simulation response
    upper_query = id.upper()
    if "UNION" in upper_query and "SELECT" in upper_query:
        return {
            "status": "exploited",
            "vulnerability": "SQL Injection (T1190)",
            "dumped_records": [
                {"id": 1, "hash": "$2a$12$e8Y...admin_pw_hash"},
                {"id": 2, "hash": "$2a$12$k9L...backup_pw_hash"}
            ]
        }
    elif "' OR '1'='1" in id or "1=1" in id:
        return {"status": "success", "results": list(USERS_DB.values())}

    try:
        user_id = int(id)
        if user_id in USERS_DB:
            return {"status": "success", "user": USERS_DB[user_id]}
        return JSONResponse(status_code=404, content={"message": "User not found"})
    except ValueError:
        return JSONResponse(status_code=400, content={"message": "Invalid user ID format"})


@app.get("/download")
def download_file(request: Request, file: str = Query(...)):
    """
    Simulates Directory Traversal / Arbitrary File Read (T1083 / T1190).
    """
    client_ip = request.client.host
    logger.warning(f"File download requested: '{file}' from {client_ip}")

    if ".." in file or "etc/passwd" in file.lower() or "win.ini" in file.lower():
        mock_passwd = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "mini-soc:x:1000:1000:Lab User:/home/mini-soc:/bin/bash\n"
        )
        return PlainTextResponse(mock_passwd)

    return PlainTextResponse(f"Safe lab file content for: {file}")


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    uvicorn.run("lab.target.app:app", host="0.0.0.0", port=port, reload=False)
