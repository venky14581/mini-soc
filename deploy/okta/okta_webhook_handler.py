"""
Okta Event Hook Receiver for Mini-SOC
Handles Okta one-time verification handshake and streams identity telemetry into Mini-SOC.
"""

from fastapi import FastAPI, Header, HTTPException, Request, Response
import urllib.request
import json
import os

app = FastAPI(title="Okta Event Hook Forwarder for Mini-SOC")

MINI_SOC_ENDPOINT = os.getenv("MINI_SOC_ENDPOINT", "http://mini-soc-siem:8000/api/v1/ingest")
MINI_SOC_API_KEY = os.getenv("MINI_SOC_API_KEY", "mini-soc-secure-webhook-token-2026")


@app.get("/okta/events")
def okta_verification_handshake(x_okta_verification_challenge: str = Header(None)):
    """
    Handles Okta Event Hook verification challenge (GET request on setup).
    """
    if not x_okta_verification_challenge:
        raise HTTPException(status_code=400, detail="Missing verification challenge")
    return {"verification": x_okta_verification_challenge}


@app.post("/okta/events")
async def receive_okta_events(request: Request):
    """
    Receives live Okta System Log events and forwards them to Mini-SOC.
    """
    body = await request.json()
    events = body.get("data", {}).get("events", [])

    for evt in events:
        event_type = evt.get("eventType", "okta.unknown")
        actor_user = evt.get("actor", {}).get("alternateId", "unknown_user")
        client_ip = evt.get("client", {}).get("ipAddress", "0.0.0.0")
        outcome = evt.get("outcome", {}).get("result", "UNKNOWN")

        normalized = {
            "source": "OKTA_IDENTITY",
            "event_name": event_type,
            "src_ip": client_ip,
            "user_identity": actor_user,
            "target_resource": "Okta Identity Cloud",
            "action_status": "SUCCESS" if outcome == "SUCCESS" else "FAILURE",
            "raw_event": evt,
            "timestamp": evt.get("published")
        }

        # Ship to Mini-SOC
        req = urllib.request.Request(
            MINI_SOC_ENDPOINT,
            data=json.dumps(normalized).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {MINI_SOC_API_KEY}"
            }
        )
        try:
            urllib.request.urlopen(req, timeout=3)
        except Exception as e:
            print(f"Failed shipping Okta event: {e}")

    return Response(status_code=200)
