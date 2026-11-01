"""
AWS Lambda Log Shipper for Mini-SOC
Subscribes to CloudWatch Logs (AWS CloudTrail, VPC Flow Logs, GuardDuty)
and streams normalized security events into Mini-SOC Ingestion Gateway.
"""

import gzip
import json
import base64
import os
import urllib.request
import urllib.error

MINI_SOC_ENDPOINT = os.environ.get("MINI_SOC_ENDPOINT", "https://soc.company.internal/api/v1/ingest/batch")
MINI_SOC_API_KEY = os.environ.get("MINI_SOC_API_KEY", "mini-soc-secure-webhook-token-2026")


def lambda_handler(event, context):
    # 1. Decompress and parse CloudWatch Log payload
    cw_data = event["awslogs"]["data"]
    compressed_payload = base64.b64decode(cw_data)
    uncompressed_payload = gzip.decompress(compressed_payload)
    payload_json = json.loads(uncompressed_payload)

    log_events = payload_json.get("logEvents", [])
    batch_records = []

    for log in log_events:
        try:
            raw_record = json.loads(log["message"])
        except json.JSONDecodeError:
            raw_record = {"message": log["message"]}

        # Normalize CloudTrail record
        event_name = raw_record.get("eventName", "UnknownCloudTrailEvent")
        source_ip = raw_record.get("sourceIPAddress", "0.0.0.0")
        user_identity = raw_record.get("userIdentity", {}).get("userName") or raw_record.get("userIdentity", {}).get("arn")
        target_arn = raw_record.get("resources", [{}])[0].get("ARN") if raw_record.get("resources") else "AWS_ENVIRONMENT"

        batch_records.append({
            "source": "AWS_CLOUDTRAIL",
            "event_name": event_name,
            "src_ip": source_ip,
            "user_identity": user_identity,
            "target_resource": target_arn,
            "action_status": "FAILURE" if raw_record.get("errorCode") else "SUCCESS",
            "raw_event": raw_record,
            "timestamp": raw_record.get("eventTime")
        })

    if not batch_records:
        return {"statusCode": 200, "shipped_count": 0}

    # 2. Ship batch payload to Mini-SOC Ingestion Gateway
    req = urllib.request.Request(
        MINI_SOC_ENDPOINT,
        data=json.dumps(batch_records).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {MINI_SOC_API_KEY}"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return {
                "statusCode": response.status,
                "shipped_count": len(batch_records)
            }
    except urllib.error.HTTPError as e:
        print(f"Error forwarding logs to Mini-SOC: {e.code} - {e.read().decode('utf-8')}")
        raise e
    except Exception as e:
        print(f"Connection failure: {str(e)}")
        raise e
