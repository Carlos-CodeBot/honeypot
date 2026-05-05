import argparse
import hmac
import json
import re
import time
from datetime import datetime
from hashlib import sha256
from pathlib import Path
from urllib import request as urllib_request

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>[^\s]+) [^"]+" (?P<status>\d{3}) (?P<size>\S+) "(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_line(line: str):
    m = LOG_PATTERN.search(line)
    if not m:
        return None
    gd = m.groupdict()
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": gd["ip"],
        "method": gd["method"],
        "path": gd["path"],
        "user_agent": gd["ua"],
        "query_string": "",
        "body": "",
        "headers": "",
        "notes": "agent_nginx_log",
        "is_attack": 0,
        "attack_type": "benign",
        "severity": "low",
        "confidence": 0.0,
    }


def sign(secret: str, ts: str, payload: str) -> str:
    msg = f"{ts}.{payload}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, sha256).hexdigest()


def send_event(url: str, token: str, hmac_secret: str, event: dict):
    body = json.dumps(event).encode("utf-8")
    ts = str(int(time.time()))
    sig = sign(hmac_secret, ts, body.decode("utf-8")) if hmac_secret else ""
    req = urllib_request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Ingest-Token": token,
            "X-Ingest-Timestamp": ts,
            "X-Ingest-Signature": sig,
        },
    )
    with urllib_request.urlopen(req, timeout=3):
        return


def follow(logfile: Path, url: str, token: str, hmac_secret: str):
    with logfile.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.25)
                continue
            event = parse_line(line.strip())
            if not event:
                continue
            try:
                send_event(url, token, hmac_secret, event)
            except Exception:
                continue


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Nginx log forwarder agent for honeypot dashboard server")
    parser.add_argument("--log", required=True, help="Path to nginx access.log")
    parser.add_argument("--url", required=True, help="Dashboard ingest URL, e.g. https://dash/api/ingest-event")
    parser.add_argument("--token", required=True, help="Ingest token")
    parser.add_argument("--hmac-secret", default="", help="Optional HMAC secret")
    args = parser.parse_args()
    follow(Path(args.log), args.url, args.token, args.hmac_secret)
