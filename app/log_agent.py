import os
import re
import json
import time
import hmac
import hashlib
import urllib.request
from datetime import datetime, timezone


LOG_AGENT_PATH = os.getenv("LOG_AGENT_PATH", "/logs/access.log")
LOG_AGENT_STATE_FILE = os.getenv("LOG_AGENT_STATE_FILE", "/data/log_agent.state")

FORWARD_LOG_URL = os.getenv("FORWARD_LOG_URL", "")
FORWARD_LOG_TOKEN = os.getenv("FORWARD_LOG_TOKEN", "")
INGEST_HMAC_SECRET = os.getenv("INGEST_HMAC_SECRET", "")

SEND_ONLY_ATTACKS = os.getenv("LOG_AGENT_SEND_ONLY_ATTACKS", "0").strip().lower() in (
    "1",
    "true",
    "yes",
    "on",
)

POLL_INTERVAL = float(os.getenv("LOG_AGENT_POLL_INTERVAL", "2"))


# Formato combined típico de Nginx/Apache:
# 1.2.3.4 - - [05/May/2026:21:03:17 +0000] "GET /wp-admin HTTP/1.1" 404 123 "-" "Mozilla"
COMBINED_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)


def classify_from_log(path, user_agent, referer, status):
    text = f"{path} {user_agent} {referer}".lower()

    checks = [
        (
            "sql_injection",
            [
                "' or '1'='1",
                " or 1=1",
                "union select",
                "sleep(",
                "benchmark(",
                "%27",
                "%22",
                "information_schema",
            ],
            "high",
        ),
        (
            "path_traversal",
            [
                "../",
                "..%2f",
                "%2e%2e",
                "/etc/passwd",
                "windows/win.ini",
                "boot.ini",
            ],
            "high",
        ),
        (
            "rce",
            [
                "cmd=",
                "exec=",
                "command=",
                "whoami",
                "id;",
                "bash -c",
                "powershell",
                "wget ",
                "curl ",
            ],
            "critical",
        ),
        (
            "scanner",
            [
                "/wp-admin",
                "/wp-login.php",
                "/xmlrpc.php",
                "/.env",
                "/phpmyadmin",
                "/vendor/phpunit",
                "/server-status",
                "/actuator",
                "/cgi-bin/",
                "/owa/",
            ],
            "medium",
        ),
        (
            "xss",
            [
                "<script",
                "%3cscript",
                "onerror=",
                "onload=",
                "javascript:",
            ],
            "medium",
        ),
        (
            "lfi",
            [
                "file=",
                "page=",
                "include=",
                "php://",
                "expect://",
                "data://",
            ],
            "high",
        ),
    ]

    for attack_type, patterns, severity in checks:
        if any(pattern in text for pattern in patterns):
            return {
                "is_attack": 1,
                "attack_type": attack_type,
                "severity": severity,
                "confidence": 0.95,
                "notes": f"detected_from_access_log status={status}",
            }

    return {
        "is_attack": 0,
        "attack_type": "benign",
        "severity": "low",
        "confidence": 0.30,
        "notes": f"access_log_event status={status}",
    }


def parse_combined_line(line):
    match = COMBINED_RE.match(line)
    if not match:
        return None

    data = match.groupdict()

    path = data.get("path", "")
    method = data.get("method", "")
    user_agent = data.get("user_agent", "")
    referer = data.get("referer", "")
    status = data.get("status", "")

    classification = classify_from_log(path, user_agent, referer, status)

    query_string = ""
    clean_path = path

    if "?" in path:
        clean_path, query_string = path.split("?", 1)

    return {
        "timestamp": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "ip": data.get("ip", ""),
        "method": method,
        "path": clean_path,
        "user_agent": user_agent,
        "query_string": query_string,
        "body": "",
        "headers": f"referer={referer}; status={status}; size={data.get('size')}; protocol={data.get('protocol')}",
        "notes": classification["notes"],
        "is_attack": classification["is_attack"],
        "attack_type": classification["attack_type"],
        "severity": classification["severity"],
        "confidence": classification["confidence"],
    }


def sign_body(timestamp, body_bytes):
    if not INGEST_HMAC_SECRET:
        return None

    msg = timestamp.encode("utf-8") + b"." + body_bytes

    return hmac.new(
        INGEST_HMAC_SECRET.encode("utf-8"),
        msg,
        hashlib.sha256,
    ).hexdigest()


def forward_event(event_payload):
    if not FORWARD_LOG_URL:
        print("[!] FORWARD_LOG_URL vacío; no se envía evento", flush=True)
        return

    if SEND_ONLY_ATTACKS and int(event_payload.get("is_attack", 0)) != 1:
        return

    body = json.dumps(
        event_payload,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    ts = str(int(time.time()))

    headers = {
        "Content-Type": "application/json",
        "X-Ingest-Token": FORWARD_LOG_TOKEN,
        "X-Ingest-Timestamp": ts,
    }

    signature = sign_body(ts, body)
    if signature:
        headers["X-Ingest-Signature"] = signature

    req = urllib.request.Request(
        FORWARD_LOG_URL,
        data=body,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            response_body = response.read().decode("utf-8", errors="ignore")
            print(
                f"[+] enviado status={response.status} path={event_payload.get('path')} body={response_body[:200]}",
                flush=True,
            )
    except Exception as exc:
        print(
            f"[!] error enviando evento path={event_payload.get('path')}: {exc!r}",
            flush=True,
        )


def read_state():
    try:
        with open(LOG_AGENT_STATE_FILE, "r", encoding="utf-8") as file_obj:
            return int(file_obj.read().strip() or "0")
    except Exception:
        return 0


def write_state(position):
    os.makedirs(os.path.dirname(LOG_AGENT_STATE_FILE), exist_ok=True)

    with open(LOG_AGENT_STATE_FILE, "w", encoding="utf-8") as file_obj:
        file_obj.write(str(position))


def follow_log():
    print(f"[+] LOG_AGENT_PATH={LOG_AGENT_PATH}", flush=True)
    print(f"[+] LOG_AGENT_STATE_FILE={LOG_AGENT_STATE_FILE}", flush=True)
    print(f"[+] FORWARD_LOG_URL={FORWARD_LOG_URL}", flush=True)
    print(f"[+] LOG_AGENT_SEND_ONLY_ATTACKS={SEND_ONLY_ATTACKS}", flush=True)

    position = read_state()

    while True:
        try:
            with open(LOG_AGENT_PATH, "r", encoding="utf-8", errors="ignore") as file_obj:
                file_obj.seek(0, os.SEEK_END)
                end = file_obj.tell()

                # Si el log rotó o fue truncado.
                if position > end:
                    print("[*] Log rotado/truncado; reiniciando posición", flush=True)
                    position = 0

                file_obj.seek(position)

                while True:
                    line = file_obj.readline()

                    if not line:
                        position = file_obj.tell()
                        write_state(position)
                        break

                    event = parse_combined_line(line.strip())

                    if event:
                        forward_event(event)
                    else:
                        print(f"[!] línea no parseada: {line[:200]}", flush=True)

                    position = file_obj.tell()
                    write_state(position)

        except FileNotFoundError:
            print(f"[!] No existe el log: {LOG_AGENT_PATH}", flush=True)
        except PermissionError:
            print(f"[!] Sin permisos para leer: {LOG_AGENT_PATH}", flush=True)
        except Exception as exc:
            print(f"[!] Error leyendo log: {exc!r}", flush=True)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    follow_log()