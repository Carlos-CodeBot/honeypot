import json
import os
import re
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, Response, g, jsonify, redirect, render_template, request, session, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "honeypot.db")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-me-in-production")
app.config["SITE_TITLE"] = os.getenv("SITE_TITLE", "NovaCore Cloud")
app.config["SITE_SUBTITLE"] = os.getenv("SITE_SUBTITLE", "Infraestructura digital para empresas en crecimiento")
app.config["THEME_COLOR"] = os.getenv("THEME_COLOR", "#1f3aed")
app.config["HERO_TAGLINE"] = os.getenv("HERO_TAGLINE", "Plataforma integral de facturación, CRM y analítica")
app.config["ADMIN_USER"] = os.getenv("ADMIN_USER", "admin")
app.config["ADMIN_PASS"] = os.getenv("ADMIN_PASS", "admin123")
app.config["SIEM_HINT"] = os.getenv("SIEM_HINT", "crowdsec")

ATTACK_RULES = [
    {
        "name": "sqli",
        "severity": "high",
        "confidence": 0.9,
        "regex": r"(union\s+select|or\s+1=1|information_schema|sleep\s*\(|benchmark\s*\(|--|/\*|@@version)",
    },
    {
        "name": "xss",
        "severity": "high",
        "confidence": 0.85,
        "regex": r"(<script|javascript:|onerror=|onload=|svg\s+onload)",
    },
    {
        "name": "path_traversal",
        "severity": "medium",
        "confidence": 0.8,
        "regex": r"(\.\./|%2e%2e%2f|%252e%252e%252f|etc/passwd|boot.ini)",
    },
    {
        "name": "command_injection",
        "severity": "high",
        "confidence": 0.88,
        "regex": r"(;\s*(cat|ls|id|whoami)|\|\||&&|`.+`|\$\(.+\))",
    },
    {
        "name": "scanner_bot",
        "severity": "medium",
        "confidence": 0.65,
        "regex": r"(sqlmap|nikto|nmap|masscan|acunetix|zap|nuclei)",
    },
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip TEXT,
            method TEXT,
            path TEXT,
            user_agent TEXT,
            query_string TEXT,
            body TEXT,
            headers TEXT,
            notes TEXT,
            is_attack INTEGER DEFAULT 0,
            attack_type TEXT DEFAULT 'benign',
            severity TEXT DEFAULT 'low',
            confidence REAL DEFAULT 0.0
        )
        """
    )
    db.commit()

    existing_columns = {row[1] for row in db.execute("PRAGMA table_info(attack_logs)").fetchall()}
    required_columns = {
        "is_attack": "INTEGER DEFAULT 0",
        "attack_type": "TEXT DEFAULT 'benign'",
        "severity": "TEXT DEFAULT 'low'",
        "confidence": "REAL DEFAULT 0.0",
    }
    for col, col_type in required_columns.items():
        if col not in existing_columns:
            db.execute(f"ALTER TABLE attack_logs ADD COLUMN {col} {col_type}")

    db.commit()
    db.close()


def detect_attack(payload):
    matches = []
    max_confidence = 0.0
    severity = "low"

    for rule in ATTACK_RULES:
        if re.search(rule["regex"], payload, flags=re.IGNORECASE):
            matches.append(rule["name"])
            max_confidence = max(max_confidence, rule["confidence"])
            if rule["severity"] == "high":
                severity = "high"
            elif rule["severity"] == "medium" and severity != "high":
                severity = "medium"

    is_attack = bool(matches)
    attack_type = ",".join(sorted(set(matches))) if matches else "benign"

    if len(matches) >= 2:
        max_confidence = min(0.98, max_confidence + 0.08)

    return {
        "is_attack": 1 if is_attack else 0,
        "attack_type": attack_type,
        "severity": severity,
        "confidence": round(max_confidence, 2) if is_attack else 0.0,
        "notes": f"rules={attack_type}" if is_attack else "",
    }


def log_event(classification):
    db = get_db()
    headers_dump = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
    db.execute(
        """
        INSERT INTO attack_logs(
            timestamp, ip, method, path, user_agent, query_string, body, headers, notes,
            is_attack, attack_type, severity, confidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.utcnow().isoformat(),
            request.headers.get("X-Forwarded-For", request.remote_addr),
            request.method,
            request.path,
            request.headers.get("User-Agent", ""),
            request.query_string.decode("utf-8", errors="ignore"),
            request.get_data(as_text=True)[:3000],
            headers_dump[:5000],
            classification["notes"],
            classification["is_attack"],
            classification["attack_type"],
            classification["severity"],
            classification["confidence"],
        ),
    )
    db.commit()


def basic_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != app.config["ADMIN_USER"] or auth.password != app.config["ADMIN_PASS"]:
            return Response(
                "Acceso no autorizado",
                401,
                {"WWW-Authenticate": 'Basic realm="Honeypot Dashboard"'},
            )
        return f(*args, **kwargs)

    return decorated


@app.before_request
def global_logger():
    ignore_paths = {"/dashboard", "/dashboard/api/logs", "/dashboard/api/intel", "/static/style.css"}
    if request.path not in ignore_paths:
        payload = " ".join(
            [
                request.path,
                request.query_string.decode("utf-8", errors="ignore"),
                request.get_data(as_text=True),
                json.dumps(dict(request.headers)),
            ]
        ).lower()
        classification = detect_attack(payload)
        log_event(classification)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/producto/<slug>")
def product(slug):
    return render_template("product.html", slug=slug)


@app.route("/contacto", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        return render_template("contact.html", success=True)
    return render_template("contact.html", success=False)


@app.route("/login", methods=["GET", "POST"])
def login():
    # Vulnerabilidad intencional: validación insegura para simular SQLi
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if "'" in username or " or " in username.lower() or "--" in username:
            session["user"] = "admin"
            return redirect(url_for("internal"))
        if username == "demo" and password == "demo":
            session["user"] = username
            return redirect(url_for("internal"))
    return render_template("login.html")


@app.route("/internal")
def internal():
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_template("internal.html", user=session["user"])


@app.route("/search")
def search():
    # Vulnerabilidad intencional: renderizado de input sin sanitizar (XSS)
    q = request.args.get("q", "")
    template = f"<h3>Resultados para: {q}</h3><p>No se encontraron coincidencias.</p>"
    return template


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "honeypot-web"})


@app.route("/dashboard")
@basic_auth_required
def dashboard():
    db = get_db()
    stats = db.execute(
        """
        SELECT
            COUNT(*) AS total,
            SUM(CASE WHEN is_attack = 1 THEN 1 ELSE 0 END) AS attacks,
            COUNT(DISTINCT ip) AS unique_ips,
            SUM(CASE WHEN severity = 'high' THEN 1 ELSE 0 END) AS high_severity
        FROM attack_logs
        """
    ).fetchone()

    top_types = db.execute(
        """
        SELECT attack_type, COUNT(*) AS total
        FROM attack_logs
        WHERE is_attack = 1
        GROUP BY attack_type
        ORDER BY total DESC
        LIMIT 5
        """
    ).fetchall()

    return render_template(
        "dashboard.html",
        stats=stats,
        top_types=[dict(x) for x in top_types],
        siem_hint=app.config["SIEM_HINT"],
    )


@app.route("/dashboard/api/logs")
@basic_auth_required
def dashboard_logs():
    db = get_db()
    only_attacks = request.args.get("only_attacks") == "1"

    if only_attacks:
        rows = db.execute(
            """
            SELECT id, timestamp, ip, method, path, user_agent, query_string,
                   is_attack, attack_type, severity, confidence
            FROM attack_logs
            WHERE is_attack = 1
            ORDER BY id DESC
            LIMIT 200
            """
        ).fetchall()
    else:
        rows = db.execute(
            """
            SELECT id, timestamp, ip, method, path, user_agent, query_string,
                   is_attack, attack_type, severity, confidence
            FROM attack_logs
            ORDER BY id DESC
            LIMIT 200
            """
        ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/dashboard/api/intel")
@basic_auth_required
def dashboard_intel():
    db = get_db()
    rows = db.execute(
        """
        SELECT ip,
               COUNT(*) AS total,
               SUM(CASE WHEN is_attack = 1 THEN 1 ELSE 0 END) AS attacks,
               MAX(confidence) AS max_confidence
        FROM attack_logs
        GROUP BY ip
        HAVING attacks > 0
        ORDER BY attacks DESC, max_confidence DESC
        LIMIT 50
        """
    ).fetchall()

    return jsonify([dict(row) for row in rows])


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000)
