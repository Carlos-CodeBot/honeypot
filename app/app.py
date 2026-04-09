import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, Response, g, jsonify, redirect, render_template, request, session, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "honeypot.db")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-me-in-production")
app.config["SITE_TITLE"] = os.getenv("SITE_TITLE", "Portal Empresarial")
app.config["SITE_SUBTITLE"] = os.getenv("SITE_SUBTITLE", "Bienvenido a tu panel de clientes")
app.config["THEME_COLOR"] = os.getenv("THEME_COLOR", "#1e3a8a")
app.config["ADMIN_USER"] = os.getenv("ADMIN_USER", "admin")
app.config["ADMIN_PASS"] = os.getenv("ADMIN_PASS", "admin123")


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
            notes TEXT
        )
        """
    )
    db.commit()
    db.close()


def log_attack(notes=""):
    db = get_db()
    headers_dump = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
    db.execute(
        """
        INSERT INTO attack_logs(timestamp, ip, method, path, user_agent, query_string, body, headers, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            notes,
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
    ignore_paths = {"/dashboard", "/dashboard/api/logs", "/static/style.css"}
    if request.path not in ignore_paths:
        indicators = ["' or", "union select", "../", "<script", "sleep(", "benchmark("]
        payload = (request.query_string.decode("utf-8", errors="ignore") + " " + request.get_data(as_text=True)).lower()
        notes = ""
        for i in indicators:
            if i in payload:
                notes += f"Indicator:{i}; "
        log_attack(notes.strip())


@app.route("/")
def home():
    promo = request.args.get("promo", "")
    return render_template("index.html", promo=promo)


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
            COUNT(DISTINCT ip) AS unique_ips,
            SUM(CASE WHEN notes != '' THEN 1 ELSE 0 END) AS suspicious
        FROM attack_logs
        """
    ).fetchone()
    return render_template("dashboard.html", stats=stats)


@app.route("/dashboard/api/logs")
@basic_auth_required
def dashboard_logs():
    db = get_db()
    rows = db.execute(
        "SELECT id, timestamp, ip, method, path, user_agent, query_string, notes FROM attack_logs ORDER BY id DESC LIMIT 200"
    ).fetchall()
    return jsonify([dict(row) for row in rows])


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000)
