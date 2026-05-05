import io
import hmac
import ipaddress
import json
import os
import posixpath
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime
from functools import wraps
from hashlib import sha256
from urllib import request as urllib_request

from flask import Flask, Response, g, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

from ml_engine import (
    ATTACK_LABEL_ES,
    VALID_LABELS,
    AdaptiveClassifier,
    decode_payload,
    detect_attack,
    parse_uploaded_training,
)

def env_bool(name, default=False):
      value = os.getenv(name)
      if value is None:
          return default
      return value.strip().lower() in ("1", "true", "yes", "on")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("DB_PATH", "/data/honeypot.db")
TRAINING_FILE = os.getenv("TRAINING_FILE", "/data/training_samples.txt")
MODEL_PATH = os.getenv("MODEL_PATH", "/data/adaptive_model.joblib")
FILTER_SCRIPT = os.getenv("FILTER_SCRIPT", os.path.join(BASE_DIR, "filtro", "ossec_filter.py"))
CUSTOM_FRONT_DIR = os.getenv("CUSTOM_FRONT_DIR", "/data/custom_front")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
app.config["SECRET_KEY"] = app.secret_key
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_SIZE", "10485760"))
app.config["SESSION_COOKIE_SECURE"] = os.getenv("SESSION_COOKIE_SECURE", "1").lower() in ("1", "true", "yes", "on")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
app.config["SITE_TITLE"] = os.getenv("SITE_TITLE", "NovaCore Cloud")
app.config["SITE_SUBTITLE"] = os.getenv("SITE_SUBTITLE", "Infraestructura digital para empresas en crecimiento")
app.config["THEME_COLOR"] = os.getenv("THEME_COLOR", "#376a12")
app.config["HERO_TAGLINE"] = os.getenv("HERO_TAGLINE", "Plataforma integral de facturación, CRM y analítica")
app.config["ADMIN_USER"] = os.getenv("ADMIN_USER")
app.config["ADMIN_PASS"] = os.getenv("ADMIN_PASS")
app.config["SIEM_HINT"] = os.getenv("SIEM_HINT", "crowdsec")
app.config["ENABLE_PUBLIC_SITE"] = env_bool("ENABLE_PUBLIC_SITE", True)
app.config["ENABLE_DASHBOARD"] = env_bool("ENABLE_DASHBOARD", True)
app.config["FORWARD_LOG_URL"] = os.getenv("FORWARD_LOG_URL", "").strip()
app.config["FORWARD_LOG_TOKEN"] = os.getenv("FORWARD_LOG_TOKEN", "").strip()
app.config["INGEST_TOKEN"] = os.getenv("INGEST_TOKEN", "").strip()
app.config["INGEST_HMAC_SECRET"] = os.getenv("INGEST_HMAC_SECRET", "").strip()
app.config["INGEST_MAX_SKEW_SECONDS"] = int(os.getenv("INGEST_MAX_SKEW_SECONDS", "120"))

ALLOWED_UPLOAD_EXTENSIONS = {".txt", ".csv"}
ALLOWED_THEME_EXTENSIONS = {".html", ".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif", ".ico"}

adaptive_model = AdaptiveClassifier(MODEL_PATH)


def process_ossec_txt_with_filter(upload_text):
    if not os.path.exists(FILTER_SCRIPT):
        return None, f"filter_script_not_found: {FILTER_SCRIPT}"

    with tempfile.TemporaryDirectory(prefix="ossec_upload_") as tmp_dir:
        input_path = os.path.join(tmp_dir, "input_ossec.txt")
        output_path = os.path.join(tmp_dir, "filtered.csv")

        with open(input_path, "w", encoding="utf-8") as input_file:
            input_file.write(upload_text)

        cmd = [sys.executable, FILTER_SCRIPT, "--input", input_path, "--output", output_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20, check=False)
        if proc.returncode != 0:
            detail = (proc.stderr or proc.stdout or "unknown_error").strip()[:500]
            return None, f"filter_script_failed: {detail}"

        if not os.path.exists(output_path):
            return None, "filter_script_no_output"

        with open(output_path, "r", encoding="utf-8", errors="ignore") as output_file:
            return output_file.read(), None


def custom_front_templates_dir():
    return os.path.join(CUSTOM_FRONT_DIR, "current", "templates")


def custom_front_assets_dir():
    return os.path.join(CUSTOM_FRONT_DIR, "current", "assets")


def load_custom_page(template_name):
    custom_path = os.path.join(custom_front_templates_dir(), template_name)
    if os.path.exists(custom_path):
        with open(custom_path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    return None


def store_theme_zip(uploaded_bytes):
    temp_extract = tempfile.mkdtemp(prefix="theme_extract_")
    templates_dir = os.path.join(temp_extract, "templates")
    assets_dir = os.path.join(temp_extract, "assets")
    os.makedirs(templates_dir, exist_ok=True)
    os.makedirs(assets_dir, exist_ok=True)

    with zipfile.ZipFile(io.BytesIO(uploaded_bytes)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue

            raw_name = info.filename.replace("\\", "/")
            normalized = posixpath.normpath(raw_name).lstrip("/")
            if normalized.startswith("..") or "/.." in normalized:
                shutil.rmtree(temp_extract, ignore_errors=True)
                return {"ok": False, "error": "zip_path_not_allowed", "detail": raw_name}

            ext = os.path.splitext(normalized.lower())[1]
            if ext not in ALLOWED_THEME_EXTENSIONS:
                shutil.rmtree(temp_extract, ignore_errors=True)
                return {"ok": False, "error": "zip_extension_not_allowed", "detail": normalized}

            target_root = None
            relative_path = None
            if normalized.startswith("templates/") or ext == ".html":
                target_root = templates_dir
                relative_path = normalized.replace("templates/", "", 1) if normalized.startswith("templates/") else os.path.basename(normalized)
            elif normalized.startswith("assets/"):
                target_root = assets_dir
                relative_path = normalized.replace("assets/", "", 1)
            else:
                target_root = assets_dir
                relative_path = normalized

            if not relative_path:
                continue
            target_path = os.path.join(target_root, relative_path)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with zf.open(info) as source, open(target_path, "wb") as target:
                target.write(source.read())

    current_dir = os.path.join(CUSTOM_FRONT_DIR, "current")
    backup_dir = os.path.join(CUSTOM_FRONT_DIR, "backup")
    os.makedirs(CUSTOM_FRONT_DIR, exist_ok=True)

    if os.path.exists(backup_dir):
        shutil.rmtree(backup_dir, ignore_errors=True)
    if os.path.exists(current_dir):
        shutil.move(current_dir, backup_dir)

    shutil.move(temp_extract, current_dir)
    return {"ok": True, "templates_dir": custom_front_templates_dir(), "assets_dir": custom_front_assets_dir()}


def backup_front_exists():
    return os.path.exists(os.path.join(CUSTOM_FRONT_DIR, "backup", "templates"))


def resolve_country_for_ip(ip_value, use_network=True):
    ip_value = (ip_value or "").strip()
    if not ip_value:
        return "Desconocido"

    try:
        parsed = ipaddress.ip_address(ip_value.split(",")[0].strip())
    except ValueError:
        return "Desconocido"

    if parsed.is_private or parsed.is_loopback or parsed.is_link_local:
        return "Red interna"

    db = get_db()
    cached = db.execute("SELECT country FROM ip_geo_cache WHERE ip = ?", (ip_value,)).fetchone()
    if cached:
        return cached["country"]

    country = "Desconocido"
    if use_network:
        try:
            with urllib_request.urlopen(f"http://ip-api.com/json/{ip_value}?fields=status,country", timeout=2) as response:
                payload = json.loads(response.read().decode("utf-8", errors="ignore"))
                if payload.get("status") == "success":
                    country = payload.get("country") or "Desconocido"
        except Exception:
            country = "Desconocido"

    db.execute(
        """
        INSERT OR REPLACE INTO ip_geo_cache(ip, country, is_private, updated_at)
        VALUES (?, ?, 0, ?)
        """,
        (ip_value, country, datetime.utcnow().isoformat()),
    )
    db.commit()
    return country


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
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(CUSTOM_FRONT_DIR, exist_ok=True)
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
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS training_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            payload TEXT NOT NULL,
            suggested_label TEXT NOT NULL,
            reviewed_label TEXT,
            source TEXT DEFAULT 'runtime',
            event_id INTEGER,
            status TEXT DEFAULT 'pending'
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS dashboard_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analyst',
            is_active INTEGER DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS ip_geo_cache (
            ip TEXT PRIMARY KEY,
            country TEXT NOT NULL,
            is_private INTEGER DEFAULT 0,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS model_training_stats (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            total_samples_seen INTEGER DEFAULT 0,
            updated_at TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        INSERT OR IGNORE INTO model_training_stats(id, total_samples_seen, updated_at)
        VALUES (1, 0, ?)
        """,
        (datetime.utcnow().isoformat(),),
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
    
    admin_user = app.config.get("ADMIN_USER")
    admin_pass = app.config.get("ADMIN_PASS")

    if admin_user and admin_pass:
        admin_exists = db.execute(
            "SELECT id FROM dashboard_users WHERE username = ?",
            (admin_user,),
        ).fetchone()

        if not admin_exists:
            db.execute(
                """
                INSERT INTO dashboard_users(username, password_hash, role, is_active, created_at)
                VALUES (?, ?, 'admin', 1, ?)
                """,
                (
                    admin_user,
                    generate_password_hash(admin_pass),
                    datetime.utcnow().isoformat(),
                ),
            )
    else:
        app.logger.warning(
            "ADMIN_USER/ADMIN_PASS no están configurados; no se creó usuario admin inicial."
        )
    db.commit()
    db.close()
try:
    with app.app_context():
        init_db()
    app.logger.info("Base de datos inicializada correctamente en %s", DB_PATH)
except Exception as exc:
    app.logger.exception("Error inicializando la base de datos: %s", exc)
    raise
   
adaptive_model.load_persisted()
if not adaptive_model.loaded and os.path.exists(TRAINING_FILE):
    with open(TRAINING_FILE, "r", encoding="utf-8", errors="ignore") as file_obj:
        samples = parse_uploaded_training(file_obj.read(), TRAINING_FILE)
    adaptive_model.train_from_samples(samples)


def log_event(classification):
    db = get_db()
    headers_dump = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
    event_payload = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr),
        "method": request.method,
        "path": request.path,
        "user_agent": request.headers.get("User-Agent", ""),
        "query_string": request.query_string.decode("utf-8", errors="ignore"),
        "body": request.get_data(as_text=True)[:3000],
        "headers": headers_dump[:5000],
        "notes": classification["notes"],
        "is_attack": classification["is_attack"],
        "attack_type": classification["attack_type"],
        "severity": classification["severity"],
        "confidence": classification["confidence"],
    }
    cursor = db.execute(
        """
        INSERT INTO attack_logs(
            timestamp, ip, method, path, user_agent, query_string, body, headers, notes,
            is_attack, attack_type, severity, confidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        tuple(event_payload.values()),
    )
    event_id = cursor.lastrowid
    if classification["is_attack"] == 1 and classification["confidence"] >= 0.86 and classification["attack_type"] in VALID_LABELS:
        payload = " ".join(
            [
                request.path,
                request.query_string.decode("utf-8", errors="ignore"),
                request.get_data(as_text=True)[:2000],
            ]
        ).strip()
        save_training_candidate(payload, classification["attack_type"], event_id)
    db.commit()
    forward_event_to_remote(event_payload)


def forward_event_to_remote(event_payload):
      target_url = app.config.get("FORWARD_LOG_URL")
      if not target_url:
          return

      try:
          data = json.dumps(
              event_payload,
              separators=(",", ":"),
              ensure_ascii=False,
          ).encode("utf-8")

          timestamp = str(int(datetime.utcnow().timestamp()))

          headers = {
              "Content-Type": "application/json",
              "X-Ingest-Token": app.config.get("FORWARD_LOG_TOKEN", ""),
              "X-Ingest-Timestamp": timestamp,
          }

          hmac_secret = app.config.get("INGEST_HMAC_SECRET", "")
          if hmac_secret:
              msg = timestamp.encode("utf-8") + b"." + data
              signature = hmac.new(
                  hmac_secret.encode("utf-8"),
                  msg,
                  sha256,
              ).hexdigest()
              headers["X-Ingest-Signature"] = signature

          req = urllib_request.Request(
              target_url,
              data=data,
              headers=headers,
              method="POST",
          )

          with urllib_request.urlopen(req, timeout=5) as response:
              response_body = response.read().decode("utf-8", errors="ignore")
              app.logger.info(
                  "forward_event_to_remote_ok status=%s body=%s",
                  getattr(response, "status", "unknown"),
                  response_body[:300],
              )

      except Exception as exc:
          app.logger.exception("forward_event_to_remote_failed: %s", exc)


def increment_total_model_samples(samples_count):
    if not samples_count:
        return
    db = get_db()
    db.execute(
        """
        UPDATE model_training_stats
        SET total_samples_seen = total_samples_seen + ?, updated_at = ?
        WHERE id = 1
        """,
        (int(samples_count), datetime.utcnow().isoformat()),
    )
    db.commit()


def get_total_model_samples():
    row = get_db().execute(
        "SELECT total_samples_seen FROM model_training_stats WHERE id = 1",
    ).fetchone()
    return int(row["total_samples_seen"]) if row else 0


def save_training_candidate(payload, suggested_label, event_id=None):
    db = get_db()
    normalized_payload = (payload or "").strip()[:3000]
    if not normalized_payload:
        return

    exists = db.execute(
        """
        SELECT id FROM training_candidates
        WHERE payload = ? AND suggested_label = ? AND status = 'pending'
        LIMIT 1
        """,
        (normalized_payload, suggested_label),
    ).fetchone()
    if exists:
        return

    db.execute(
        """
        INSERT INTO training_candidates(timestamp, payload, suggested_label, source, event_id, status)
        VALUES (?, ?, ?, ?, ?, 'pending')
        """,
        (datetime.utcnow().isoformat(), normalized_payload, suggested_label, "runtime", event_id),
    )


def get_dashboard_user():
    user_id = session.get("dashboard_user_id")
    if not user_id:
        return None
    db = get_db()
    return db.execute(
        """
        SELECT id, username, role, is_active
        FROM dashboard_users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()


def dashboard_auth_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_dashboard_user()
        if not user or user["is_active"] != 1:
            if request.path.startswith("/dashboard/api") or request.path.startswith("/dashboard/approve") or request.path.startswith("/dashboard/train"):
                return jsonify({"ok": False, "error": "unauthorized"}), 401
            return redirect(url_for("dashboard_login"))
        g.dashboard_user = user
        return f(*args, **kwargs)

    return decorated


def dashboard_admin_required(f):
    @wraps(f)
    @dashboard_auth_required
    def decorated(*args, **kwargs):
        user = getattr(g, "dashboard_user", None)
        if not user or user["role"] != "admin":
            return jsonify({"ok": False, "error": "forbidden"}), 403
        return f(*args, **kwargs)

    return decorated


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"ok": False, "error": "file_too_large", "max_bytes": app.config["MAX_CONTENT_LENGTH"]}), 413


@app.before_request
def global_logger():
    if not app.config["ENABLE_PUBLIC_SITE"]:
        return
    ignore_prefixes = ("/dashboard", "/static/", "/custom-assets/")
    if not request.path.startswith(ignore_prefixes):
        features = {
            "path": decode_payload(request.path),
            "query": decode_payload(request.query_string.decode("utf-8", errors="ignore")),
            "body": decode_payload(request.get_data(as_text=True)),
            "ua": decode_payload(request.headers.get("User-Agent", "")),
        }
    try:
      classification = detect_attack(features, adaptive_model)
      log_event(classification)
    except Exception as exc:
      app.logger.exception("global_logger_failed: %s", exc)



@app.before_request
def route_mode_guard():
    if request.path.startswith("/dashboard"):
        if not app.config["ENABLE_DASHBOARD"]:
            return jsonify({"ok": False, "error": "dashboard_disabled"}), 404
        return None

    public_exceptions = ("/static/", "/custom-assets/", "/api/health",  "/api/ingest-event")
    if request.path.startswith(public_exceptions):
        return None

    if not app.config["ENABLE_PUBLIC_SITE"]:
        return jsonify({"ok": False, "error": "public_site_disabled"}), 404
    return None


@app.route("/")
def home():
    custom = load_custom_page("index.html")
    if custom:
        return Response(custom, mimetype="text/html")
    return render_template("index.html")


@app.route("/producto/<slug>")
def product(slug):
    custom = load_custom_page("product.html")
    if custom:
        return Response(custom, mimetype="text/html")
    return render_template("product.html", slug=slug)


@app.route("/contacto", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        custom = load_custom_page("contact.html")
        if custom:
            return Response(custom, mimetype="text/html")
        return render_template("contact.html", success=True)
    custom = load_custom_page("contact.html")
    if custom:
        return Response(custom, mimetype="text/html")
    return render_template("contact.html", success=False)


@app.route("/login", methods=["GET", "POST"])
def login():
    custom = load_custom_page("login.html")
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if "'" in username or " or " in username.lower() or "--" in username:
            session["user"] = "admin"
            return redirect(url_for("internal"))
        if username == "demo" and password == "demo":
            session["user"] = username
            return redirect(url_for("internal"))
    if custom:
        return Response(custom, mimetype="text/html")
    return render_template("login.html")


@app.route("/internal")
def internal():
    if not session.get("user"):
        return redirect(url_for("login"))
    custom = load_custom_page("internal.html")
    if custom:
        return Response(custom, mimetype="text/html")
    return render_template("internal.html", user=session["user"])


@app.route("/custom-assets/<path:filename>")
def custom_assets(filename):
    assets_root = custom_front_assets_dir()
    if not os.path.exists(assets_root):
        return jsonify({"ok": False, "error": "custom_assets_not_found"}), 404
    return send_from_directory(assets_root, filename)


@app.route("/<path:filename>")
def custom_assets_passthrough(filename):
    reserved = {"dashboard", "api", "producto", "contacto", "login", "internal", "search", "static", "custom-assets"}
    first = filename.split("/", 1)[0]
    if first in reserved:
        return jsonify({"ok": False, "error": "not_found"}), 404

    ext = os.path.splitext(filename.lower())[1]
    if ext not in ALLOWED_THEME_EXTENSIONS:
        return jsonify({"ok": False, "error": "not_found"}), 404

    assets_root = custom_front_assets_dir()
    if not os.path.exists(assets_root):
        return jsonify({"ok": False, "error": "not_found"}), 404

    candidate = os.path.join(assets_root, filename)
    if os.path.exists(candidate):
        return send_from_directory(assets_root, filename)

    basename_candidate = os.path.join(assets_root, os.path.basename(filename))
    if os.path.exists(basename_candidate):
        return send_from_directory(assets_root, os.path.basename(filename))

    return jsonify({"ok": False, "error": "not_found"}), 404


@app.route("/search")
def search():
    q = request.args.get("q", "")
    template = f"<h3>Resultados para: {q}</h3><p>No se encontraron coincidencias.</p>"
    return template


@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "honeypot-web"})


@app.route("/dashboard/login", methods=["GET", "POST"])
def dashboard_login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        db = get_db()
        user = db.execute(
            """
            SELECT id, username, password_hash, role, is_active
            FROM dashboard_users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()
        if user and user["is_active"] == 1 and check_password_hash(user["password_hash"], password):
            session["dashboard_user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        return render_template("dashboard_login.html", error="Credenciales inválidas")

    return render_template("dashboard_login.html", error=None)


@app.route("/dashboard/logout", methods=["POST"])
@dashboard_auth_required
def dashboard_logout():
    session.pop("dashboard_user_id", None)
    return redirect(url_for("dashboard_login"))


@app.route("/dashboard")
@dashboard_auth_required
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

    pending_candidates = db.execute(
        "SELECT COUNT(*) AS total FROM training_candidates WHERE status = 'pending'"
    ).fetchone()

    formatted_top = []
    for item in top_types:
        attack_key = item["attack_type"]
        formatted_top.append(
            {
                "attack_type": attack_key,
                "attack_label": ATTACK_LABEL_ES.get(attack_key, attack_key.replace("_", " ").title()),
                "total": item["total"],
            }
        )

    return render_template(
        "dashboard.html",
        stats=stats,
        top_types=formatted_top,
        siem_hint=app.config["SIEM_HINT"],
        training_file=TRAINING_FILE,
        model_loaded=adaptive_model.loaded,
        model_samples=adaptive_model.samples_seen,
        max_upload_size=app.config["MAX_CONTENT_LENGTH"],
        custom_front_active=os.path.exists(custom_front_templates_dir()),
        custom_front_backup=backup_front_exists(),
        pending_candidates=pending_candidates["total"] if pending_candidates else 0,
        current_user=g.dashboard_user,
        current_role="Administrador" if g.dashboard_user["role"] == "admin" else "Analista",
        total_samples_seen=get_total_model_samples(),
    )


@app.route("/dashboard/reload-training", methods=["POST"])
@dashboard_auth_required
def reload_training():
    if not os.path.exists(TRAINING_FILE):
        return jsonify({"ok": False, "error": "training_file_not_found", "training_file": TRAINING_FILE}), 404

    with open(TRAINING_FILE, "r", encoding="utf-8", errors="ignore") as file_obj:
        samples = parse_uploaded_training(file_obj.read(), TRAINING_FILE)
    result = adaptive_model.train_from_samples(samples)
    status = 200 if result.get("ok") else 400
    result["training_file"] = TRAINING_FILE
    if result.get("ok"):
        increment_total_model_samples(result.get("samples"))
        result["total_samples_seen"] = get_total_model_samples()
    return jsonify(result), status


@app.route("/dashboard/upload-ossec", methods=["POST"])
@dashboard_auth_required
def upload_ossec_file():
    upload = request.files.get("dataset")
    if not upload or not upload.filename:
        return jsonify({"ok": False, "error": "missing_file"}), 400

    safe_name = secure_filename(upload.filename)
    ext = os.path.splitext(safe_name.lower())[1]
    if ext not in ALLOWED_UPLOAD_EXTENSIONS:
        return jsonify({"ok": False, "error": "invalid_extension", "allowed": sorted(ALLOWED_UPLOAD_EXTENSIONS)}), 400

    content = upload.stream.read().decode("utf-8", errors="ignore")
    normalized_content = content

    if ext == ".txt":
        filtered_csv, filter_error = process_ossec_txt_with_filter(content)
        if filtered_csv:
            normalized_content = filtered_csv
            safe_name = "filtered_from_ossec.csv"
        else:
            return jsonify({"ok": False, "error": "filter_processing_failed", "detail": filter_error}), 400

    samples = parse_uploaded_training(normalized_content, safe_name)
    parsed_samples = len(samples)
    if parsed_samples < 25:
        return jsonify({"ok": False, "error": "dataset_insuficiente", "detail": "Se detectaron menos de 25 filas útiles.", "parsed_samples": parsed_samples, "stages": ["uploading", "parsing"]}), 400

    result = adaptive_model.train_from_samples(samples)
    if not result.get("ok"):
        return jsonify(result), 400
    increment_total_model_samples(result.get("samples"))

    os.makedirs(os.path.dirname(TRAINING_FILE), exist_ok=True)
    with open(TRAINING_FILE, "w", encoding="utf-8") as file_obj:
        for label, payload in samples:
            file_obj.write(f"{label}\t{payload[:3000]}\n")

    return jsonify(
        {
            "ok": True,
            "filename": safe_name,
            "samples": result["samples"],
            "labels": result["labels"],
            "training_file": TRAINING_FILE,
            "model_path": MODEL_PATH,
            "parsed_samples": parsed_samples,
            "stages": ["uploading", "parsing", "training", "done"],
            "total_samples_seen": get_total_model_samples(),
        }
    )


@app.route("/api/ingest-event", methods=["POST"])
def ingest_remote_event():
    if not app.config["ENABLE_DASHBOARD"]:
        return jsonify({"ok": False, "error": "dashboard_disabled"}), 404
    token = request.headers.get("X-Ingest-Token", "")
    expected = app.config.get("INGEST_TOKEN", "")
    if not expected or token != expected:
        return jsonify({"ok": False, "error": "forbidden"}), 403
    content_length = request.content_length or 0
    if content_length <= 0 or content_length > 65536:
        return jsonify({"ok": False, "error": "invalid_request_size"}), 400
    timestamp_header = request.headers.get("X-Ingest-Timestamp", "")
    if not timestamp_header.isdigit():
        return jsonify({"ok": False, "error": "missing_timestamp"}), 400
    now_ts = int(datetime.utcnow().timestamp())
    sent_ts = int(timestamp_header)
    if abs(now_ts - sent_ts) > app.config["INGEST_MAX_SKEW_SECONDS"]:
        return jsonify({"ok": False, "error": "timestamp_out_of_window"}), 400

    data = request.get_json(silent=True) or {}
    if app.config.get("INGEST_HMAC_SECRET"):
        raw_body = request.get_data(as_text=True)
        expected_sig = hmac.new(
            app.config["INGEST_HMAC_SECRET"].encode("utf-8"),
            f"{timestamp_header}.{raw_body}".encode("utf-8"),
            sha256,
        ).hexdigest()
        got_sig = request.headers.get("X-Ingest-Signature", "")
        if not got_sig or not hmac.compare_digest(got_sig, expected_sig):
            return jsonify({"ok": False, "error": "invalid_signature"}), 403

    required = {"timestamp", "path"}
    if not required.issubset(data.keys()):
        return jsonify({"ok": False, "error": "invalid_payload"}), 400

    features = {
        "path": decode_payload(data.get("path", "")),
        "query": decode_payload(data.get("query_string", "")),
        "body": decode_payload(data.get("body", "")),
        "ua": decode_payload(data.get("user_agent", "")),
    }
    classification = detect_attack(features, adaptive_model)

    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO attack_logs(
            timestamp, ip, method, path, user_agent, query_string, body, headers, notes,
            is_attack, attack_type, severity, confidence
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            data.get("timestamp"),
            data.get("ip"),
            data.get("method"),
            data.get("path"),
            data.get("user_agent"),
            data.get("query_string"),
            data.get("body"),
            data.get("headers"),
            f"remote_ingest {classification.get('notes', '')}".strip(),
            classification.get("is_attack", 0),
            classification.get("attack_type", "benign"),
            classification.get("severity", "low"),
            classification.get("confidence", 0.0),
        ),
    )
    event_id = cursor.lastrowid
    if (
        classification.get("is_attack") == 1
        and float(classification.get("confidence", 0)) >= 0.86
        and classification.get("attack_type") in VALID_LABELS
    ):
        payload = " ".join(
            [
                data.get("path", ""),
                data.get("query_string", ""),
                data.get("body", ""),
            ]
        ).strip()
        save_training_candidate(payload, classification.get("attack_type"), event_id)
    db.commit()
    return jsonify({"ok": True, "classification": classification})




@app.route("/dashboard/api/logs")
@dashboard_auth_required
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
@dashboard_auth_required
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

    payload = []
    for row in rows:
        item = dict(row)
        item["country"] = resolve_country_for_ip(item.get("ip"))
        payload.append(item)
    return jsonify(payload)


@app.route("/dashboard/api/distribution")
@dashboard_auth_required
def dashboard_distribution():
    db = get_db()
    rows = db.execute(
        """
        SELECT attack_type, COUNT(*) AS total
        FROM attack_logs
        WHERE is_attack = 1
        GROUP BY attack_type
        ORDER BY total DESC
        """
    ).fetchall()
    payload = []
    for row in rows:
        data = dict(row)
        data["attack_label"] = ATTACK_LABEL_ES.get(data["attack_type"], data["attack_type"].replace("_", " ").title())
        payload.append(data)
    return jsonify(payload)


@app.route("/dashboard/api/candidates")
@dashboard_auth_required
def dashboard_candidates():
    db = get_db()
    rows = db.execute(
        """
        SELECT id, timestamp, suggested_label, reviewed_label, status, payload, source
        FROM training_candidates
        ORDER BY id DESC
        LIMIT 150
        """
    ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/dashboard/api/top-ips")
@dashboard_auth_required
def dashboard_top_ips():
    db = get_db()
    rows = db.execute(
        """
        SELECT COALESCE(ip, 'unknown') AS ip, COUNT(*) AS total
        FROM attack_logs
        GROUP BY ip
        ORDER BY total DESC
        LIMIT 10
        """
    ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/dashboard/api/model-health")
@dashboard_auth_required
def dashboard_model_health():
    db = get_db()
    rows = db.execute(
        """
        SELECT
            SUM(CASE WHEN confidence >= 0.90 THEN 1 ELSE 0 END) AS very_high,
            SUM(CASE WHEN confidence >= 0.75 AND confidence < 0.90 THEN 1 ELSE 0 END) AS high,
            SUM(CASE WHEN confidence >= 0.60 AND confidence < 0.75 THEN 1 ELSE 0 END) AS medium,
            SUM(CASE WHEN confidence < 0.60 THEN 1 ELSE 0 END) AS low
        FROM attack_logs
        WHERE is_attack = 1
        """
    ).fetchone()
    return jsonify(dict(rows))


@app.route("/dashboard/api/model-metrics")
@dashboard_auth_required
def dashboard_model_metrics():
    pretty = []
    for label, values in adaptive_model.metrics.items():
        pretty.append(
            {
                "label": label,
                "label_es": ATTACK_LABEL_ES.get(label, label.replace("_", " ").title()),
                "precision": values.get("precision", 0),
                "recall": values.get("recall", 0),
                "f1": values.get("f1", 0),
                "support": values.get("support", 0),
            }
        )
    return jsonify(sorted(pretty, key=lambda x: x["precision"], reverse=True))


@app.route("/dashboard/api/country-stats")
@dashboard_auth_required
def dashboard_country_stats():
    db = get_db()
    rows = db.execute(
        """
        SELECT ip, COUNT(*) AS total
        FROM attack_logs
        WHERE is_attack = 1
        GROUP BY ip
        ORDER BY total DESC
        LIMIT 300
        """
    ).fetchall()
    country_counts = {}
    for row in rows:
        country = resolve_country_for_ip(row["ip"])
        country_counts[country] = country_counts.get(country, 0) + row["total"]

    ordered = sorted(country_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify([{"country": country, "total": total} for country, total in ordered])


@app.route("/dashboard/export-wazuh")
@dashboard_auth_required
def export_wazuh_log():
    try:
        db = get_db()
        rows = db.execute(
            """
            SELECT timestamp, ip, method, path, user_agent, query_string, attack_type, severity, confidence
            FROM attack_logs
            WHERE is_attack = 1
            ORDER BY id DESC
            LIMIT 2000
            """
        ).fetchall()

        lines = []
        for row in rows:
            country = resolve_country_for_ip(row["ip"], use_network=False)
            event = {
                "event_type": "honeypot_attack",
                "timestamp": row["timestamp"],
                "srcip": row["ip"],
                "country": country,
                "method": row["method"],
                "path": row["path"],
                "query": row["query_string"],
                "user_agent": row["user_agent"],
                "attack_type": row["attack_type"],
                "severity": row["severity"],
                "confidence": row["confidence"],
            }
            lines.append(json.dumps(event, ensure_ascii=False))

        content = "\n".join(lines) + ("\n" if lines else "")
        return Response(
            content,
            mimetype="text/plain",
            headers={"Content-Disposition": "attachment; filename=honeypot_wazuh.log"},
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": "wazuh_export_failed", "detail": str(exc)}), 500


@app.route("/dashboard/approve-candidate", methods=["POST"])
@dashboard_auth_required
def approve_candidate():
    data = request.get_json(silent=True) or {}
    candidate_id = data.get("id")
    label = (data.get("label") or "").strip().lower()
    if not candidate_id:
        return jsonify({"ok": False, "error": "missing_id"}), 400
    if label and label not in VALID_LABELS:
        return jsonify({"ok": False, "error": "invalid_label"}), 400

    db = get_db()
    row = db.execute("SELECT id, suggested_label FROM training_candidates WHERE id = ?", (candidate_id,)).fetchone()
    if not row:
        return jsonify({"ok": False, "error": "candidate_not_found"}), 404

    reviewed_label = label or row["suggested_label"]
    db.execute(
        """
        UPDATE training_candidates
        SET status = 'approved', reviewed_label = ?
        WHERE id = ?
        """,
        (reviewed_label, candidate_id),
    )
    db.commit()
    return jsonify({"ok": True, "id": candidate_id, "label": reviewed_label})


@app.route("/dashboard/reject-candidate", methods=["POST"])
@dashboard_auth_required
def reject_candidate():
    data = request.get_json(silent=True) or {}
    candidate_id = data.get("id")
    if not candidate_id:
        return jsonify({"ok": False, "error": "missing_id"}), 400

    db = get_db()
    row = db.execute("SELECT id FROM training_candidates WHERE id = ?", (candidate_id,)).fetchone()
    if not row:
        return jsonify({"ok": False, "error": "candidate_not_found"}), 404

    db.execute(
        """
        UPDATE training_candidates
        SET status = 'rejected'
        WHERE id = ?
        """,
        (candidate_id,),
    )
    db.commit()
    return jsonify({"ok": True, "id": candidate_id})


@app.route("/dashboard/train-candidates", methods=["POST"])
@dashboard_auth_required
def train_from_candidates():
    db = get_db()
    rows = db.execute(
        """
        SELECT COALESCE(reviewed_label, suggested_label) AS label, payload
        FROM training_candidates
        WHERE status = 'approved'
        """
    ).fetchall()
    if not rows:
        return jsonify({"ok": False, "error": "no_approved_candidates"}), 400

    samples = [(row["label"], row["payload"]) for row in rows if row["label"] in VALID_LABELS]
    result = adaptive_model.train_from_samples(samples)
    status = 200 if result.get("ok") else 400
    if result.get("ok"):
        increment_total_model_samples(result.get("samples"))
        db.execute("UPDATE training_candidates SET status = 'trained' WHERE status = 'approved'")
        db.commit()
        result["total_samples_seen"] = get_total_model_samples()
    return jsonify(result), status


@app.route("/dashboard/api/users")
@dashboard_admin_required
def dashboard_users():
    db = get_db()
    rows = db.execute(
        """
        SELECT id, username, role, is_active, created_at
        FROM dashboard_users
        ORDER BY id ASC
        """
    ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/dashboard/api/users", methods=["POST"])
@dashboard_admin_required
def create_dashboard_user():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    role = (data.get("role") or "analyst").strip().lower()
    if not username or len(password) < 8:
        return jsonify({"ok": False, "error": "invalid_input"}), 400
    if role not in {"admin", "analyst"}:
        role = "analyst"

    db = get_db()
    exists = db.execute("SELECT id FROM dashboard_users WHERE username = ?", (username,)).fetchone()
    if exists:
        return jsonify({"ok": False, "error": "user_exists"}), 400

    db.execute(
        """
        INSERT INTO dashboard_users(username, password_hash, role, is_active, created_at)
        VALUES (?, ?, ?, 1, ?)
        """,
        (username, generate_password_hash(password), role, datetime.utcnow().isoformat()),
    )
    db.commit()
    return jsonify({"ok": True})


@app.route("/dashboard/api/users/<int:user_id>/password", methods=["POST"])
@dashboard_admin_required
def change_dashboard_user_password(user_id):
    data = request.get_json(silent=True) or {}
    new_password = data.get("password") or ""
    if len(new_password) < 8:
        return jsonify({"ok": False, "error": "password_too_short"}), 400
    db = get_db()
    db.execute("UPDATE dashboard_users SET password_hash = ? WHERE id = ?", (generate_password_hash(new_password), user_id))
    db.commit()
    return jsonify({"ok": True})


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000)
