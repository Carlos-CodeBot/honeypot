import csv
import io
import os
import posixpath
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime
from functools import wraps
from urllib.parse import unquote_plus

import joblib
from flask import Flask, Response, g, jsonify, redirect, render_template, request, send_from_directory, session, url_for
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("DB_PATH", "/data/honeypot.db")
TRAINING_FILE = os.getenv("TRAINING_FILE", "/data/training_samples.txt")
MODEL_PATH = os.getenv("MODEL_PATH", "/data/adaptive_model.joblib")
FILTER_SCRIPT = os.getenv("FILTER_SCRIPT", os.path.join(BASE_DIR, "filtro", "ossec_filter.py"))
CUSTOM_FRONT_DIR = os.getenv("CUSTOM_FRONT_DIR", "/data/custom_front")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change-me-in-production")
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_UPLOAD_SIZE", "10485760"))
app.config["SITE_TITLE"] = os.getenv("SITE_TITLE", "NovaCore Cloud")
app.config["SITE_SUBTITLE"] = os.getenv("SITE_SUBTITLE", "Infraestructura digital para empresas en crecimiento")
app.config["THEME_COLOR"] = os.getenv("THEME_COLOR", "#376a12")
app.config["HERO_TAGLINE"] = os.getenv("HERO_TAGLINE", "Plataforma integral de facturación, CRM y analítica")
app.config["ADMIN_USER"] = os.getenv("ADMIN_USER", "admin")
app.config["ADMIN_PASS"] = os.getenv("ADMIN_PASS", "admin123")
app.config["SIEM_HINT"] = os.getenv("SIEM_HINT", "crowdsec")

ATTACK_RULES = [
    {
        "name": "xss",
        "severity": "high",
        "confidence": 0.93,
        "targets": ["query", "body", "path"],
        "regex": r"(<\s*script\b|javascript:|on\w+\s*=|<\s*img\b[^>]*\bon\w+\s*=|<\s*svg\b)",
    },
    {
        "name": "sqli",
        "severity": "high",
        "confidence": 0.9,
        "targets": ["query", "body", "path"],
        "regex": r"(union\s+all?\s+select|information_schema|(?:'|\")\s*(?:or|and)\s*(?:'\d+'|\d+)\s*=\s*(?:'\d+'|\d+)|\b(?:sleep|benchmark)\s*\(|waitfor\s+delay|/\*\!\d+)",
    },
    {
        "name": "path_traversal",
        "severity": "medium",
        "confidence": 0.83,
        "targets": ["query", "path"],
        "regex": r"(\.\./|%2e%2e%2f|%252e%252e%252f|etc/passwd|boot\.ini)",
    },
    {
        "name": "lfi",
        "severity": "high",
        "confidence": 0.87,
        "targets": ["query", "path"],
        "regex": r"(php://filter|/proc/self/environ|/etc/passwd|/var/log/auth\.log|\.{2}/)",
    },
    {
        "name": "rfi",
        "severity": "high",
        "confidence": 0.86,
        "targets": ["query", "body"],
        "regex": r"(https?://[^\s]+\.(txt|php|jpg)|include=https?://|require=https?://)",
    },
    {
        "name": "ssrf",
        "severity": "high",
        "confidence": 0.87,
        "targets": ["query", "body"],
        "regex": r"(169\.254\.169\.254|localhost|127\.0\.0\.1|0\.0\.0\.0|file://|gopher://)",
    },
    {
        "name": "xxe",
        "severity": "high",
        "confidence": 0.9,
        "targets": ["body", "query"],
        "regex": r"(<!doctype\s+[^>]*\[|<!entity\s+\w+\s+system|file:///etc/passwd)",
    },
    {
        "name": "deserialization",
        "severity": "high",
        "confidence": 0.82,
        "targets": ["body", "query"],
        "regex": r"(java\.lang\.runtime|objectinputstream|ysoserial|__reduce__|ac ed 00 05|rO0AB)",
    },
    {
        "name": "auth_bypass",
        "severity": "high",
        "confidence": 0.84,
        "targets": ["query", "body", "path"],
        "regex": r"(admin=true|is_admin=1|role=admin|bypass|password\s*=\s*'?'?\s*or\s*'1'='1)",
    },
    {
        "name": "bruteforce",
        "severity": "medium",
        "confidence": 0.75,
        "targets": ["path", "query", "body"],
        "regex": r"(/login|/wp-login\.php|/xmlrpc\.php|invalid password|too many attempts)",
    },
    {
        "name": "webshell_activity",
        "severity": "high",
        "confidence": 0.88,
        "targets": ["path", "query", "body"],
        "regex": r"(cmd=|c99\.php|r57\.php|wso\.php|shell_exec|passthru\()",
    },
    {
        "name": "file_upload_abuse",
        "severity": "high",
        "confidence": 0.85,
        "targets": ["path", "body", "query"],
        "regex": r"(multipart/form-data|filename=.*\.(php|jsp|asp|aspx|exe|sh)|/upload|content-type:\s*application/x-php)",
    },
    {
        "name": "command_injection",
        "severity": "high",
        "confidence": 0.86,
        "targets": ["query", "body"],
        "regex": r"(;\s*(cat|ls|id|whoami|wget|curl|nc|bash)\b|\|\||&&|`[^`]+`|\$\([^)]+\))",
    },
    {
        "name": "scanner_bot",
        "severity": "medium",
        "confidence": 0.72,
        "targets": ["ua"],
        "regex": r"(sqlmap|nikto|nmap|masscan|acunetix|zap|nuclei|dirbuster)",
    },
]

SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3}
ALLOWED_UPLOAD_EXTENSIONS = {".txt", ".csv"}
VALID_LABELS = {
    "xss",
    "sqli",
    "path_traversal",
    "command_injection",
    "scanner_bot",
    "lfi",
    "rfi",
    "ssrf",
    "xxe",
    "deserialization",
    "auth_bypass",
    "bruteforce",
    "webshell_activity",
    "file_upload_abuse",
    "benign",
}
ALLOWED_THEME_EXTENSIONS = {".html", ".css", ".js", ".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif", ".ico"}
DEFAULT_BENIGN_SAMPLES = [
    "GET /",
    "GET /contacto",
    "GET /producto/crm",
    "POST /contacto nombre=juan email=demo@empresa.com",
    "GET /search?q=precios+planes",
    "GET /api/health",
]


class AdaptiveClassifier:
    def __init__(self, model_path):
        self.model_path = model_path
        self.pipeline = None
        self.labels = []
        self.loaded = False
        self.samples_seen = 0

    def load_persisted(self):
        if not os.path.exists(self.model_path):
            self.loaded = False
            return

        artifact = joblib.load(self.model_path)
        self.pipeline = artifact.get("pipeline")
        self.labels = artifact.get("labels", [])
        self.samples_seen = artifact.get("samples_seen", 0)
        self.loaded = self.pipeline is not None

    def train_from_samples(self, samples):
        texts = []
        labels = []
        for label, payload in samples:
            if label in VALID_LABELS and payload:
                texts.append(payload[:3000])
                labels.append(label)

        if "benign" not in set(labels):
            for sample in DEFAULT_BENIGN_SAMPLES:
                texts.append(sample)
                labels.append("benign")

        unique_labels = set(labels)
        if len(texts) < 25 or len(unique_labels) < 2:
            return {
                "ok": False,
                "error": "dataset_insuficiente",
                "detail": "Se requieren al menos 25 muestras y 2 clases.",
            }

        self.pipeline = Pipeline(
            [
                (
                    "tfidf",
                    TfidfVectorizer(
                        analyzer="char_wb",
                        ngram_range=(3, 5),
                        lowercase=True,
                        max_features=25000,
                    ),
                ),
                (
                    "mlp",
                    MLPClassifier(
                        hidden_layer_sizes=(64, 32),
                        activation="relu",
                        solver="adam",
                        max_iter=250,
                        random_state=42,
                        early_stopping=True,
                        validation_fraction=0.15,
                        n_iter_no_change=8,
                    ),
                ),
            ]
        )
        self.pipeline.fit(texts, labels)
        self.labels = sorted(unique_labels)
        self.samples_seen = len(texts)
        self.loaded = True

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(
            {
                "pipeline": self.pipeline,
                "labels": self.labels,
                "samples_seen": self.samples_seen,
            },
            self.model_path,
        )
        return {"ok": True, "samples": self.samples_seen, "labels": self.labels}

    def predict(self, payload):
        if not self.loaded or not payload.strip():
            return None

        proba = self.pipeline.predict_proba([payload])[0]
        classes = self.pipeline.classes_
        best_idx = int(proba.argmax())
        best_label = classes[best_idx]
        confidence = float(round(proba[best_idx], 2))

        if best_label == "benign" or confidence < 0.62:
            return {
                "is_attack": 0,
                "attack_type": "benign",
                "severity": "low",
                "confidence": confidence,
                "notes": "mlp_model=benign_or_low_confidence",
            }

        severity = "medium" if best_label in {"path_traversal", "scanner_bot", "bruteforce"} else "high"
        return {
            "is_attack": 1,
            "attack_type": best_label,
            "severity": severity,
            "confidence": confidence,
            "notes": "mlp_model",
        }


adaptive_model = AdaptiveClassifier(MODEL_PATH)


def normalize_label(raw_label, payload):
    label = (raw_label or "").strip().lower().replace(" ", "_")
    mapping = {
        "sqli": "sqli",
        "sql_injection": "sqli",
        "xss_attack": "xss",
        "cmdi": "command_injection",
        "rce": "command_injection",
        "local_file_inclusion": "lfi",
        "remote_file_inclusion": "rfi",
        "server_side_request_forgery": "ssrf",
        "xml_external_entity": "xxe",
        "deser": "deserialization",
        "authbypass": "auth_bypass",
        "brute_force": "bruteforce",
        "webshell": "webshell_activity",
        "upload_abuse": "file_upload_abuse",
        "attack": "command_injection",
        "malicious": "command_injection",
        "normal": "benign",
    }
    label = mapping.get(label, label)
    if label in VALID_LABELS:
        return label

    inferred = infer_attack_type(payload)
    return inferred if inferred else "benign"


def infer_attack_type(payload):
    normalized = decode_payload(payload)
    for rule in ATTACK_RULES:
        if rule["name"] == "scanner_bot":
            continue
        if re.search(rule["regex"], normalized, flags=re.IGNORECASE):
            return rule["name"]
    return None


def decode_payload(payload):
    return unquote_plus((payload or "").strip()).lower()


def parse_uploaded_training(content, filename):
    samples = []
    ext = os.path.splitext(filename.lower())[1]

    if ext == ".csv":
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            label = row.get("label") or row.get("attack_type") or row.get("type") or row.get("class")
            method = (row.get("Metodo") or row.get("method") or "").strip().upper()
            request_body = (row.get("Cuerpo_Peticion") or "").strip()
            response_code = (row.get("Codigo_Respuesta") or "").strip()
            payload = row.get("payload") or row.get("request") or row.get("query") or row.get("raw") or row.get("message")
            if not payload and request_body:
                payload = f"{method} {request_body} status={response_code}".strip()
            if payload:
                normalized_label = normalize_label(label, payload) if label else infer_label_from_csv_payload(payload, response_code)
                samples.append((normalized_label, payload.strip()))
    else:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            if "\t" in line:
                label, payload = line.split("\t", 1)
            elif ";" in line:
                label, payload = line.split(";", 1)
            else:
                label, payload = "attack", line

            payload = payload.strip()
            if payload:
                samples.append((normalize_label(label, payload), payload))

    return samples


def infer_label_from_csv_payload(payload, response_code):
    inferred = infer_attack_type(payload)
    if inferred:
        return inferred

    if response_code and response_code.isdigit() and int(response_code) in {401, 403, 404, 405, 406, 429}:
        return "scanner_bot"
    return "command_injection"


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

    adaptive_model.load_persisted()
    if not adaptive_model.loaded and os.path.exists(TRAINING_FILE):
        with open(TRAINING_FILE, "r", encoding="utf-8", errors="ignore") as file_obj:
            samples = parse_uploaded_training(file_obj.read(), TRAINING_FILE)
        adaptive_model.train_from_samples(samples)


def detect_attack(features):
    best = None

    for rule in ATTACK_RULES:
        target_payload = " ".join(features.get(t, "") for t in rule["targets"])
        if re.search(rule["regex"], target_payload, flags=re.IGNORECASE):
            candidate = {
                "is_attack": 1,
                "attack_type": rule["name"],
                "severity": rule["severity"],
                "confidence": round(rule["confidence"], 2),
                "notes": f"rules={rule['name']}",
            }
            if not best:
                best = candidate
            else:
                current_weight = (SEVERITY_WEIGHT[best["severity"]], best["confidence"])
                candidate_weight = (SEVERITY_WEIGHT[candidate["severity"]], candidate["confidence"])
                if candidate_weight > current_weight:
                    best = candidate

    if best:
        return best

    ml_payload = " ".join([features.get("query", ""), features.get("body", ""), features.get("path", "")])
    learned = adaptive_model.predict(ml_payload)
    if learned:
        return learned

    return {
        "is_attack": 0,
        "attack_type": "benign",
        "severity": "low",
        "confidence": 0.0,
        "notes": "",
    }


def log_event(classification):
    db = get_db()
    headers_dump = "\n".join(f"{k}: {v}" for k, v in request.headers.items())
    cursor = db.execute(
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


@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({"ok": False, "error": "file_too_large", "max_bytes": app.config["MAX_CONTENT_LENGTH"]}), 413


@app.before_request
def global_logger():
    ignore_paths = {
        "/dashboard",
        "/dashboard/api/logs",
        "/dashboard/api/intel",
        "/dashboard/api/distribution",
        "/dashboard/api/candidates",
        "/dashboard/reload-training",
        "/dashboard/upload-ossec",
        "/dashboard/upload-theme",
        "/dashboard/restore-theme",
        "/dashboard/approve-candidate",
        "/dashboard/train-candidates",
        "/static/style.css",
    }
    if request.path not in ignore_paths:
        features = {
            "path": decode_payload(request.path),
            "query": decode_payload(request.query_string.decode("utf-8", errors="ignore")),
            "body": decode_payload(request.get_data(as_text=True)),
            "ua": decode_payload(request.headers.get("User-Agent", "")),
        }
        classification = detect_attack(features)
        log_event(classification)


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

    pending_candidates = db.execute(
        "SELECT COUNT(*) AS total FROM training_candidates WHERE status = 'pending'"
    ).fetchone()

    return render_template(
        "dashboard.html",
        stats=stats,
        top_types=[dict(x) for x in top_types],
        siem_hint=app.config["SIEM_HINT"],
        training_file=TRAINING_FILE,
        model_loaded=adaptive_model.loaded,
        model_samples=adaptive_model.samples_seen,
        max_upload_size=app.config["MAX_CONTENT_LENGTH"],
        custom_front_active=os.path.exists(custom_front_templates_dir()),
        custom_front_backup=backup_front_exists(),
        pending_candidates=pending_candidates["total"] if pending_candidates else 0,
    )


@app.route("/dashboard/reload-training", methods=["POST"])
@basic_auth_required
def reload_training():
    if not os.path.exists(TRAINING_FILE):
        return jsonify({"ok": False, "error": "training_file_not_found", "training_file": TRAINING_FILE}), 404

    with open(TRAINING_FILE, "r", encoding="utf-8", errors="ignore") as file_obj:
        samples = parse_uploaded_training(file_obj.read(), TRAINING_FILE)
    result = adaptive_model.train_from_samples(samples)
    status = 200 if result.get("ok") else 400
    result["training_file"] = TRAINING_FILE
    return jsonify(result), status


@app.route("/dashboard/upload-ossec", methods=["POST"])
@basic_auth_required
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
    if len(samples) < 25:
        return jsonify({"ok": False, "error": "dataset_insuficiente", "detail": "Se detectaron menos de 25 filas útiles."}), 400

    result = adaptive_model.train_from_samples(samples)
    if not result.get("ok"):
        return jsonify(result), 400

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
        }
    )


@app.route("/dashboard/upload-theme", methods=["POST"])
@basic_auth_required
def upload_theme_zip():
    upload = request.files.get("theme_zip")
    if not upload or not upload.filename:
        return jsonify({"ok": False, "error": "missing_file"}), 400

    safe_name = secure_filename(upload.filename)
    if not safe_name.lower().endswith(".zip"):
        return jsonify({"ok": False, "error": "invalid_extension", "allowed": [".zip"]}), 400

    uploaded_bytes = upload.stream.read()
    if len(uploaded_bytes) > app.config["MAX_CONTENT_LENGTH"]:
        return jsonify({"ok": False, "error": "file_too_large", "max_bytes": app.config["MAX_CONTENT_LENGTH"]}), 413

    result = store_theme_zip(uploaded_bytes)
    status = 200 if result.get("ok") else 400
    result["filename"] = safe_name
    result["custom_front_active"] = os.path.exists(custom_front_templates_dir())
    result["custom_front_backup"] = backup_front_exists()
    return jsonify(result), status


@app.route("/dashboard/restore-theme", methods=["POST"])
@basic_auth_required
def restore_theme():
    current_dir = os.path.join(CUSTOM_FRONT_DIR, "current")
    backup_dir = os.path.join(CUSTOM_FRONT_DIR, "backup")
    temp_dir = os.path.join(CUSTOM_FRONT_DIR, "restore_tmp")

    if not os.path.exists(backup_dir):
        return jsonify({"ok": False, "error": "backup_not_found"}), 404

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)
    if os.path.exists(current_dir):
        shutil.move(current_dir, temp_dir)
    shutil.move(backup_dir, current_dir)
    if os.path.exists(temp_dir):
        shutil.move(temp_dir, backup_dir)

    return jsonify(
        {
            "ok": True,
            "custom_front_active": os.path.exists(custom_front_templates_dir()),
            "custom_front_backup": backup_front_exists(),
        }
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


@app.route("/dashboard/api/distribution")
@basic_auth_required
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
    return jsonify([dict(row) for row in rows])


@app.route("/dashboard/api/candidates")
@basic_auth_required
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


@app.route("/dashboard/approve-candidate", methods=["POST"])
@basic_auth_required
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


@app.route("/dashboard/train-candidates", methods=["POST"])
@basic_auth_required
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
        db.execute("UPDATE training_candidates SET status = 'trained' WHERE status = 'approved'")
        db.commit()
    return jsonify(result), status


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000)
