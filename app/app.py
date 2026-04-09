import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime
from functools import wraps

from flask import Flask, Response, g, jsonify, redirect, render_template, request, session, url_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.getenv("DB_PATH", "/data/honeypot.db")
TRAINING_FILE = os.getenv("TRAINING_FILE", "/data/training_samples.txt")

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
        "targets": ["query", "body", "path"],
        "regex": r"(union\s+select|information_schema|sleep\s*\(|benchmark\s*\(|drop\s+table|insert\s+into|select\s+.+\s+from|(?:'|\")\s*or\s+\d+=\d+)",
    },
    {
        "name": "xss",
        "severity": "high",
        "confidence": 0.88,
        "targets": ["query", "body", "path"],
        "regex": r"(<script|javascript:|onerror=|onload=|<img\s+[^>]*onerror=|<svg\s+[^>]*onload=)",
    },
    {
        "name": "path_traversal",
        "severity": "medium",
        "confidence": 0.8,
        "targets": ["query", "path"],
        "regex": r"(\.\./|%2e%2e%2f|%252e%252e%252f|etc/passwd|boot.ini)",
    },
    {
        "name": "command_injection",
        "severity": "high",
        "confidence": 0.88,
        "targets": ["query", "body"],
        "regex": r"(;\s*(cat|ls|id|whoami|wget|curl)\b|\|\||&&|`[^`]+`|\$\([^)]+\))",
    },
    {
        "name": "scanner_bot",
        "severity": "medium",
        "confidence": 0.7,
        "targets": ["ua"],
        "regex": r"(sqlmap|nikto|nmap|masscan|acunetix|zap|nuclei|dirbuster)",
    },
]

SEVERITY_WEIGHT = {"low": 1, "medium": 2, "high": 3}


class AdaptiveClassifier:
    def __init__(self):
        self.label_token_counts = defaultdict(Counter)
        self.label_counts = Counter()
        self.loaded = False

    @staticmethod
    def _tokenize(text):
        return re.findall(r"[a-z0-9_\-]{2,}", text.lower())

    def load_examples(self, path):
        self.label_token_counts = defaultdict(Counter)
        self.label_counts = Counter()

        if not os.path.exists(path):
            self.loaded = False
            return

        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Formato esperado: label\tpayload
                if "\t" not in line:
                    continue
                label, payload = line.split("\t", 1)
                label = label.strip().lower()
                payload = payload.strip()
                if not label or not payload:
                    continue

                self.label_counts[label] += 1
                for token in self._tokenize(payload):
                    self.label_token_counts[label][token] += 1

        self.loaded = sum(self.label_counts.values()) > 0

    def predict(self, payload):
        if not self.loaded:
            return None

        tokens = self._tokenize(payload)
        if not tokens:
            return None

        label_scores = {}
        vocabulary = set()
        for c in self.label_token_counts.values():
            vocabulary.update(c.keys())
        v_size = max(len(vocabulary), 1)

        for label, token_counts in self.label_token_counts.items():
            total_tokens = sum(token_counts.values()) + v_size
            prior = self.label_counts[label] / max(sum(self.label_counts.values()), 1)
            score = prior
            for token in tokens:
                score *= (token_counts[token] + 1) / total_tokens
            label_scores[label] = score

        if not label_scores:
            return None

        best_label = max(label_scores, key=label_scores.get)
        total = sum(label_scores.values())
        confidence = round((label_scores[best_label] / total), 2) if total > 0 else 0.0

        if best_label == "benign":
            return {
                "is_attack": 0,
                "attack_type": "benign",
                "severity": "low",
                "confidence": confidence,
                "notes": "adaptive_model=benign",
            }

        severity = "medium" if best_label in {"xss", "path_traversal", "scanner_bot"} else "high"
        return {
            "is_attack": 1,
            "attack_type": best_label,
            "severity": severity,
            "confidence": confidence,
            "notes": "adaptive_model",
        }


adaptive_model = AdaptiveClassifier()


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

    adaptive_model.load_examples(TRAINING_FILE)


def detect_attack(features):
    matches = []
    max_confidence = 0.0
    severity = "low"

    for rule in ATTACK_RULES:
        target_payload = " ".join(features.get(t, "") for t in rule["targets"])
        if re.search(rule["regex"], target_payload, flags=re.IGNORECASE):
            matches.append(rule["name"])
            max_confidence = max(max_confidence, rule["confidence"])
            if SEVERITY_WEIGHT[rule["severity"]] > SEVERITY_WEIGHT[severity]:
                severity = rule["severity"]

    if matches:
        attack_type = ",".join(sorted(set(matches)))
        if len(matches) >= 2:
            max_confidence = min(0.98, max_confidence + 0.07)
        return {
            "is_attack": 1,
            "attack_type": attack_type,
            "severity": severity,
            "confidence": round(max_confidence, 2),
            "notes": f"rules={attack_type}",
        }

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
    ignore_paths = {
        "/dashboard",
        "/dashboard/api/logs",
        "/dashboard/api/intel",
        "/dashboard/api/distribution",
        "/dashboard/reload-training",
        "/static/style.css",
    }
    if request.path not in ignore_paths:
        features = {
            "path": request.path.lower(),
            "query": request.query_string.decode("utf-8", errors="ignore").lower(),
            "body": request.get_data(as_text=True).lower(),
            "ua": request.headers.get("User-Agent", "").lower(),
        }
        classification = detect_attack(features)
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
        training_file=TRAINING_FILE,
        model_loaded=adaptive_model.loaded,
    )


@app.route("/dashboard/reload-training", methods=["POST"])
@basic_auth_required
def reload_training():
    adaptive_model.load_examples(TRAINING_FILE)
    return jsonify({"ok": True, "model_loaded": adaptive_model.loaded, "training_file": TRAINING_FILE})


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


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8000)
