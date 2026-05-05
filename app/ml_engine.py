import csv
import io
import os
import re
from urllib.parse import unquote_plus

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import Pipeline

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
DEFAULT_BENIGN_SAMPLES = [
    "GET /",
    "GET /contacto",
    "GET /producto/crm",
    "POST /contacto nombre=juan email=demo@empresa.com",
    "GET /search?q=precios+planes",
    "GET /api/health",
]

ATTACK_LABEL_ES = {
    "xss": "XSS",
    "sqli": "Inyección SQL",
    "path_traversal": "Path Traversal",
    "command_injection": "Inyección de Comandos",
    "scanner_bot": "Escáner / Bot",
    "lfi": "Inclusión Local de Archivos (LFI)",
    "rfi": "Inclusión Remota de Archivos (RFI)",
    "ssrf": "SSRF",
    "xxe": "XXE",
    "deserialization": "Deserialización Insegura",
    "auth_bypass": "Bypass de Autenticación",
    "bruteforce": "Fuerza Bruta",
    "webshell_activity": "Actividad Webshell",
    "file_upload_abuse": "Abuso de Carga de Archivos",
    "benign": "Benigno",
}


class AdaptiveClassifier:
    def __init__(self, model_path):
        self.model_path = model_path
        self.pipeline = None
        self.labels = []
        self.loaded = False
        self.samples_seen = 0
        self.metrics = {}

    def load_persisted(self):
        if not os.path.exists(self.model_path):
            self.loaded = False
            return

        artifact = joblib.load(self.model_path)
        self.pipeline = artifact.get("pipeline")
        self.labels = artifact.get("labels", [])
        self.samples_seen = artifact.get("samples_seen", 0)
        self.metrics = artifact.get("metrics", {})
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
        preds = self.pipeline.predict(texts)
        report = classification_report(labels, preds, output_dict=True, zero_division=0)
        self.metrics = {
            label: {
                "precision": round(report.get(label, {}).get("precision", 0.0), 3),
                "recall": round(report.get(label, {}).get("recall", 0.0), 3),
                "f1": round(report.get(label, {}).get("f1-score", 0.0), 3),
                "support": int(report.get(label, {}).get("support", 0)),
            }
            for label in unique_labels
        }
        self.labels = sorted(unique_labels)
        self.samples_seen = len(texts)
        self.loaded = True

        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        joblib.dump(
            {
                "pipeline": self.pipeline,
                "labels": self.labels,
                "samples_seen": self.samples_seen,
                "metrics": self.metrics,
            },
            self.model_path,
        )
        return {"ok": True, "samples": self.samples_seen, "labels": self.labels, "metrics": self.metrics}

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


def infer_label_from_csv_payload(payload, response_code):
    inferred = infer_attack_type(payload)
    if inferred:
        return inferred

    if response_code and response_code.isdigit() and int(response_code) in {401, 403, 404, 405, 406, 429}:
        return "scanner_bot"
    return "command_injection"


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


def detect_attack(features, adaptive_model):
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
