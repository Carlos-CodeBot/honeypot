"""Weekly reports: encrypted settings, durable queue and independent worker.

Never import app.py here: that would start the site's custom log reader again.
"""
import argparse
import base64
from contextlib import closing
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime
import json
import os
from pathlib import Path
import re
import smtplib
import sqlite3
import ssl
import tempfile
import time
from urllib import request as urlrequest, parse as urlparse, error as urlerror
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from cryptography.fernet import Fernet, InvalidToken
from executive_report import collect, render_pdf

UTC = timezone.utc
DEFAULTS = dict(enabled=False, transport="smtp", sender="", recipients=[],
                weekday=0, hour="07:00", timezone="America/Bogota",
                tenant_id="", client_id="")
EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}\Z")
TERMINAL = {"accepted", "partial", "failed", "uncertain", "cancelled"}


def now_utc():
    return datetime.now(UTC)


def stamp(value=None):
    return (value or now_utc()).astimezone(UTC).isoformat(timespec="seconds")


def slot(config, now, future=True):
    """Weekly local wall time; normalize DST gaps forward, choose first fold."""
    zone = ZoneInfo(config["timezone"])
    local = now.astimezone(zone)
    day = local.date() + timedelta(days=config["weekday"] - local.weekday())
    hour, minute = map(int, config["hour"].split(":"))
    candidate = datetime(day.year, day.month, day.day, hour, minute, tzinfo=zone).astimezone(UTC)
    if future and candidate <= now:
        day += timedelta(days=7)
    elif not future and candidate > now:
        day -= timedelta(days=7)
    return datetime(day.year, day.month, day.day, hour, minute, tzinfo=zone).astimezone(UTC)


def report_week(occurrence, config):
    # Reports currently use whole UTC days. Scheduling has a separate timezone.
    day = occurrence.astimezone(ZoneInfo(config["timezone"])).date()
    monday = day - timedelta(days=day.weekday())
    return str(monday - timedelta(days=7)), str(monday - timedelta(days=1))


def validate(payload):
    if not isinstance(payload, dict):
        raise ValueError("La configuración debe ser un objeto JSON.")
    if set(payload) - (set(DEFAULTS) | {"password", "client_secret"}):
        raise ValueError("La configuración contiene campos desconocidos.")
    config = dict(DEFAULTS, **{k: v for k, v in payload.items() if k in DEFAULTS})
    if type(config["enabled"]) is not bool or config["transport"] not in ("smtp", "graph"):
        raise ValueError("Seleccione un método de envío válido.")
    for field in ("sender", "hour", "timezone", "tenant_id", "client_id"):
        if not isinstance(config[field], str) or len(config[field]) > 254:
            raise ValueError("Formato de configuración no válido.")
        config[field] = config[field].strip()
    if not EMAIL.fullmatch(config["sender"]) or len(config["sender"]) > 254:
        raise ValueError("Introduzca un correo remitente válido, sin nombre ni saltos de línea.")
    recipients = config["recipients"]
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= 20:
        raise ValueError("Configure entre 1 y 20 destinatarios.")
    if any(not isinstance(x, str) or len(x) > 254 or not EMAIL.fullmatch(x) for x in recipients):
        raise ValueError("Hay un destinatario no válido.")
    config["recipients"] = list(dict.fromkeys(recipients))
    if type(config["weekday"]) is not int or not 0 <= config["weekday"] <= 6:
        raise ValueError("El día debe estar entre lunes y domingo.")
    if not re.fullmatch(r"(?:[01]\d|2[0-3]):[0-5]\d", config["hour"]):
        raise ValueError("Use una hora válida HH:MM.")
    try:
        ZoneInfo(config["timezone"])
    except (ZoneInfoNotFoundError, ValueError):
        raise ValueError("Zona horaria no válida.") from None
    if config["transport"] == "graph":
        try:
            for key in ("tenant_id", "client_id"):
                config[key] = str(uuid.UUID(config[key]))
        except ValueError:
            raise ValueError("Tenant ID y Client ID deben ser UUID válidos.") from None
    for key in ("password", "client_secret"):
        if key in payload and (not isinstance(payload[key], str) or len(payload[key]) > 4096 or "\x00" in payload[key]):
            raise ValueError("La credencial no tiene un formato válido.")
    return config


class Store:
    def __init__(self, data_db):
        self.data_db = Path(data_db).resolve()
        self.directory = Path(os.getenv("REPORT_MAIL_DIR", str(self.data_db.parent / "report-mail")))
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.directory / "settings.sqlite3"
        self.key_path = self.directory / "credentials.key"
        with closing(self.connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS settings(id INTEGER PRIMARY KEY CHECK(id=1),
                  payload TEXT NOT NULL, secret TEXT NOT NULL, next_due TEXT, updated TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, dedup TEXT UNIQUE,
                  kind TEXT NOT NULL, start TEXT NOT NULL, end TEXT NOT NULL, payload TEXT NOT NULL,
                  secret TEXT NOT NULL, status TEXT NOT NULL, created TEXT NOT NULL, started TEXT,
                  finished TEXT, detail TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS worker(id INTEGER PRIMARY KEY CHECK(id=1), heartbeat TEXT NOT NULL);
            """)
        if os.name != "nt":
            self.directory.chmod(0o700)
            self.path.chmod(0o600)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        return db

    def cipher(self, create=False):
        if create and not self.key_path.exists():
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(Fernet.generate_key())
        return Fernet(self.key_path.read_bytes())

    def secrets(self, encrypted):
        return json.loads(self.cipher().decrypt(encrypted.encode())) if encrypted else {}

    def save(self, payload, now=None):
        now = now or now_utc()
        config = validate(payload)
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT * FROM settings WHERE id=1").fetchone()
            credentials = self.secrets(old["secret"]) if old else {}
            for key in ("password", "client_secret"):
                if payload.get(key):
                    credentials[key] = payload[key]
            required = "password" if config["transport"] == "smtp" else "client_secret"
            if not credentials.get(required):
                raise ValueError("Introduzca la contraseña o el secreto de la aplicación antes de guardar.")
            old_config = json.loads(old["payload"]) if old else {}
            schedule_changed = any(old_config.get(k) != config[k] for k in ("enabled", "weekday", "hour", "timezone"))
            next_due = (stamp(slot(config, now)) if schedule_changed or not old else old["next_due"]) if config["enabled"] else None
            encrypted = self.cipher(create=True).encrypt(json.dumps(credentials).encode()).decode()
            db.execute("INSERT OR REPLACE INTO settings VALUES (1,?,?,?,?)",
                       (json.dumps(config), encrypted, next_due, stamp(now)))
            # A saved change supersedes queued work; never silently send to old recipients.
            db.execute("UPDATE jobs SET status='cancelled', secret='', finished=?, detail='Configuración modificada antes del envío.' WHERE status='queued'", (stamp(now),))

    def status(self):
        with closing(self.connect()) as db:
            row = db.execute("SELECT * FROM settings WHERE id=1").fetchone()
            jobs = [dict(r) for r in db.execute("SELECT id,kind,start,end,status,created,started,finished,detail FROM jobs ORDER BY created DESC, rowid DESC LIMIT 20")]
            worker = db.execute("SELECT heartbeat FROM worker WHERE id=1").fetchone()
        config = json.loads(row["payload"]) if row else dict(DEFAULTS)
        # The API never decrypts or returns credentials on GET.
        return {"config": config, "has_credentials": bool(row and row["secret"]),
                "next_due": row["next_due"] if row else None, "jobs": jobs,
                "worker_heartbeat": worker[0] if worker else None}

    def enqueue(self, kind, now=None):
        if kind not in ("test", "manual"):
            raise ValueError("Tipo de envío no válido.")
        now = now or now_utc()
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM settings WHERE id=1").fetchone()
            if not row:
                raise ValueError("Guarde primero la configuración.")
            worker = db.execute("SELECT heartbeat FROM worker WHERE id=1").fetchone()
            if not worker or (now - datetime.fromisoformat(worker[0])).total_seconds() > 600:
                raise ValueError("El servicio de correo no está activo. Inicie honeypot-report-mail.")
            if db.execute("SELECT 1 FROM jobs WHERE status IN ('queued','preparing','sending') LIMIT 1").fetchone():
                raise ValueError("Ya hay un envío pendiente o en curso. Espere a que termine.")
            latest = db.execute("SELECT created FROM jobs ORDER BY created DESC LIMIT 1").fetchone()
            if latest and (now - datetime.fromisoformat(latest[0])).total_seconds() < 60:
                raise ValueError("Espere un minuto antes de solicitar otro envío.")
            start, end = report_week(now, json.loads(row["payload"]))
            return self.insert_job(db, kind, start, end, row, now)

    @staticmethod
    def insert_job(db, kind, start, end, settings, now, dedup=None):
        job_id = str(uuid.uuid4())
        db.execute("INSERT OR IGNORE INTO jobs(id,dedup,kind,start,end,payload,secret,status,created) VALUES (?,?,?,?,?,?,?,'queued',?)",
                   (job_id, dedup, kind, start, end, settings["payload"], settings["secret"], stamp(now)))
        return job_id

    def tick(self, now=None):
        now = now or now_utc()
        with closing(self.connect()) as db, db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT OR REPLACE INTO worker VALUES (1,?)", (stamp(now),))
            stale = stamp(now - timedelta(minutes=15))
            db.execute("UPDATE jobs SET status='failed', secret='', finished=?, detail='El proceso se interrumpió antes del envío. Puede solicitar otro informe.' WHERE status='preparing' AND started < ?", (stamp(now), stale))
            db.execute("UPDATE jobs SET status='uncertain', secret='', finished=?, detail='Proceso interrumpido durante el envío; confirme en Microsoft antes de repetir.' WHERE status='sending' AND started < ?", (stamp(now), stale))
            settings = db.execute("SELECT * FROM settings WHERE id=1").fetchone()
            if settings and settings["next_due"] and settings["next_due"] <= stamp(now):
                config = json.loads(settings["payload"])
                start, end = report_week(slot(config, now, future=False), config)
                self.insert_job(db, "weekly", start, end, settings, now, "weekly:" + start)
                db.execute("UPDATE settings SET next_due=? WHERE id=1", (stamp(slot(config, now)),))
            if db.execute("SELECT 1 FROM jobs WHERE status IN ('preparing','sending') LIMIT 1").fetchone():
                return None
            job = db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created,rowid LIMIT 1").fetchone()
            if job:
                db.execute("UPDATE jobs SET status='preparing',started=? WHERE id=?", (stamp(now), job["id"]))
                return dict(job)
        return None

    def mark(self, job_id, state, detail=""):
        with closing(self.connect()) as db, db:
            db.execute("UPDATE jobs SET status=?,detail=?,finished=? WHERE id=?",
                       (state, detail, stamp() if state in TERMINAL else None, job_id))
            if state in TERMINAL:
                db.execute("UPDATE jobs SET secret='' WHERE id=?", (job_id,))


class SnapshotTimeout(TimeoutError):
    """Safe, actionable error without provider or credential details."""


def snapshot_report(store, job):
    with tempfile.TemporaryDirectory(prefix="pdf-", dir=store.directory) as directory:
        copy = Path(directory) / "events.db"
        with closing(sqlite3.connect(store.data_db.as_uri() + "?mode=ro", uri=True, timeout=2)) as source:
            # Pin one read snapshot: otherwise commits on another connection can
            # restart the incremental backup indefinitely on a busy honeypot.
            # WAL permits concurrent commits. Rollback journals block commits,
            # so keep their read-lock budget short rather than risking ingestion.
            wal = source.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
            budget = 60 if wal else 2
            deadline = time.monotonic() + budget
            def progress(*_):
                if time.monotonic() > deadline:
                    raise SnapshotTimeout(
                        "La copia SQLite superó 60 s; revise tamaño, espacio y rendimiento del disco."
                        if wal else
                        "La copia SQLite superó 2 s en modo sin WAL. Se liberó la lectura para proteger la ingesta. Revise el tamaño y planifique WAL o una ventana de baja actividad."
                    )
            source.execute("BEGIN")
            source.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
            with closing(sqlite3.connect(copy)) as target:
                source.backup(target, pages=256, progress=progress, sleep=.1)
        data = collect(copy, job["start"], job["end"], query_timeout=120)
        pdf = render_pdf(data)
        if len(pdf) > 2 * 1024 * 1024:
            raise ValueError("attachment_size")
        return data, pdf


class NoRedirect(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def graph_json(url, data, headers):
    opener = urlrequest.build_opener(NoRedirect())
    request = urlrequest.Request(url, data=data, headers=headers, method="POST")
    with opener.open(request, timeout=30) as response:
        return response.status, response.read(1024 * 1024)


def deliver(config, credentials, job, summary, pdf, sending):
    prefix = "[PRUEBA] " if job["kind"] == "test" else ""
    subject = f"{prefix}Honeypot | Informe semanal | {job['start']} a {job['end']}"
    body = (f"Informe ejecutivo del período {job['start']} a {job['end']} (UTC).\n\n"
            f"Eventos: {summary['total']:,}\nAtaques detectados: {summary['attacks']:,}\n"
            f"IP con ataques: {summary['ips']:,}\nSeveridad alta/crítica: {summary['urgent']:,}\n\n"
            "El PDF adjunto incluye rankings, evidencia y confianza. Las detecciones no confirman una intrusión exitosa.\n"
            f"Referencia de envío: {job['id']}")
    filename = f"honeypot-{job['start']}-{job['end']}.pdf"
    if config["transport"] == "smtp":
        message = EmailMessage()
        message["From"] = config["sender"]
        message["To"] = ", ".join(config["recipients"])
        message["Subject"] = subject
        message["Date"] = format_datetime(now_utc())
        message["Message-ID"] = f"<{job['id']}@{config['sender'].split('@')[1]}>"
        message.set_content(body)
        message.add_attachment(pdf, maintype="application", subtype="pdf", filename=filename)
        # Fixed Microsoft endpoint: credentials cannot be redirected to arbitrary hosts.
        with smtplib.SMTP("smtp.office365.com", 587, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            smtp.login(config["sender"], credentials["password"])
            sending()
            refused = smtp.send_message(message)
            return bool(refused)
    token_data = urlparse.urlencode({"grant_type": "client_credentials", "client_id": config["client_id"],
                                    "client_secret": credentials["client_secret"], "scope": "https://graph.microsoft.com/.default"}).encode()
    _, response = graph_json(f"https://login.microsoftonline.com/{config['tenant_id']}/oauth2/v2.0/token", token_data,
                             {"Content-Type": "application/x-www-form-urlencoded"})
    token = json.loads(response)["access_token"]
    message = {"subject": subject, "body": {"contentType": "Text", "content": body},
               "toRecipients": [{"emailAddress": {"address": address}} for address in config["recipients"]],
               "attachments": [{"@odata.type": "#microsoft.graph.fileAttachment", "name": filename,
                                "contentType": "application/pdf", "contentBytes": base64.b64encode(pdf).decode()}]}
    sending()
    status, _ = graph_json("https://graph.microsoft.com/v1.0/users/" + urlparse.quote(config["sender"], safe="") + "/sendMail",
                           json.dumps({"message": message, "saveToSentItems": True}).encode(),
                           {"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    if status != 202:
        raise RuntimeError("unexpected_response")
    return False


def process_job(store, job):
    in_flight = False
    def sending():
        nonlocal in_flight
        store.mark(job["id"], "sending")
        in_flight = True
    try:
        config = json.loads(job["payload"])
        credentials = store.secrets(job["secret"])
        data, pdf = snapshot_report(store, job)
        partial = deliver(config, credentials, job, data, pdf, sending)
        store.mark(job["id"], "partial" if partial else "accepted",
                   "Microsoft aceptó solo algunos destinatarios. No se reintenta automáticamente." if partial else
                   "Microsoft aceptó el mensaje. Esto no confirma su entrega final; revise posibles devoluciones.")
    except SnapshotTimeout as exc:
        store.mark(job["id"], "failed", str(exc))
    except smtplib.SMTPAuthenticationError:
        store.mark(job["id"], "failed", "Microsoft rechazó la autenticación SMTP. Verifique la contraseña y que SMTP AUTH esté habilitado, o use Graph.")
    except (smtplib.SMTPRecipientsRefused, smtplib.SMTPDataError):
        store.mark(job["id"], "failed", "Microsoft rechazó destinatarios o contenido. Revise el buzón y sus permisos antes de repetir.")
    except urlerror.HTTPError as exc:
        # Do not persist provider response bodies: they can contain sensitive data.
        state = "uncertain" if in_flight and exc.code >= 500 else "failed"
        store.mark(job["id"], state, f"Microsoft Graph respondió HTTP {exc.code}. Revise permisos, credencial y buzón. No se reintentó automáticamente.")
    except (InvalidToken, FileNotFoundError):
        store.mark(job["id"], "failed", "No se pudo abrir la base o descifrar la credencial. Revise el volumen y la clave persistente.")
    except Exception:
        store.mark(job["id"], "uncertain" if in_flight else "failed",
                   "Respuesta de envío incierta. Compruebe el buzón antes de repetir." if in_flight else
                   "Falló la preparación o conexión segura. Revise base, tiempo de consulta, conectividad TLS y configuración.")


def register_mail(app, admin_required, data_db):
    import secrets
    from flask import jsonify, request, session
    def store():
        return Store(data_db)
    def csrf():
        token = session.get("report_mail_csrf", "")
        return bool(token) and secrets.compare_digest(token, request.headers.get("X-CSRF-Token", ""))
    @app.route("/dashboard/api/report-mail", methods=["GET", "POST"])
    @admin_required
    def report_mail_settings():
        try:
            if request.method == "POST":
                if not csrf():
                    return jsonify(ok=False, error="La sesión del formulario venció. Recargue la página."), 403
                if len(request.get_data()) > 32768:
                    return jsonify(ok=False, error="Configuración demasiado grande."), 413
                store().save(request.get_json(silent=True))
            token = session.setdefault("report_mail_csrf", secrets.token_urlsafe(32))
            response = jsonify(ok=True, csrf=token, **store().status())
            response.headers["Cache-Control"] = "no-store"
            return response
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        except Exception:
            return jsonify(ok=False, error="No se pudo acceder a la configuración cifrada. Revise el volumen y su clave."), 503

    @app.post("/dashboard/api/report-mail/send")
    @admin_required
    def report_mail_send():
        if not csrf():
            return jsonify(ok=False, error="La sesión del formulario venció. Recargue la página."), 403
        try:
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict):
                raise ValueError("Solicitud no válida.")
            job_id = store().enqueue(payload.get("kind"))
            return jsonify(ok=True, job_id=job_id), 202
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)), 400
        except Exception:
            return jsonify(ok=False, error="No se pudo registrar el envío."), 503


def main():
    parser = argparse.ArgumentParser(description="Servicio independiente de informes semanales.")
    parser.add_argument("--db", default=os.getenv("DB_PATH", "/data/honeypot.db"))
    parser.add_argument("--once", action="store_true", help="Procesar como máximo un trabajo y salir.")
    args = parser.parse_args()
    os.umask(0o077)
    store = Store(args.db)
    while True:
        try:
            job = store.tick()
            if job:
                process_job(store, job)
        except Exception:
            # Deliberately no exception text, settings or provider bodies in logs.
            print("report_mail_worker: error de almacenamiento; se reintentará la consulta.", flush=True)
            if args.once:
                raise SystemExit(1)
        if args.once:
            return
        time.sleep(15)


if __name__ == "__main__":
    main()
