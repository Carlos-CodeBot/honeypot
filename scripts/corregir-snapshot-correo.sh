#!/usr/bin/env bash
# Actualización localizada: no reinicia web, Nginx ni el lector.
set -Eeuo pipefail
umask 077
DEPLOY_DIR=${1:-/home/adm0n/honeypot}
cd "$DEPLOY_DIR"
DEPLOY_DIR=$(pwd -P)
for cmd in docker git flock sha256sum mktemp; do command -v "$cmd" >/dev/null; done
exec 9>"${DEPLOY_DIR}.informe-v2.lock"
flock -n 9 || { echo 'Otra actualización está en curso.' >&2; exit 1; }
[[ -f app/report_mail.py && -f docker-compose.report-mail.yml ]]
[[ $(docker inspect honeypot-report-mail --format '{{.State.Running}}') == true ]]
[[ $(docker inspect honeypot-report-mail --format '{{index .Config.Labels "com.docker.compose.project"}}') == honeypot ]]
ACTIVE_VOLUME=$(docker inspect honeypot-report-mail --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}')
[[ -n "$ACTIVE_VOLUME" ]] || { echo 'Se esperaba un volumen nombrado en /data.' >&2; exit 1; }
export REPORT_DATA_VOLUME="$ACTIVE_VOLUME"
COMPOSE=(docker compose -p honeypot -f "$DEPLOY_DIR/docker-compose.prod.yml" -f "$DEPLOY_DIR/docker-compose.report-mail.yml")
"${COMPOSE[@]}" config --quiet
BACKUP=$(mktemp -d "$(dirname "$DEPLOY_DIR")/honeypot-respaldo-snapshot-XXXXXX")
trap 'rc=$?; echo "Se detuvo la actualización (código $rc). Respaldo: $BACKUP. No se restaura la base." >&2; exit "$rc"' ERR
echo "Respaldo del módulo e imagen: $BACKUP"
cp app/report_mail.py "$BACKUP/report_mail.py"
OLD_IMAGE=$(docker inspect honeypot-report-mail --format '{{.Image}}')
OLD_TAG="honeypot-report-mail:pre-snapshot-$(date +%Y%m%d-%H%M%S)-$$"
docker image tag "$OLD_IMAGE" "$OLD_TAG"
printf '%s\n' "$OLD_TAG" > "$BACKUP/imagen-anterior.txt"
PATCH_FILE="$BACKUP/correccion.patch"
cat > "$PATCH_FILE" <<'SNAPSHOT_PATCH'
diff --git a/app/report_mail.py b/app/report_mail.py
index fb3d368..53d0c8a 100644
--- a/app/report_mail.py
+++ b/app/report_mail.py
@@ -227,14 +227,30 @@ class Store:
                 db.execute("UPDATE jobs SET secret='' WHERE id=?", (job_id,))
 
 
+class SnapshotTimeout(TimeoutError):
+    """Safe, actionable error without provider or credential details."""
+
+
 def snapshot_report(store, job):
     with tempfile.TemporaryDirectory(prefix="pdf-", dir=store.directory) as directory:
         copy = Path(directory) / "events.db"
-        deadline = time.monotonic() + 60
-        def progress(*_):
-            if time.monotonic() > deadline:
-                raise TimeoutError("snapshot")
         with closing(sqlite3.connect(store.data_db.as_uri() + "?mode=ro", uri=True, timeout=2)) as source:
+            # Pin one read snapshot: otherwise commits on another connection can
+            # restart the incremental backup indefinitely on a busy honeypot.
+            # WAL permits concurrent commits. Rollback journals block commits,
+            # so keep their read-lock budget short rather than risking ingestion.
+            wal = source.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
+            budget = 60 if wal else 2
+            deadline = time.monotonic() + budget
+            def progress(*_):
+                if time.monotonic() > deadline:
+                    raise SnapshotTimeout(
+                        "La copia SQLite superó 60 s; revise tamaño, espacio y rendimiento del disco."
+                        if wal else
+                        "La copia SQLite superó 2 s en modo sin WAL. Se liberó la lectura para proteger la ingesta. Revise el tamaño y planifique WAL o una ventana de baja actividad."
+                    )
+            source.execute("BEGIN")
+            source.execute("SELECT name FROM sqlite_master LIMIT 1").fetchone()
             with closing(sqlite3.connect(copy)) as target:
                 source.backup(target, pages=256, progress=progress, sleep=.1)
         data = collect(copy, job["start"], job["end"], query_timeout=120)
@@ -315,6 +331,8 @@ def process_job(store, job):
         store.mark(job["id"], "partial" if partial else "accepted",
                    "Microsoft aceptó solo algunos destinatarios. No se reintenta automáticamente." if partial else
                    "Microsoft aceptó el mensaje. Esto no confirma su entrega final; revise posibles devoluciones.")
+    except SnapshotTimeout as exc:
+        store.mark(job["id"], "failed", str(exc))
     except smtplib.SMTPAuthenticationError:
         store.mark(job["id"], "failed", "Microsoft rechazó la autenticación SMTP. Verifique la contraseña y que SMTP AUTH esté habilitado, o use Graph.")
     except (smtplib.SMTPRecipientsRefused, smtplib.SMTPDataError):
SNAPSHOT_PATCH
if git apply --check "$PATCH_FILE"; then
  git apply "$PATCH_FILE"
elif git apply --reverse --check "$PATCH_FILE"; then
  echo 'El módulo ya tiene la corrección.'
else
  echo 'El módulo tiene otros cambios; no se ha sobrescrito.' >&2
  exit 1
fi
"${COMPOSE[@]}" build honeypot-report-mail
NEW_IMAGE=$(docker image inspect honeypot-report-mail:weekly --format '{{.Id}}')
echo 'Prueba de copia y PDF sobre el volumen real; no se enviará correo.'
docker run --rm -i --network none --volumes-from honeypot-report-mail --entrypoint python "$NEW_IMAGE" - <<'PY'
import os
from report_mail import Store, snapshot_report, report_week, now_utc
store = Store(os.environ.get('DB_PATH','/data/honeypot.db'))
start,end=report_week(now_utc(),store.status()['config'])
_,pdf=snapshot_report(store,{'start':start,'end':end})
print(f'OK: copia y PDF de {len(pdf)} bytes; período {start} / {end}.')
PY
# No interrumpir una entrega que ya se encuentre en curso.
docker exec honeypot-report-mail python -c 'from report_mail import Store; s=Store("/data/honeypot.db"); active=any(j["status"] in ("preparing","sending") for j in s.status()["jobs"]); raise SystemExit("Hay un envío en curso. Espere a que termine y repita el script." if active else 0)'
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate honeypot-report-mail
[[ $(docker inspect honeypot-report-mail --format '{{.Image}}') == "$NEW_IMAGE" ]]
EXPECTED_HASH=$(sha256sum app/report_mail.py | cut -d ' ' -f 1)
ACTUAL_HASH=$(docker exec honeypot-report-mail python -c 'from pathlib import Path; import hashlib; print(hashlib.sha256(Path("/app/report_mail.py").read_bytes()).hexdigest())')
[[ "$EXPECTED_HASH" == "$ACTUAL_HASH" ]]
echo 'CORREGIDO. Solo se recreó el servicio de correo. Solicite una prueba nueva desde el dashboard.'
echo "Respaldo: $BACKUP"
