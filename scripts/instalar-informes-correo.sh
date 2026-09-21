#!/usr/bin/env bash
# Usar el parche del paquete; conserva el app.py y Compose personalizados.
set -Eeuo pipefail
umask 077
DEPLOY_DIR=/home/adm0n/honeypot
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
PATCH="$SCRIPT_DIR/../informe-correo.patch"
ACCEPT_REPLAY=0
PREPARE_ONLY=0
BACKUP=''
STAGE=inicio
usage() {
  cat <<'HELP'
Uso: bash instalar-informes-correo.sh [--accept-log-replay] [--prepare-only]
       [--dir /home/adm0n/honeypot] [--patch /ruta/informe-correo.patch]

Respalda archivos, imagen, SQLite y configuración/clave de correo si existen.
Aplica el parche, construye web y worker, y activa ambos. Con lector activo o
desconocido, se detiene antes del recreate salvo que se use --accept-log-replay.
Esta opción acepta la posible relectura/duplicación del lector personalizado.
HELP
}
while (($#)); do
  case "$1" in
    --accept-log-replay) ACCEPT_REPLAY=1 ;;
    --prepare-only) PREPARE_ONLY=1 ;;
    --dir) [[ $# -ge 2 ]] || exit 2; DEPLOY_DIR=$2; shift ;;
    --patch) [[ $# -ge 2 ]] || exit 2; PATCH=$2; shift ;;
    --help|-h) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done
fail() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
trap 'code=$?; printf "Error en %s (codigo %s). Respaldo: %s. No se revierte ni restaura la base automaticamente.\n" "$STAGE" "$code" "$BACKUP" >&2; exit "$code"' ERR
[[ -s "$PATCH" ]] || fail 'Falta el parche del paquete. Extraiga el ZIP completo o use --patch.'
PATCH=$(cd -- "$(dirname -- "$PATCH")" && printf '%s/%s' "$PWD" "$(basename -- "$PATCH")")
for cmd in docker git tar flock sha256sum tee mktemp; do command -v "$cmd" >/dev/null || fail "Falta $cmd"; done
cd "$DEPLOY_DIR"
DEPLOY_DIR=$(pwd -P)
BASE_COMPOSE="$DEPLOY_DIR/docker-compose.prod.yml"
MAIL_COMPOSE="$DEPLOY_DIR/docker-compose.report-mail.yml"
COMPOSE=(docker compose -p honeypot -f "$BASE_COMPOSE")
MAIL=(docker compose -p honeypot -f "$BASE_COMPOSE" -f "$MAIL_COMPOSE")
exec 9>"${DEPLOY_DIR}.informe-v2.lock"
flock -n 9 || fail 'Otra actualización está en curso.'
STAGE=comprobar_despliegue
docker info >/dev/null
[[ $(docker inspect honeypot-web --format '{{.State.Running}}') == true ]] || fail 'El servicio web no está activo.'
[[ $(docker inspect honeypot-web --format '{{index .Config.Labels "com.docker.compose.project"}}') == honeypot ]] || fail 'Proyecto Compose inesperado.'
[[ $(docker inspect honeypot-web --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}') == "$BASE_COMPOSE" ]] || fail 'El contenedor utiliza otro Compose. Adapte el procedimiento.'
VOLUME=${REPORT_DATA_VOLUME:-honeypot_honeypot-data}
ACTIVE_VOLUME=$(docker inspect honeypot-web --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}')
[[ "$ACTIVE_VOLUME" == "$VOLUME" ]] || fail 'El volumen /data no coincide. Configure REPORT_DATA_VOLUME con el nombre real.'
docker volume inspect "$VOLUME" >/dev/null
"${COMPOSE[@]}" config --quiet

STAGE=respaldo
BACKUP=$(mktemp -d "$(dirname "$DEPLOY_DIR")/honeypot-respaldo-correo-$(date +%Y%m%d-%H%M%S)-XXXXXX")
exec > >(tee -a "$BACKUP/instalacion.log") 2>&1
echo "Respaldo: $BACKUP"
tar --exclude='./.git' -czf "$BACKUP/archivos.tgz" .
git diff --binary > "$BACKUP/cambios-locales.patch"
git diff --cached --binary > "$BACKUP/cambios-staged.patch"
IMAGE_TAG="honeypot-web:pre-correo-$(date +%Y%m%d-%H%M%S)-$$"
docker image tag "$(docker inspect honeypot-web --format '{{.Image}}')" "$IMAGE_TAG"
printf '%s\n' "$IMAGE_TAG" > "$BACKUP/imagen-anterior.txt"
PROTECTED=(docker-compose.prod.yml)
for file in .env .envn; do [[ ! -f "$file" ]] || PROTECTED+=("$file"); done
sha256sum "${PROTECTED[@]}" > "$BACKUP/protegidos.sha256"
BACKUP_TMP="/tmp/respaldo-correo-$(date +%Y%m%d-%H%M%S)-$$"
docker exec -i honeypot-web python - "$BACKUP_TMP" <<'PY'
import os, shutil, sqlite3, sys
from contextlib import closing
from pathlib import Path
os.umask(0o077)
target = Path(sys.argv[1]); target.mkdir(mode=0o700)
source = Path(os.environ.get('DB_PATH','/data/honeypot.db')).resolve()
def backup(src, dst):
    with closing(sqlite3.connect(src.as_uri()+'?mode=ro', uri=True)) as a:
        with closing(sqlite3.connect(dst)) as b:
            a.backup(b, pages=256, sleep=.1)
            if b.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
                raise RuntimeError('Copia SQLite no válida')
backup(source, target/'honeypot.db')
state = Path(os.environ.get('REPORT_MAIL_DIR',str(source.parent/'report-mail')))
if (state/'settings.sqlite3').exists():
    # BEGIN IMMEDIATE excludes configuration writers while the matching key
    # is copied. Read backup through a separate connection on the stable state.
    with closing(sqlite3.connect(state/'settings.sqlite3')) as lock:
        lock.execute('BEGIN IMMEDIATE')
        try:
            backup((state/'settings.sqlite3').resolve(), target/'report-mail-settings.sqlite3')
            if (state/'credentials.key').exists():
                shutil.copy2(state/'credentials.key', target/'report-mail-credentials.key')
        finally:
            lock.rollback()
print('Respaldos SQLite verificados.')
PY
docker cp "honeypot-web:$BACKUP_TMP/." "$BACKUP/"
[[ -s "$BACKUP/honeypot.db" ]] || fail 'El respaldo de eventos está vacío.'
printf 'services:\n  honeypot-web:\n    image: %s\n' "$IMAGE_TAG" > "$BACKUP/rollback-image.yml"
{
  printf '#!/usr/bin/env bash\nset -Eeuo pipefail\n'
  printf '# Recrear web puede provocar relectura en el lector personalizado.\n'
  printf 'cd %q\n' "$DEPLOY_DIR"
  printf 'docker stop honeypot-report-mail || true\n'
  printf 'docker compose -p honeypot -f %q -f %q up -d --no-deps --no-build --force-recreate honeypot-web\n' "$BASE_COMPOSE" "$BACKUP/rollback-image.yml"
  printf 'docker exec honeypot-nginx nginx -t && docker exec honeypot-nginx nginx -s reload\n'
} > "$BACKUP/revertir-imagen.sh"

STAGE=parche
cp "$PATCH" "$BACKUP/informe-correo.patch"
if git apply --check "$PATCH" >/dev/null 2>&1; then
  git apply "$PATCH"
elif git apply --reverse --check "$PATCH" >/dev/null 2>&1; then
  echo 'La actualización ya está aplicada.'
else
  fail 'El parche no encaja. Se conservan los archivos; revise sus personalizaciones antes de continuar.'
fi
sha256sum --check "$BACKUP/protegidos.sha256"
"${MAIL[@]}" config --quiet
STAGE=construccion
"${MAIL[@]}" build honeypot-web honeypot-report-mail
BUILT_IMAGE=$(docker image inspect honeypot-honeypot-web --format '{{.Id}}')
# Importar solo el módulo independiente: no arrancar Flask ni el lector.
docker run --rm --network none --entrypoint python "$BUILT_IMAGE" -c 'import report_mail; print("Módulo de correo disponible")'
if ((PREPARE_ONLY)); then echo "PREPARADO, sin reinicio. Respaldo: $BACKUP"; exit 0; fi
READER=$(docker exec honeypot-web python -c 'import os; print(os.getenv("ENABLE_LOG_AGENT","__UNSET__"))')
case "${READER,,}" in 0|false|no|off) RISK=0 ;; *) RISK=1 ;; esac
if ((RISK && !ACCEPT_REPLAY)); then
  echo 'PREPARADO, SIN REINICIAR (código 3). Para aceptar la posible relectura use --accept-log-replay.'
  exit 3
fi
STAGE=activar_web
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate honeypot-web
[[ $(docker inspect honeypot-web --format '{{.Image}}') == "$BUILT_IMAGE" ]] || fail 'El web no utiliza la imagen construida.'
docker exec -i honeypot-web python - <<'PY'
import time, urllib.request
for _ in range(30):
    try:
        with urllib.request.urlopen('http://127.0.0.1:8000/api/health',timeout=2) as r:
            if r.status == 200: break
    except Exception: pass
    time.sleep(1)
else: raise SystemExit('La API no está saludable; revise logs y la imagen de respaldo.')
from pathlib import Path
assert 'register_mail(app, dashboard_admin_required, DB_PATH)' in Path('/app/app.py').read_text()
assert Path('/app/templates/report_mail.html').is_file()
print('API y módulo de correo verificados.')
PY
docker exec honeypot-nginx nginx -t
docker exec honeypot-nginx nginx -s reload
STAGE=activar_worker
"${MAIL[@]}" up -d --no-deps --no-build --force-recreate honeypot-report-mail
"${MAIL[@]}" ps
echo 'INSTALADO. Abra Dashboard > Informes por correo como administrador.'
echo 'Configure la cuenta y destinatarios, envíe una prueba y después active el horario.'
echo "Respaldo y reversión: $BACKUP"
