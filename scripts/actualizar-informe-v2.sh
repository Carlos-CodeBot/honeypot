#!/usr/bin/env bash
# Actualizacion selectiva para dckcyber01. Ejecutar con Bash, no con sh.
set -Eeuo pipefail
umask 077

DEPLOY_DIR=/home/adm0n/honeypot
PROJECT=honeypot
WEB=honeypot-web
NGINX=honeypot-nginx
BASE=235aa874538c2c044b89d733ad64fa3ab194365a
TARGET=11c6a6737c1e716ecdaefe34ca5d1bf11cfa8fcb
PREVIOUS=5f795559a708ce9b755daa58b972f23aa2d3d8db
QUERY_TIMEOUT=120
ACCEPT_REPLAY=0
PREPARE_ONLY=0
BACKUP=''
STAGE=inicio

usage() {
    cat <<'HELP'
Uso: bash actualizar-informe-v2.sh [opciones]

  --prepare-only       Respalda, aplica, prueba y construye; no reinicia.
  --accept-log-replay   Permite recrear honeypot-web con el lector activo.
                       Puede releer logs e insertar eventos duplicados.
  --dir RUTA           Directorio de despliegue (por defecto /home/adm0n/honeypot).
  --query-timeout N    Tiempo para el PDF sobre la copia SQLite (1-600; 120).
  --help               Muestra esta ayuda.

Sin opciones despliega si el lector local esta deshabilitado. Si esta activo
o su estado es desconocido, prepara todo y termina con codigo 3 sin reiniciar.
Al activar, fuerza la recreacion, compara la imagen activa con la construida,
verifica la API y la plantilla, y valida/recarga Nginx.
No cambia app/app.py, Compose, .env, .envn, collector, el servidor publico ni
honeypot-log-puller. El parche se limita al generador y plantilla del informe.
Requiere Docker Compose v2, Git, Bash, tar, flock y acceso al repositorio.
HELP
}

while (($#)); do
    case "$1" in
        --prepare-only) PREPARE_ONLY=1 ;;
        --accept-log-replay) ACCEPT_REPLAY=1 ;;
        --dir) [[ $# -ge 2 ]] || { usage; exit 2; }; DEPLOY_DIR=$2; shift ;;
        --query-timeout) [[ $# -ge 2 ]] || { usage; exit 2; }; QUERY_TIMEOUT=$2; shift ;;
        --help|-h) usage; exit 0 ;;
        *) printf 'Opcion desconocida: %s\n' "$1" >&2; usage; exit 2 ;;
    esac
    shift
done
if [[ ! "$QUERY_TIMEOUT" =~ ^[1-9][0-9]{0,2}$ ]] || ((QUERY_TIMEOUT > 600)); then
    printf 'El tiempo debe ser un entero entre 1 y 600 segundos.\n' >&2
    exit 2
fi

fail() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }
on_error() {
    local status=$?
    printf '\nERROR en etapa "%s" (codigo %s). No se ejecutaran mas cambios.\n' "$STAGE" "$status" >&2
    [[ -z "$BACKUP" ]] || printf 'Respaldo y registro: %s\nNo se revierte automaticamente ni se restaura la base.\n' "$BACKUP" >&2
    exit "$status"
}
trap on_error ERR

for cmd in docker git tar flock sha256sum tee mktemp; do
    command -v "$cmd" >/dev/null || fail "Falta el comando $cmd."
done
cd "$DEPLOY_DIR"
DEPLOY_DIR=$(pwd -P)
COMPOSE_FILE="$DEPLOY_DIR/docker-compose.prod.yml"
[[ -f "$COMPOSE_FILE" && -f app/app.py ]] || fail 'No es el directorio de despliegue esperado.'
[[ ! -L app/executive_report.py && ! -L app/templates/dashboard.html ]] || fail 'Los archivos del informe no deben ser enlaces simbolicos.'

# El bloqueo vive fuera del repositorio y evita dos actualizaciones simultaneas.
exec 9>"${DEPLOY_DIR}.informe-v2.lock"
flock -n 9 || fail 'Ya hay otra actualizacion del informe en ejecucion.'

COMPOSE=(docker compose -p "$PROJECT" -f "$COMPOSE_FILE")
STAGE=verificacion
docker info >/dev/null
docker compose version >/dev/null
[[ $(docker inspect "$WEB" --format '{{.State.Running}}') == true ]] || fail 'honeypot-web no esta en ejecucion.'
[[ $(docker inspect "$WEB" --format '{{index .Config.Labels "com.docker.compose.project"}}') == "$PROJECT" ]] || fail 'El proyecto del contenedor no es honeypot.'
[[ $(docker inspect "$WEB" --format '{{index .Config.Labels "com.docker.compose.project.config_files"}}') == "$COMPOSE_FILE" ]] || fail 'El contenedor utiliza otros archivos Compose. Adapte el procedimiento antes de continuar.'
"${COMPOSE[@]}" config --quiet
git rev-parse --is-inside-work-tree >/dev/null

BACKUP=$(mktemp -d "$(dirname "$DEPLOY_DIR")/honeypot-respaldo-v2-$(date +%Y%m%d-%H%M%S)-XXXXXX")
exec > >(tee -a "$BACKUP/actualizacion.log") 2>&1
printf 'Directorio: %s\nRespaldo: %s\nVersion objetivo: %s\n' "$DEPLOY_DIR" "$BACKUP" "$TARGET"

STAGE=respaldo_archivos
tar --exclude='./.git' -czf "$BACKUP/archivos.tgz" .
git diff --binary > "$BACKUP/cambios-locales.patch"
git diff --cached --binary > "$BACKUP/cambios-staged.patch"
git status --short > "$BACKUP/estado-git.txt"
git rev-parse HEAD > "$BACKUP/head-original.txt"
OLD_IMAGE=$(docker inspect "$WEB" --format '{{.Image}}')
printf '%s\n' "$OLD_IMAGE" > "$BACKUP/imagen-original-id.txt"
IMAGE_TAG="honeypot-web:pre-informe-v2-$(date +%Y%m%d-%H%M%S)-$$"
docker image tag "$OLD_IMAGE" "$IMAGE_TAG"
printf '%s\n' "$IMAGE_TAG" > "$BACKUP/imagen-anterior.txt"
PROTECTED=(app/app.py docker-compose.prod.yml)
for file in .env .envn; do [[ ! -f "$file" ]] || PROTECTED+=("$file"); done
sha256sum "${PROTECTED[@]}" > "$BACKUP/archivos-protegidos.sha256"

STAGE=respaldo_sqlite
DB_TMP="/tmp/honeypot-informe-v2-backup-$(date +%Y%m%d-%H%M%S)-$$.db"
docker exec -i "$WEB" python - "$DB_TMP" <<'PY'
import os, sqlite3, sys
from pathlib import Path
source = Path(os.environ.get('DB_PATH', '/data/honeypot.db'))
src = sqlite3.connect(source.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
dst = sqlite3.connect(sys.argv[1])
try:
    src.backup(dst, pages=256, sleep=0.1)
    result = dst.execute('PRAGMA quick_check').fetchall()
    if result != [('ok',)]:
        raise RuntimeError('La copia SQLite no supera quick_check')
finally:
    dst.close()
    src.close()
print('Copia SQLite consistente y verificada.')
PY
docker cp "$WEB:$DB_TMP" "$BACKUP/honeypot.db"
[[ -s "$BACKUP/honeypot.db" ]] || fail 'El respaldo SQLite esta vacio.'

# Preparar instrucciones de retorno a la imagen anterior sin tocar los datos.
printf 'services:\n  honeypot-web:\n    image: %s\n' "$IMAGE_TAG" > "$BACKUP/rollback-image.yml"
{
    printf '#!/usr/bin/env bash\nset -Eeuo pipefail\n'
    printf '# Recrea el servicio: el lector activo tambien podria releer logs.\n'
    printf 'cd %q\n' "$DEPLOY_DIR"
    printf 'docker compose -p %q -f %q -f %q up -d --no-deps --no-build --force-recreate honeypot-web\n' "$PROJECT" "$COMPOSE_FILE" "$BACKUP/rollback-image.yml"
    printf 'docker exec honeypot-nginx nginx -t && docker exec honeypot-nginx nginx -s reload\n'
} > "$BACKUP/revertir-imagen.sh"

STAGE=descarga
git fetch origin "$TARGET"
git cat-file -e "${BASE}^{commit}"
git cat-file -e "${TARGET}^{commit}"
git diff --no-ext-diff --no-textconv --binary "$BASE" "$TARGET" -- \
    app/executive_report.py app/templates/dashboard.html > "$BACKUP/informe-v2.patch"
[[ -s "$BACKUP/informe-v2.patch" ]] || fail 'El parche esta vacio.'

STAGE=aplicar_parche
if git apply --check "$BACKUP/informe-v2.patch" >/dev/null 2>&1; then
    git apply "$BACKUP/informe-v2.patch"
    echo 'Actualizacion selectiva aplicada.'
elif git apply --reverse --check "$BACKUP/informe-v2.patch" >/dev/null 2>&1; then
    echo 'Los archivos ya tienen esta actualizacion; se conserva su contenido.'
else
    # Permite reanudar la version que ya aplico el parche y fallo en prueba_pdf.
    git diff --no-ext-diff --no-textconv --binary "$PREVIOUS" "$TARGET" -- \
        app/executive_report.py app/templates/dashboard.html > "$BACKUP/informe-v2-incremental.patch"
    [[ -s "$BACKUP/informe-v2-incremental.patch" ]] || fail 'No hay parche incremental disponible.'
    if git apply --check "$BACKUP/informe-v2-incremental.patch"; then
        git apply "$BACKUP/informe-v2-incremental.patch"
        echo 'Correccion incremental aplicada sobre la version v2 existente.'
    else
        fail "Los parches no encajan. No se forzo ni se reemplazo ningun archivo. Revise $BACKUP."
    fi
fi
sha256sum --check "$BACKUP/archivos-protegidos.sha256"

STAGE=prueba_pdf
REPORT_TMP="/tmp/executive-report-v2-$$.py"
PDF_TMP="/tmp/informe-v2-$$.pdf"
docker cp app/executive_report.py "$WEB:$REPORT_TMP"
docker exec "$WEB" python -m py_compile "$REPORT_TMP"
echo "Generando PDF sobre la copia SQLite verificada, con limite de ${QUERY_TIMEOUT}s."
docker exec "$WEB" python "$REPORT_TMP" --db "$DB_TMP" --output "$PDF_TMP" --query-timeout "$QUERY_TIMEOUT"
docker cp "$WEB:$PDF_TMP" "$BACKUP/informe-v2.pdf"
[[ -s "$BACKUP/informe-v2.pdf" ]] || fail 'No se genero el PDF de prueba.'

STAGE=construccion
"${COMPOSE[@]}" build honeypot-web
BUILT_IMAGE=$(docker image inspect "${PROJECT}-${WEB}" --format '{{.Id}}')
[[ -n "$BUILT_IMAGE" ]] || fail 'No se pudo identificar la imagen construida.'
printf 'Imagen construida: %s\n' "$BUILT_IMAGE"
sha256sum --check "$BACKUP/archivos-protegidos.sha256"

if ((PREPARE_ONLY)); then
    printf '\nPREPARADO. Sin reinicio. PDF: %s/informe-v2.pdf\n' "$BACKUP"
    exit 0
fi

# Se consulta la variable dentro del contenedor: un codigo de error o valor
# inesperado no se interpreta como lector desactivado.
STAGE=comprobar_lector
READER_STATE=$(docker exec "$WEB" python -c 'import os; print(os.getenv("ENABLE_LOG_AGENT", "__UNSET__"))')
case "${READER_STATE,,}" in
    0|false|no|off) READER_RISK=0 ;;
    *) READER_RISK=1 ;;
esac
if ((READER_RISK && !ACCEPT_REPLAY)); then
    printf '\nPREPARADO, SIN REINICIAR (codigo 3).\n'
    printf 'ENABLE_LOG_AGENT=%s. El lector local puede releer logs al arrancar.\n' "$READER_STATE"
    printf 'PDF disponible: %s/informe-v2.pdf\n' "$BACKUP"
    printf 'Para activar: corrija primero la persistencia del lector, o vuelva a ejecutar\n'
    printf 'este script con --accept-log-replay si acepta posibles eventos duplicados.\n'
    exit 3
fi
if ((READER_RISK)); then
    echo 'Se autorizo la recreacion con posible relectura mediante --accept-log-replay.'
fi

STAGE=activar
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate honeypot-web
STAGE=verificar_imagen
RUNNING_IMAGE=$(docker inspect "$WEB" --format '{{.Image}}')
printf 'Imagen en ejecucion: %s\n' "$RUNNING_IMAGE"
[[ "$RUNNING_IMAGE" == "$BUILT_IMAGE" ]] || fail "El contenedor no usa la imagen construida. Consulte $BACKUP/actualizacion.log."

STAGE=salud
docker exec -i "$WEB" python - <<'PY'
import time, urllib.request
for attempt in range(30):
    try:
        with urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2) as response:
            if response.status == 200:
                print('API interna saludable.')
                break
    except Exception:
        pass
    time.sleep(1)
else:
    raise SystemExit('La API no respondio correctamente; revise logs y el respaldo para revertir.')
PY
docker exec -i "$WEB" python - <<'PY'
from pathlib import Path
assert 'Informe para dirección' in Path('/app/templates/dashboard.html').read_text(encoding='utf-8')
assert 'class ReportCanvas:' in Path('/app/executive_report.py').read_text(encoding='utf-8')
assert '--query-timeout' in Path('/app/executive_report.py').read_text(encoding='utf-8')
print('Plantilla y generador nuevos presentes en el contenedor.')
PY

STAGE=nginx
docker exec "$NGINX" nginx -t
docker exec "$NGINX" nginx -s reload
"${COMPOSE[@]}" ps
printf '\nACTUALIZACION ACTIVADA.\nRespaldo y PDF de prueba: %s\n' "$BACKUP"
printf 'Entre al dashboard interno > Resumen > Descargar informe PDF.\n'
printf 'Compruebe que siguen llegando eventos; la salud HTTP no valida el flujo del recolector.\n'
printf 'Si necesita volver a la imagen anterior: bash %q\n' "$BACKUP/revertir-imagen.sh"
