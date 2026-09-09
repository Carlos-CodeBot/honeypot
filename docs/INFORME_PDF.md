# Actualización: informe ejecutivo PDF

Base: Carlos-CodeBot/honeypot, commit 384e99be379834b0c14b5a0239702d4b59aaf18b.
Este paquete es una actualización, no una copia completa del repositorio.

## Contenido y comportamiento
- Módulo app/executive_report.py; usa únicamente Python estándar en producción.
- Botón en Resumen del dashboard, protegido por la sesión y la activación actuales del dashboard.
- Período UTC de 1 a 90 días, 30 días por defecto; comparación con igual número de días previos.
- Eventos, detecciones, porcentaje, severidades, IP, rutas, evolución y acciones priorizadas.
- PDF sin servicios externos; lectura independiente mode=ro y query_only, sin crear tablas, índices ni archivos de base de datos.
- Presupuesto de consultas de aproximadamente 2 segundos, espera de bloqueo de 200 ms; una transacción consistente, cerrada antes de renderizar.
- Error 400 para fechas inválidas; 401 sin sesión; 404 si dashboard deshabilitado; 503 ante bloqueo, error SQLite o tiempo excedido.
- No cambia .env, Compose, Dockerfile, requirements, Nginx, agentes, ingesta, usuarios ni entrenamiento.
- Los caracteres fuera de Windows-1252 se representan como ?. Los valores de rankings se limitan a 180 caracteres; los grupos siguen siendo independientes aunque su texto abreviado coincida.
- Consultas de solo lectura también consumen CPU/E/S y pueden retrasar escrituras brevemente en SQLite sin WAL. No se promete impacto cero. En bases grandes, use una copia consistente fuera de producción; reducir fechas no evita necesariamente un recorrido completo porque no se añaden índices.
- No calcula riesgo empresarial ni confirma compromiso. Las limitaciones de cobertura y retención se explican en el informe.

## Opción A: generar PDF sin reiniciar el servicio
Recomendada para usar el informe inmediatamente con el honeypot activo.
Descomprima el paquete en una carpeta aparte. Desde esa carpeta, en el host Docker (Linux):
```sh
docker cp app/executive_report.py honeypot-web:/tmp/executive_report.py
docker exec honeypot-web sh -c 'python /tmp/executive_report.py --db "${DB_PATH:-/data/honeypot.db}" --start 2026-08-01 --end 2026-08-31 --output /tmp/informe-ejecutivo.pdf'
docker cp honeypot-web:/tmp/informe-ejecutivo.pdf ./informe-ejecutivo.pdf
```
Sustituya las fechas y el nombre del contenedor si su instalación usa otros. El archivo de /tmp no se conserva al recrear el contenedor. Esta opción no añade el botón al proceso web en ejecución.
También puede ejecutarlo con Python 3.12 sobre una copia consistente de la base:
```sh
python app/executive_report.py --db /ruta/copia-consistente.db --output informe.pdf
```
Use el mecanismo de backup de SQLite o una instantánea coordinada; no copie a ciegas una base activa, especialmente si utiliza WAL.

## Opción B: integrar el botón en el dashboard
1. Trabaje en el repositorio de despliegue. Mantenga el mismo directorio, proyecto Compose, archivos Compose y .env que utiliza actualmente. Conserve su copia de seguridad y la imagen anterior.
2. Compruebe la base y los cambios locales:
```sh
git rev-parse HEAD
git status --short
```
El SHA debe ser el indicado. Si hay cambios locales o commits posteriores, revise y adapte el parche antes de continuar: no sobrescriba personalizaciones.
3. Guarde el ZIP fuera del repositorio y aplique el parche (ajuste su ruta):
```sh
git apply --check /ruta/paquete/honeypot-executive-report.patch
git apply /ruta/paquete/honeypot-executive-report.patch
git diff --stat
```
El parche solo modifica app/app.py y app/templates/dashboard.html y añade módulo, pruebas y esta guía. No copie archivos de configuración.
4. Conserve la imagen del contenedor actual y construya mientras sigue atendiendo:
```sh
docker inspect --format '{{.Image}}' honeypot-web
docker image tag ID_OBTENIDO honeypot-web:pre-pdf
docker compose -f docker-compose.prod.yml build honeypot-web
```
ID_OBTENIDO es la salida del primer comando. Estos ejemplos asumen el Compose de producción del commit; use exactamente las opciones -f y -p de su despliegue actual.
5. En una ventana de mantenimiento:
```sh
docker compose -f docker-compose.prod.yml up -d --no-deps honeypot-web
```
Esto recrea únicamente el servicio web conservando su volumen. Puede interrumpir brevemente ingesta y dashboard; los agentes del commit no garantizan reenvío de todo evento fallido. Si no puede aceptar esa interrupción, use la opción A.
No use down -v ni elimine volúmenes. No vuelva a ejecutar el instalador inicial.
El arranque original ya sincroniza el administrador desde ADMIN_USER/ADMIN_PASS: conserve el entorno exacto para evitar cambios involuntarios de credenciales.
6. Verifique salud, ingesta, sesión y descarga:
```sh
docker compose -f docker-compose.prod.yml ps
docker logs --tail 50 honeypot-web
```
Compruebe /api/health por su URL habitual y que aumentan los eventos de sus agentes. Entre al dashboard > Resumen > Descargar informe PDF.
Si Nginx conserva la IP anterior y responde 502, valide y recargue su configuración con los comandos habituales de su instalación (en el contenedor del Compose base: docker exec honeypot-nginx nginx -t, seguido de docker exec honeypot-nginx nginx -s reload).
No se ha ejecutado este despliegue desde Codex.

## Reversión
La opción A no cambia el código del servicio; puede dejar de usar el módulo.
Para revertir la opción B sin cambios posteriores en los archivos afectados:
```sh
git apply --reverse --check /ruta/paquete/honeypot-executive-report.patch
git apply --reverse /ruta/paquete/honeypot-executive-report.patch
docker compose -f docker-compose.prod.yml build honeypot-web
docker compose -f docker-compose.prod.yml up -d --no-deps honeypot-web
```
Si falla la construcción, puede restaurar la imagen guardada usando un override temporal de Compose con image: honeypot-web:pre-pdf para honeypot-web y up -d --no-deps --no-build. Mantenga los mismos archivos base y nombre de proyecto. Verifique salud e ingesta de nuevo. Ninguna reversión requiere restaurar o eliminar los datos.

## Validación local
Python 3.12.10, Flask/Werkzeug 3.0.3, scikit-learn 1.5.2 y joblib 1.4.2.
Pruebas: cálculos, límites de fechas, comparación, PDF vacío y con texto malicioso, bytes de base sin cambios, base inexistente, bloqueo, presupuesto de consulta, autenticación y usuario inactivo, dashboard deshabilitado y respuesta de error.
Para reproducir en un entorno de pruebas con dependencias del proyecto:
```sh
python -m pip install pypdf==6.18.0
python -m unittest discover -s tests -v
```
pypdf es solo para pruebas y no se añade a requirements de producción.
El PDF de ejemplo usa exclusivamente datos sintéticos, no eventos reales.

