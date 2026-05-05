# Honeypot Web (Docker)

Honeypot web educativo para capturar, **clasificar** y analizar intentos de ataque HTTP desde un dashboard SOC.

> ⚠️ **Solo laboratorio/entorno aislado**. Incluye vulnerabilidades intencionales para atraer tráfico malicioso.

## Qué trae esta versión

- Frontend más realista y personalizable (landing tipo SaaS, módulos de producto, formulario de contacto, login de clientes).
- Endpoints con debilidades intencionales (XSS reflejado y login inseguro) para observación de ataques.
- Motor de clasificación por reglas, ajustado para reducir falsos positivos y **priorizar XSS correctamente** frente a SQLi cuando corresponde.
- Clasificador adaptativo con **red neuronal MLP** (`scikit-learn`) entrenable desde dashboard.
- Carga segura de dataset (`.txt` / `.csv`) para entrenar con salidas de OSSEC/filtro.
- Integración con script de filtro OSSEC (`app/filtro/ossec_filter.py`) para transformar `.txt` a CSV de entrenamiento.
- Gráfica tipo torta (pie chart) con distribución de ataques.
- Dashboard con métricas, tabla de eventos e inteligencia por IP.
- Docker + Docker Compose para despliegue rápido.

## Instalación

```bash
cp .env.example .env
docker compose up -d --build --force-recreate
```

- Sitio público: `http://localhost:8000`
- Dashboard SOC: `http://localhost:8000/dashboard`

Credenciales dashboard por defecto:

- Usuario: `admin`
- Contraseña: `admin123`

## Personalización

En `.env` puedes ajustar:

- `SITE_TITLE`
- `SITE_SUBTITLE`
- `HERO_TAGLINE`
- `THEME_COLOR`
- `ADMIN_USER`
- `ADMIN_PASS`
- `SIEM_HINT`
- `TRAINING_FILE`
- `MODEL_PATH`
- `MAX_UPLOAD_SIZE`
- `FILTER_SCRIPT`
- `ENABLE_PUBLIC_SITE` (1/0, habilita solo sitio público)
- `ENABLE_DASHBOARD` (1/0, habilita solo panel SOC)
- `FORWARD_LOG_URL` (URL del server dashboard para reenviar eventos)
- `FORWARD_LOG_TOKEN` (token que envía el server público)
- `INGEST_TOKEN` (token esperado por `/api/ingest-event`)
- `INGEST_HMAC_SECRET` (firma HMAC SHA-256 opcional/ recomendada para ingesta)
- `INGEST_MAX_SKEW_SECONDS` (ventana anti-replay para timestamp)

## Arquitectura Agent/Server (recomendada)

Nuevo modelo para 2 servidores:

- **Agente (server front):** no expone dashboard. Toma líneas de `nginx access.log` y las envía al server SOC.
- **Server (dashboard):** recibe eventos por `/api/ingest-event`, aplica validaciones de token, timestamp, tamaño y firma HMAC.

Configuración sugerida:

- **Agente/front:**
  - `ENABLE_PUBLIC_SITE=1`
  - `ENABLE_DASHBOARD=0`
  - `FORWARD_LOG_URL=https://dashboard.tu-dominio/api/ingest-event`
  - `FORWARD_LOG_TOKEN=<token-fuerte>`
  - `INGEST_HMAC_SECRET=<secreto-largo>`
- **Server/dashboard:**
  - `ENABLE_PUBLIC_SITE=0`
  - `ENABLE_DASHBOARD=1`
  - `INGEST_TOKEN=<token-fuerte>`
  - `INGEST_HMAC_SECRET=<secreto-largo>`

### Agente de logs Nginx

Se incluye `app/agent_nginx_forwarder.py` para enviar logs de Nginx al dashboard:

```bash
python app/agent_nginx_forwarder.py   --log /var/log/nginx/access.log   --url https://dashboard.tu-dominio/api/ingest-event   --token "$INGEST_TOKEN"   --hmac-secret "$INGEST_HMAC_SECRET"
```

## Separar sitio vulnerable y dashboard en servidores distintos

Puedes desplegar en 2 hosts para segmentar riesgo:

- **Server A (público/honeypot):**
  - `ENABLE_PUBLIC_SITE=1`
  - `ENABLE_DASHBOARD=0`
  - `FORWARD_LOG_URL=https://dashboard.tu-dominio/api/ingest-event`
  - `FORWARD_LOG_TOKEN=<token-compartido>`
- **Server B (dashboard/SOC):**
  - `ENABLE_PUBLIC_SITE=0`
  - `ENABLE_DASHBOARD=1`
  - `INGEST_TOKEN=<mismo-token-compartido>`

Con esto, el tráfico real se clasifica en el server público y se reenvía al server dashboard para análisis, sin exponer el panel SOC en el host vulnerable.

## Despliegue recomendado con Nginx (producción)

Este repo incluye `docker-compose.prod.yml` + `nginx/default.conf` para desplegar:

- Flask servido por **Gunicorn** (no servidor dev).
- Reverse proxy con **Nginx**.
- Volumen persistente `/data`.
- Headers `X-Forwarded-*` compatibles con `ProxyFix`.

Comandos:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

## Endpoints relevantes

- `/` landing corporativa
- `/producto/<slug>` páginas de producto
- `/contacto` formulario comercial
- `/login` login intencionalmente débil
- `/internal` área interna simulada
- `/search?q=...` vulnerable a XSS reflejado (intencional)
- `/dashboard` panel SOC
- `/dashboard/login` acceso al panel
- `/dashboard/logout` cerrar sesión
- `/dashboard/upload-ossec` subida segura de dataset para entrenar
- `/dashboard/api/candidates` lista candidatos de entrenamiento desde tráfico real
- `/dashboard/approve-candidate` aprueba/etiqueta candidato
- `/dashboard/reject-candidate` rechaza candidato
- `/dashboard/train-candidates` entrena modelo con candidatos aprobados
- `/dashboard/api/users` gestión de usuarios del panel (admin)
- `/dashboard/reload-training` recarga entrenamiento desde `TRAINING_FILE`
- `/dashboard/api/logs?only_attacks=1` logs clasificados
- `/dashboard/api/intel` ranking por IP
- `/dashboard/api/distribution` distribución para gráfica
- `/dashboard/api/model-health` distribución de confianza del clasificador
- `/dashboard/api/model-metrics` métricas de entrenamiento por clase (precisión/recall/F1)
- `/dashboard/api/country-stats` países con mayor volumen de ataques
- `/dashboard/export-wazuh` exporta `.log` listo para ingesta en Wazuh

## Formatos de dataset para entrenamiento

Etiquetas soportadas actualmente:

`xss`, `sqli`, `path_traversal`, `command_injection`, `scanner_bot`, `lfi`, `rfi`, `ssrf`, `xxe`, `deserialization`, `auth_bypass`, `bruteforce`, `webshell_activity`, `file_upload_abuse`, `benign`.

### TXT (recomendado)

```txt
xss	<script>alert(1)</script>
sqli	1' OR 1=1 --
benign	consulta normal de producto
```

Si subes un `.txt` de OSSEC, el backend primero ejecuta el script configurado en `FILTER_SCRIPT` (por defecto `app/filtro/ossec_filter.py`) para generar un CSV intermedio (`label,payload`) y entrenar el modelo con ese resultado.
El filtro está adaptado al formato de tu script y genera columnas: `Metodo,Cuerpo_Peticion,Codigo_Respuesta`. El backend transforma esas filas a texto de entrenamiento y les infiere una etiqueta de ataque automáticamente.

### CSV

Se recomiendan columnas:

- `label`
- `payload`

También se intentan mapear nombres alternativos como `attack_type`, `type`, `request`, `message`.
Cuando el CSV no incluye `label`, la app intenta inferir la clase (`xss`, `sqli`, etc.) desde `Cuerpo_Peticion` y `Codigo_Respuesta`.

## Seguridad de la carga de archivos

La vista de carga del dashboard aplica:

- Autenticación Basic Auth del dashboard.
- Límite de tamaño (`MAX_UPLOAD_SIZE`, por defecto 10 MB).
- Validación de extensión (`.txt`, `.csv`).
- Normalización de nombre con `secure_filename`.
- Parseo controlado (sin ejecución de código del archivo).

## Personalización del frontend por ZIP

- HTML personalizado se guarda en `CUSTOM_FRONT_DIR/current/templates`.
- Assets (`.css`, `.js`, imágenes) se guardan en `CUSTOM_FRONT_DIR/current/assets`.
- Los assets se exponen bajo `/custom-assets/<archivo>`.
- Si el HTML personalizado referencia `/styles.css` o `/script.js`, el backend intenta resolver esos archivos desde el paquete de assets cargado.
- El backend valida que el ZIP no tenga rutas peligrosas (`../`) ni extensiones no permitidas.

## Troubleshooting

Si ves que la web no cambia tras actualizar código:

```bash
docker compose down
docker compose up -d --build --force-recreate
docker compose ps
docker compose logs -f honeypot-web
```

Este proyecto persiste **solo la base de datos/modelo** en `/data` para evitar que volúmenes antiguos oculten cambios del código.

## Seguridad operativa

- No desplegar junto a sistemas productivos.
- Usar red/host aislado.
- Rotar credenciales del dashboard.
- Monitorizar consumo de recursos y mantener snapshots/respaldos.
