# Honeypot Web (Docker)

Honeypot web educativo para capturar, **clasificar** y analizar intentos de ataque HTTP desde un dashboard SOC.

> ⚠️ **Solo laboratorio/entorno aislado**. Incluye vulnerabilidades intencionales para atraer tráfico malicioso.

## Qué trae esta versión

- Frontend más realista y personalizable (landing tipo SaaS, módulos de producto, formulario de contacto, login de clientes).
- Endpoints con debilidades intencionales (XSS reflejado y login inseguro) para observación de ataques.
- Motor de clasificación basado en reglas (`SQLi`, `XSS`, `path traversal`, `command injection`, `scanner bot`).
- Dashboard con:
  - Conteo total de eventos
  - Ataques detectados
  - Alta severidad
  - Top de técnicas detectadas
  - Tabla de inteligencia por IP (eventos/ataques/confianza)
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
- `SIEM_HINT` (texto mostrado en dashboard para herramienta recomendada)

## Endpoints relevantes

- `/` landing corporativa
- `/producto/<slug>` páginas de producto
- `/contacto` formulario comercial
- `/login` login intencionalmente débil
- `/internal` área interna simulada
- `/search?q=...` vulnerable a XSS reflejado (intencional)
- `/dashboard` panel SOC
- `/dashboard/api/logs?only_attacks=1` logs clasificados
- `/dashboard/api/intel` ranking por IP

## ¿Conviene usar una herramienta existente?

Sí. El clasificador interno ayuda para una primera capa, pero para inteligencia más sólida es recomendable integrar:

1. **CrowdSec** para decisiones colaborativas y bloqueo automático.
2. **Wazuh + Elastic/OpenSearch** para correlación multi-fuente.
3. **Suricata/Zeek** si también quieres telemetría de red además de HTTP app-level.

Puedes exportar los eventos de SQLite periódicamente o enviar eventos en tiempo real a tu pipeline SIEM.

## Troubleshooting (importante)

Si ves que la web no cambia tras actualizar código (por ejemplo `/contacto` devuelve 404), normalmente es por contenedor/imagen anterior en ejecución.

1. Reconstruye e inicia de nuevo:

```bash
docker compose down
docker compose up -d --build --force-recreate
```

2. Verifica que el contenedor use la imagen nueva:

```bash
docker compose ps
docker compose logs -f honeypot-web
```

3. Este proyecto persiste **solo la base de datos** en `/data/honeypot.db`; el código ya no se monta como volumen para evitar que una versión antigua tape los archivos de la imagen.

## Seguridad operativa

- No desplegar junto a sistemas productivos.
- Usar red/host aislado.
- Rotar credenciales del dashboard.
- Monitorizar consumo de recursos y mantener snapshots/respaldos.
