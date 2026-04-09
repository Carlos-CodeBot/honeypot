# Honeypot Web (Docker)

Honeypot web educativo para capturar intentos de ataque HTTP y analizarlos desde un dashboard interno.

> ⚠️ **Uso recomendado solo en laboratorio/entorno aislado**. Este proyecto incluye vulnerabilidades intencionales para atraer tráfico malicioso.

## Características

- Sitio web personalizable por variables de entorno (título, subtítulo, color de tema).
- Endpoints con debilidades intencionales simuladas (XSS reflejado y login inseguro).
- Registro de peticiones HTTP en SQLite (IP, User-Agent, query, body y notas de indicadores).
- Dashboard interno protegido por Basic Auth para visualizar estadísticas y eventos.
- Despliegue simple con Docker Compose.

## Instalación rápida

```bash
cp .env.example .env
docker compose up -d --build
```

Aplicación: `http://localhost:8000`

Dashboard: `http://localhost:8000/dashboard`

Credenciales por defecto dashboard:

- Usuario: `admin`
- Contraseña: `admin123`

## Endpoints

- `/` Inicio
- `/login` Login intencionalmente débil
- `/internal` Zona interna simulada
- `/search?q=...` Búsqueda vulnerable a XSS reflejado (intencional)
- `/dashboard` Dashboard de análisis
- `/dashboard/api/logs` API JSON con los últimos eventos

## Inteligencia básica sugerida

1. Crear reglas para `notes` en base a patrones (SQLi, path traversal, XSS).
2. Exportar logs y correlacionar IPs con feeds de reputación.
3. Añadir geolocalización/IP ASN en un job offline.

## Personalización

Edita `.env`:

- `SITE_TITLE`
- `SITE_SUBTITLE`
- `THEME_COLOR`
- `ADMIN_USER`
- `ADMIN_PASS`

## Seguridad operativa

- No expongas este honeypot en la misma red de sistemas productivos.
- Ejecuta en una VLAN o host aislado.
- Usa credenciales distintas y rotación periódica.
