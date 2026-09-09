"""Executive PDF reports. Standard library only; no schema or configuration changes."""
import argparse
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import textwrap
import time

MAX_DAYS = 90

def period(start=None, end=None):
    today = datetime.now(timezone.utc).date()
    try:
        last = date.fromisoformat(end) if end else today
        first = date.fromisoformat(start) if start else last - timedelta(days=29)
        stop = last + timedelta(days=1)
        previous = first - (stop - first)
    except (ValueError, OverflowError):
        raise ValueError("Use fechas válidas AAAA-MM-DD.")
    if first > last or (stop - first).days > MAX_DAYS or last > today:
        raise ValueError("Seleccione entre 1 y 90 días, sin fechas futuras.")
    return first, stop, previous

def collect(db_path, start=None, end=None):
    first, stop, previous = period(start, end)
    deadline = time.monotonic() + 2
    # mode=ro fails if the database is missing; never creates an empty database.
    db = sqlite3.connect(Path(db_path).resolve().as_uri() + "?mode=ro", uri=True, timeout=0.2)
    db.row_factory = sqlite3.Row
    db.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        # SQLite datetime normalizes ISO timestamps, including timezone offsets.
        where = "datetime(timestamp) >= ? AND datetime(timestamp) < ?"
        bounds = (str(first) + " 00:00:00", str(stop) + " 00:00:00")
        def summary(a, b):
            return dict(db.execute("""
                SELECT COUNT(*) total,
                COALESCE(SUM(is_attack = 1),0) attacks,
                COUNT(DISTINCT CASE WHEN is_attack=1 THEN NULLIF(ip,'') END) ips,
                COALESCE(SUM(is_attack=1 AND severity IN ('high','critical')),0) urgent,
                MIN(timestamp) first_event, MAX(timestamp) last_event
                FROM attack_logs WHERE """ + where, (a,b)).fetchone())
        data = summary(*bounds)
        data["previous"] = summary(str(previous) + " 00:00:00", bounds[0])
        data.update(start=str(first), end=str(stop - timedelta(days=1)),
                    previous_start=str(previous), previous_end=str(first - timedelta(days=1)),
                    generated=datetime.now(timezone.utc).isoformat())
        for key, column in (("types","attack_type"), ("severity","severity"), ("ips_top","ip"), ("paths","path")):
            # column identifiers are a fixed allowlist; dates remain parameters.
            data[key] = [tuple(row) for row in db.execute(
                "SELECT substr(COALESCE(NULLIF(" + column + ",''),'Desconocido'),1,180), COUNT(*) "
                "FROM attack_logs WHERE " + where + " AND is_attack=1 "
                "GROUP BY " + column + " ORDER BY COUNT(*) DESC, " + column + " LIMIT 10", bounds)]
        data["daily"] = [tuple(row) for row in db.execute(
            "SELECT date(timestamp), COUNT(*), SUM(is_attack=1) FROM attack_logs WHERE " + where +
            " GROUP BY date(timestamp) ORDER BY date(timestamp)", bounds)]
        return data
    finally:
        db.close()  # release the read snapshot before rendering

def report_lines(data):
    total, attacks = data["total"], data["attacks"]
    rate = 100 * attacks / total if total else 0
    old = data["previous"]["attacks"]
    change = f"{100 * (attacks-old)/old:+.1f}%" if old else "No calculable: período anterior sin ataques"
    lines = [
        ("title", "Informe ejecutivo de seguridad"),
        ("text", "CONFIDENCIAL | Honeypot | Detecciones observadas"),
        ("text", f"Período UTC: {data['start']} a {data['end']} (ambos inclusive)"),
        ("text", f"Generado: {data['generated']}"),
        ("heading", "1. Resumen para decisiones"),
        ("text", f"Eventos: {total:,} | Ataques detectados: {attacks:,} ({rate:.1f}%)"),
        ("text", f"IP de origen con ataques: {data['ips']:,} | Ataques de severidad alta/crítica: {data['urgent']:,}"),
        ("text", f"Variación de ataques: {change}. Base anterior: {old:,} ataques / {data['previous']['total']:,} eventos."),
        ("text", f"Comparación UTC: {data['previous_start']} a {data['previous_end']}."),
    ]
    if not total:
        lines.append(("text", "No hay eventos en el período. Verifique la recepción de telemetría y la retención antes de concluir ausencia de amenazas."))
    elif not attacks:
        lines.append(("text", "No se clasificaron ataques en los eventos disponibles. Esto no demuestra ausencia de amenazas."))
    else:
        lines.append(("text", "Las detecciones requieren validación con los registros del servidor y el SIEM; no acreditan una intrusión exitosa."))
    lines.append(("heading", "2. Acciones recomendadas"))
    if data["urgent"]:
        lines.append(("text", "Prioridad 1 | SOC, hoy: validar detecciones altas/críticas con logs de Nginx, aplicación y SIEM; comprobar impacto y abrir incidente si se confirma compromiso."))
    if attacks:
        lines.append(("text", "Prioridad 2 | Seguridad y plataforma, esta semana: revisar los tipos y rutas predominantes; comprobar parches y controles WAF con pruebas antes de aplicar bloqueos."))
        if old and attacks > old:
            lines.append(("text", "Prioridad 2 | SOC: investigar el aumento frente al período anterior; descartar cambios de cobertura, retención o volumen legítimo."))
        lines.append(("text", "Prioridad 3 | SOC: revisar muestras y falsos positivos antes de ajustar reglas o entrenar el modelo. No bloquear IP únicamente por este informe."))
    lines.append(("text", "Control recurrente | Operaciones: verificar continuidad de ingesta, retención y cobertura de agentes; asignar responsables y seguimiento de las acciones."))
    for heading, key in (("3. Tipos de ataque (top 10)", "types"), ("4. Severidades (top 10)", "severity"), ("5. IP de origen (top 10)", "ips_top"), ("6. Rutas objetivo (top 10)", "paths")):
        lines.append(("heading", heading))
        lines.extend(("text", f"{value}: {count:,} detecciones") for value, count in data[key])
        if not data[key]:
            lines.append(("text", "Sin detecciones."))
    lines.append(("heading", "7. Evolución diaria (UTC)"))
    daily = {day:(events, hits or 0) for day,events,hits in data["daily"]}
    current = date.fromisoformat(data["start"])
    while current <= date.fromisoformat(data["end"]):
        events, hits = daily.get(str(current),(0,0))
        lines.append(("text", f"{current} | Eventos: {events:,} | Ataques: {hits:,}"))
        current += timedelta(days=1)
    lines.extend([
        ("heading", "8. Alcance y limitaciones"),
        ("text", "Fuente: attack_logs del servidor central; incluye eventos de las fuentes que ya registra. No identifica clientes o agentes individuales porque no existe una columna dedicada a ello en este commit."),
        ("text", "Ataque = is_attack igual a 1. Severidad alta/crítica = high o critical entre ataques. Las clasificaciones y severidades son las almacenadas, sin reclasificación ni cálculo de riesgo empresarial."),
        ("text", "Fechas sin zona se interpretan como UTC, según el servidor. Fechas inválidas quedan fuera. El día actual es parcial; retención y cobertura pueden afectar la comparación. Cero eventos no demuestra disponibilidad ni ausencia de actividad."),
        ("text", "Las IP no identifican personas: pueden corresponder a proxies o NAT. No se incluyen cuerpos, cabeceras ni query_string. Las rutas e IP pueden contener información sensible; distribuya el PDF por canales autorizados."),
        ("text", "Los rankings muestran hasta 10 grupos y pueden no sumar todas las detecciones. No se estima precisión del modelo a partir de su confianza."),
    ])
    return lines

def render_pdf(data):
    """Small paginated PDF with built-in WinAnsi fonts, no external processes/assets."""
    pages, rows, y = [], [], 780
    for kind, raw in report_lines(data):
        # Discard controls, escape PDF syntax below. Long attacker strings wrap.
        clean = "".join(c if c.isprintable() else " " for c in str(raw))
        size = 20 if kind == "title" else 13 if kind == "heading" else 10
        wrapped = textwrap.wrap(clean, width=40 if kind == "title" else 58 if kind == "heading" else 82) or [""]
        needed = len(wrapped) * (size + 5) + 9
        if y - needed < 55 and rows:
            pages.append(rows); rows=[]; y=780
        for line in wrapped:
            rows.append((48,y,size,kind,line))
            y -= size + 5
        y -= 9
    if rows: pages.append(rows)
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"]
    def escaped(value):
        return value.encode("cp1252", "replace").replace(b"\\", b"\\\\").replace(b"(",b"\\(").replace(b")",b"\\)")
    kids=[]
    for number, rows in enumerate(pages,1):
        page_id=len(objects)+1
        kids.append(f"{page_id} 0 R")
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {page_id+1} 0 R >>".encode())
        content=b""
        rows.append((48,30,9,"text",f"CONFIDENCIAL | Honeypot | Página {number} de {len(pages)}"))
        for x,y,size,kind,line in rows:
            font="F2" if kind in ("heading","title") else "F1"
            content += f"BT /{font} {size} Tf 0.10 0.18 0.27 rg {x} {y} Td (".encode()+escaped(line)+b") Tj ET\n"
        objects.append(f"<< /Length {len(content)} >>\nstream\n".encode()+content+b"endstream")
    objects[1]=f"<< /Type /Pages /Count {len(kids)} /Kids [{' '.join(kids)}] >>".encode()
    pdf=b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
    offsets=[0]
    for i,obj in enumerate(objects,1):
        offsets.append(len(pdf)); pdf+=f"{i} 0 obj\n".encode()+obj+b"\nendobj\n"
    xref=len(pdf)
    pdf+=f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode()
    pdf+=b"".join(f"{pos:010d} 00000 n \n".encode() for pos in offsets[1:])
    pdf+=f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return pdf

def register_report(app, auth_required, db_path):
    from flask import Response, jsonify, request
    @app.get("/dashboard/api/executive-report.pdf")
    @auth_required
    def executive_report_pdf():
        try:
            data=collect(db_path, request.args.get("start"), request.args.get("end"))
            pdf=render_pdf(data)
        except ValueError as exc:
            return jsonify(ok=False, error=str(exc)),400
        except sqlite3.Error:
            app.logger.warning("Executive report database unavailable or query budget exceeded")
            return jsonify(ok=False, error="Informe no disponible. Reintente con un período menor o fuera de hora punta."),503
        response=Response(pdf,mimetype="application/pdf")
        response.headers["Content-Disposition"]=f'attachment; filename="honeypot-{data["start"]}-{data["end"]}.pdf"'
        response.headers["Cache-Control"]="no-store"
        response.headers["X-Content-Type-Options"]="nosniff"
        return response

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description="Informe ejecutivo sin iniciar la aplicación.")
    parser.add_argument("--db",required=True)
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--output",required=True)
    args=parser.parse_args()
    Path(args.output).write_bytes(render_pdf(collect(args.db,args.start,args.end)))
