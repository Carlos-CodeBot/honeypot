"""Executive PDF reports. Standard library only; no schema or configuration changes."""
import argparse
import re
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import time

MAX_DAYS = 90

SOURCE_LABELS = {"ml": "Modelo IA (MLP)", "rules": "Reglas", "unknown": "Origen no identificado"}


def safe_excerpt(value, limit=360):
    """Bounded, printable evidence. Redaction is best effort, not anonymization."""
    value = "".join(c if c.isprintable() else " " for c in str(value or ""))
    value = re.sub(
        r'''(?i)(["']?(?:password|passwd|pwd|token|access_token|refresh_token|api_key|apikey|secret|authorization|cookie)["']?\s*[:=]\s*)("[^"]*"|'[^']*'|[^&\s,;}]*)''',
        r"\1[OCULTO]", value)
    return value[:limit] + ("... [recortado]" if len(value) > limit else "")

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
                "SELECT COALESCE(NULLIF(" + column + ",''),'Desconocido'), COUNT(*) "
                "FROM attack_logs WHERE " + where + " AND is_attack=1 "
                "GROUP BY COALESCE(NULLIF(" + column + ",''),'Desconocido') ORDER BY COUNT(*) DESC, 1 LIMIT 10", bounds)]
        columns = {row[1] for row in db.execute("PRAGMA table_info(attack_logs)")}
        score = "confidence" if "confidence" in columns else "NULL"
        valid = f"CASE WHEN typeof({score}) IN ('real','integer') AND {score} BETWEEN 0 AND 1 THEN {score} END"
        source = ("CASE WHEN notes='mlp_model' THEN 'ml' WHEN notes LIKE 'rules=%' THEN 'rules' ELSE 'unknown' END"
                  if "notes" in columns else "'unknown'")
        data["confidence"] = [dict(row) for row in db.execute(
            f"SELECT {source} source, COUNT(*) total, COUNT({valid}) valid, AVG({valid}) average, "
            f"MIN({valid}) minimum, MAX({valid}) maximum, "
            f"SUM(CASE WHEN ({valid}) >= .90 THEN 1 ELSE 0 END) very_high, "
            f"SUM(CASE WHEN ({valid}) >= .75 AND ({valid}) < .90 THEN 1 ELSE 0 END) high, "
            f"SUM(CASE WHEN ({valid}) >= .60 AND ({valid}) < .75 THEN 1 ELSE 0 END) medium, "
            f"SUM(CASE WHEN ({valid}) < .60 THEN 1 ELSE 0 END) low "
            "FROM attack_logs WHERE " + where + " AND is_attack=1 GROUP BY 1 ORDER BY 1", bounds)]
        geo_exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='ip_geo_cache'").fetchone()
        data["countries"] = []
        data["geo_known"] = 0
        data["geo_internal"] = 0
        if geo_exists:
            # Reuse the stored cache only: no network calls and no writes during reporting.
            geo_where = where.replace("datetime(timestamp)", "datetime(a.timestamp)")
            geo = list(db.execute(
                "SELECT CASE WHEN g.is_private=1 OR g.country='Red interna' THEN 'internal' "
                "WHEN g.country IS NULL OR trim(g.country) IN ('','Desconocido','Unknown') THEN 'unknown' "
                "ELSE 'known' END kind, trim(g.country) country, COUNT(*) total "
                "FROM attack_logs a LEFT JOIN ip_geo_cache g ON g.ip=a.ip WHERE " + geo_where +
                " AND a.is_attack=1 GROUP BY 1,2 ORDER BY total DESC, country", bounds))
            data["countries"] = [(r["country"], r["total"]) for r in geo if r["kind"] == "known"][:10]
            data["geo_known"] = sum(r["total"] for r in geo if r["kind"] == "known")
            data["geo_internal"] = sum(r["total"] for r in geo if r["kind"] == "internal")
        data["geo_unknown"] = data["attacks"] - data["geo_known"] - data["geo_internal"]
        data["examples"] = []
        optional = ["method", "query_string", "body", "user_agent"]
        fields = ", ".join(f"substr({c},1,6000) AS {c}" if c in columns else f"NULL AS {c}" for c in optional)
        identity = "id" if "id" in columns else "rowid"
        for attack_type, count in data["types"]:
            selection = where + " AND is_attack=1 AND COALESCE(NULLIF(attack_type,''),'Desconocido')=?"
            params = (*bounds, attack_type)
            row = dict(db.execute(
                f"SELECT {identity} event_id, timestamp, substr(ip,1,180) ip, substr(path,1,6000) path, {fields}, "
                f"{source} source, {valid} confidence FROM attack_logs WHERE " + selection +
                f" ORDER BY datetime(timestamp) DESC, {identity} DESC LIMIT 1", params).fetchone())
            row.update(attack_type=attack_type, count=count)
            row["scores"] = dict(db.execute(
                f"SELECT COUNT({valid}) valid, AVG({valid}) average FROM attack_logs WHERE " + selection,
                params).fetchone())
            data["examples"].append(row)
        data["daily"] = [tuple(row) for row in db.execute(
            "SELECT date(timestamp), COUNT(*), SUM(is_attack=1) FROM attack_logs WHERE " + where +
            " GROUP BY date(timestamp) ORDER BY date(timestamp)", bounds)]
        return data
    finally:
        db.close()  # release the read snapshot before rendering

# Standard Helvetica widths in thousandths of an em, indexed by WinAnsi byte.
FONT_WIDTHS = (761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 761, 278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, 761, 556, 761, 222, 556, 333, 1000, 556, 556, 333, 1000, 667, 333, 1000, 761, 611, 761, 761, 222, 222, 333, 333, 350, 556, 1000, 333, 1000, 500, 333, 944, 761, 500, 667, 278, 333, 556, 556, 556, 556, 260, 556, 333, 737, 370, 556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 556, 537, 278, 333, 333, 365, 556, 834, 834, 834, 611, 667, 667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278, 278, 722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611, 556, 556, 556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278, 556, 556, 556, 556, 556, 556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500)

NAVY = (0.055, 0.12, 0.21)
TEAL = (0.00, 0.48, 0.49)
INK = (0.13, 0.20, 0.28)
MUTED = (0.37, 0.43, 0.49)
PALE = (0.94, 0.96, 0.97)
WHITE = (1, 1, 1)


def pct(value, total):
    return f"{100 * value / total:.1f}%" if total else "N/D"


def score_text(value):
    return f"{100 * value:.1f}%" if value is not None else "N/D"


class ReportCanvas:
    """Small vector PDF renderer. All dynamic strings are literal escaped text.

    Helvetica body text uses bundled standard metrics for wrapping without
    runtime font packages. Headers use Helvetica; no external assets or links.
    """
    def __init__(self, data):
        self.data = data
        self.pages = []

    def rect(self, x, y, w, h, color):
        self.pages[-1].append(f"{' '.join(map(str,color))} rg {x} {y} {w} {h} re f\n".encode())

    def text(self, x, y, value, size=9, bold=False, color=INK):
        clean = "".join(c if c.isprintable() else " " for c in str(value))
        escaped = clean.encode("cp1252", "replace").replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
        font = "F2" if bold else "F1"
        self.pages[-1].append(f"BT /{font} {size} Tf {' '.join(map(str,color))} rg 1 0 0 1 {x} {y} Tm (".encode() + escaped + b") Tj ET\n")

    @staticmethod
    def wrap(value, width, size):
        clean = " ".join(str(value).split())
        lines, line = [], ""
        def measure(text):
            return sum(FONT_WIDTHS[b] for b in text.encode("cp1252", "replace")) * size / 1000
        for word in clean.split(" "):
            if line and measure(line + " " + word) > width:
                lines.append(line)
                line = ""
            while measure(word) > width:
                cut, used = 0, 0
                for char in word:
                    step = measure(char)
                    if cut and used + step > width:
                        break
                    cut += 1
                    used += step
                lines.append(word[:cut])
                word = word[cut:]
            line = (line + " " + word).strip()
        if line:
            lines.append(line)
        return lines or [""]

    def paragraph(self, value, y, x=44, width=507, size=10, color=INK):
        lines = self.wrap(value, width, size)
        for line in lines:
            self.text(x, y, line, size, color=color)
            y -= size + 4
        return y - 8

    def page(self, title, subtitle):
        self.pages.append([])
        self.rect(0, 758, 595, 84, NAVY)
        self.rect(44, 775, 34, 3, TEAL)
        self.text(44, 808, "HONEYPOT / INTELIGENCIA DE SEGURIDAD", 9, True, WHITE)
        self.text(44, 735, title, 21, True)
        self.paragraph(subtitle, 711, size=9, color=MUTED)
        if self.data.get("demo"):
            self.text(342, 780, "DEMOSTRACIÓN / DATOS SINTÉTICOS", 9, True, WHITE)

    def section(self, title, y):
        self.rect(44, y - 7, 3, 20, TEAL)
        self.text(55, y, title, 12, True)
        return y - 28

    def ranking(self, rows, total, y, label="ORIGEN", scores=None):
        self.rect(44, y - 10, 507, 25, NAVY)
        self.text(52, y, "#", 8, True, WHITE)
        self.text(80, y, label, 8, True, WHITE)
        self.text(340, y, "ATAQUES", 8, True, WHITE)
        self.text(410, y, "% TOTAL", 8, True, WHITE)
        self.text(474, y, "CONFIANZA" if scores is not None else "VOLUMEN", 8, True, WHITE)
        y -= 35
        if not rows:
            return self.paragraph("Sin detecciones con datos disponibles para este ranking.", y)
        maximum = max(count for _, count in rows)
        for index, (label, count) in enumerate(rows, 1):
            label = safe_excerpt(label, 43)
            lines = self.wrap(label, 245, 9)
            height = max(37, len(lines) * 11 + 16)
            self.rect(44, y - height + 15, 507, height, PALE if index % 2 else (0.98, .985, .99))
            self.text(52, y, f"{index:02}", 9, color=TEAL)
            for n, line in enumerate(lines):
                self.text(80, y - 11*n, line, 9)
            self.text(340, y, f"{count:,}", 9)
            self.text(410, y, pct(count, total), 9)
            if scores is not None:
                self.text(478, y, score_text(scores[index-1]), 9)
            else:
                self.rect(475, y - 1, 64, 6, (.82, .87, .89))
                self.rect(475, y - 1, 64 * count / maximum, 6, TEAL)
            y -= height
        return y - 15

    def finish(self):
        objects = [b"<< /Type /Catalog /Pages 2 0 R >>", b"",
                   b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
                   b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"]
        kids = []
        for number, commands in enumerate(self.pages, 1):
            # Draw footer into the current page without altering layout state.
            saved = self.pages
            self.pages = [commands]
            self.rect(44, 49, 507, 1, (.82, .87, .89))
            self.text(44, 33, "CONFIDENCIAL | Honeypot", 8, color=MUTED)
            self.text(420, 33, f"Página {number} de {len(saved)}", 8, color=MUTED)
            self.pages = saved
            page_id = len(objects) + 1
            kids.append(f"{page_id} 0 R")
            objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {page_id+1} 0 R >>".encode())
            content = b"".join(commands)
            objects.append(f"<< /Length {len(content)} >>\nstream\n".encode() + content + b"endstream")
        objects[1] = f"<< /Type /Pages /Count {len(kids)} /Kids [{' '.join(kids)}] >>".encode()
        pdf = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"
        offsets = [0]
        for i, obj in enumerate(objects, 1):
            offsets.append(len(pdf))
            pdf += f"{i} 0 obj\n".encode() + obj + b"\nendobj\n"
        xref = len(pdf)
        pdf += f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode()
        pdf += b"".join(f"{pos:010d} 00000 n \n".encode() for pos in offsets[1:])
        pdf += f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
        return pdf


def render_pdf(data):
    c = ReportCanvas(data)
    total, attacks = data["total"], data["attacks"]
    interval = f"{data['start']} a {data['end']} | UTC | Ambos días inclusive"
    old = data["previous"]["attacks"]
    change = f"{100*(attacks-old)/old:+.1f}%" if old else "No calculable: base anterior sin ataques"
    c.page("Informe ejecutivo de seguridad", interval)
    c.text(44, 672, "DETECCIONES OBSERVADAS / RESUMEN PARA DECISIONES", 10, True, TEAL)
    for x, value, label in ((44, f"{attacks:,}", "ATAQUES DETECTADOS"), (217, pct(attacks,total), "% DE LOS EVENTOS"), (390, f"{data['ips']:,}", "IP CON ATAQUES")):
        c.rect(x, 566, 161, 84, PALE)
        c.text(x+12, 613, value, 25, True)
        c.text(x+12, 582, label, 8, True, MUTED)
    y = c.paragraph(f"Eventos analizados: {total:,}. Severidad alta/crítica: {data['urgent']:,} detecciones. Variación: {change}.", 540)
    y = c.paragraph(f"Base de comparación: {data['previous_start']} a {data['previous_end']}, con {old:,} ataques en {data['previous']['total']:,} eventos.", y, color=MUTED)
    y = c.section("Lectura ejecutiva", y-8)
    if not total:
        insight = "No hay eventos en el período. Verificar ingesta y retención antes de concluir ausencia de amenazas."
    elif not attacks:
        insight = "No se clasificaron ataques en los eventos disponibles. Revisar cobertura y continuidad de la telemetría."
    else:
        top_type, top_count = data["types"][0]
        insight = f"La categoría predominante es {safe_excerpt(top_type,80)}: {top_count:,} detecciones ({pct(top_count, attacks)} del total de ataques). Las 10 primeras IP concentran {pct(sum(v for _,v in data['ips_top']), attacks)} de las detecciones."
    y = c.paragraph(insight, y)
    y = c.paragraph("Las detecciones son intentos o actividad clasificada como ataque; no confirman una intrusión exitosa ni cuantifican pérdidas de negocio.", y)
    y = c.section("Acciones y responsables", y-6)
    actions = []
    if data["urgent"]:
        actions.append("01 / HOY / SOC: validar los eventos altos y críticos con Nginx, aplicación y SIEM; abrir incidente si se confirma impacto.")
    if attacks:
        actions.append("02 / ESTA SEMANA / SEGURIDAD Y PLATAFORMA: revisar categorías, rutas y ejemplos; priorizar parches y probar ajustes del WAF.")
        actions.append("03 / ESTA SEMANA / ANALISTAS: revisar muestras de menor confianza y falsos positivos antes de ajustar reglas o entrenar el modelo.")
    actions.append("CONTROL CONTINUO / OPERACIONES: comprobar ingesta, retención y cobertura. Asignar seguimiento y fecha de cierre a cada acción.")
    for action in actions:
        y = c.paragraph(action, y, size=8.5)
    c.text(44, 70, "Emitido: " + data["generated"][:19] + " UTC", 8, color=MUTED)

    c.page("01 / Orígenes con más ataques", interval)
    y = c.ranking(data["ips_top"], attacks, 664, "IP REGISTRADA")
    y = c.paragraph("Top 10 por número de eventos clasificados como ataque. El porcentaje usa todos los ataques del período; la barra compara con la primera posición.", y)
    c.paragraph("La IP es la registrada por el servidor. Puede representar proxy, NAT o una cadena X-Forwarded-For; no identifica a una persona. Validar los proxies de confianza antes de atribuir o bloquear.", y, color=MUTED)

    c.page("02 / Países de origen", interval)
    y = c.paragraph(f"Cobertura geográfica: {pct(data['geo_known'], attacks)} de los ataques. Con país: {data['geo_known']:,} | Sin país: {data['geo_unknown']:,} | Red interna: {data['geo_internal']:,}.", 666)
    y = c.ranking(data["countries"], attacks, y-10, "PAÍS EN CACHÉ")
    y = c.paragraph("Top 10 de países conocidos, por ataques (no por IP únicas). Sin país y Red interna quedan fuera del ranking, pero forman parte del denominador de los porcentajes.", y)
    c.paragraph("Se reutiliza ip_geo_cache, sin consultas externas. La caché puede estar incompleta o desactualizada y no representa necesariamente la ubicación en la fecha del evento. El país de una IP no prueba la nacionalidad del atacante.", y, color=MUTED)

    c.page("03 / Técnicas más observadas", interval)
    y = c.ranking(data["types"], attacks, 664, "TIPO DE ATAQUE", [e["scores"]["average"] for e in data["examples"]])
    y = c.paragraph("Confianza: media de puntuaciones válidas almacenadas por categoría, combinando reglas y modelo. N/D indica ausencia de puntuaciones válidas. Consulte la separación por origen en la sección 05.", y)
    c.paragraph("Los ejemplos siguientes proceden del evento más reciente de cada categoría dentro del período; los empates se resuelven por ID descendente. Son muestras observadas, no pruebas de explotación exitosa.", y, color=MUTED)

    examples = data["examples"]
    y = 0
    for n, event in enumerate(examples, 1):
        request = (event["method"] or "N/D") + " " + (event["path"] or "/")
        if event["query_string"]:
            request += "?" + event["query_string"]
        paragraphs = [
            f"Evento #{event['event_id']} | {safe_excerpt(event['timestamp'],35)} | IP: {safe_excerpt(event['ip'],80) or 'N/D'}",
            f"Origen: {SOURCE_LABELS[event['source']]} | Confianza del evento: {score_text(event['confidence'])} | Muestras con puntuación: {event['scores']['valid']}/{event['count']}",
            "Petición: " + safe_excerpt(request, 235),
            "Cuerpo: " + safe_excerpt(event["body"], 145) if event["body"] else
            "User-Agent: " + safe_excerpt(event["user_agent"], 145) if event["user_agent"] else
            "Sin cuerpo ni User-Agent disponibles en este registro.",
        ]
        needed = 51 + sum(len(c.wrap(p, 507, 9))*13 + 8 for p in paragraphs)
        if y - needed < 150:
            c.page("04 / Evidencia de los registros", f"Ejemplos del top 10 | {interval}")
            c.paragraph("Extractos limitados y con ocultación básica de credenciales. Pueden quedar datos sensibles. Las cabeceras se omiten; el patrón que activó una regla puede estar fuera del extracto. Consulte el evento original por ID.", 107, size=8, color=MUTED)
            y = 664
        c.rect(44, y-22, 507, 35, PALE)
        c.text(53, y, f"{n:02} / " + safe_excerpt(event["attack_type"], 32), 11, True)
        y -= 42
        for paragraph in paragraphs:
            y = c.paragraph(paragraph, y, size=9)
        y -= 9


    c.page("05 / Confianza de la clasificación", interval)
    y = c.paragraph("La confianza expresa la puntuación del clasificador para la categoría asignada. No es precisión medida, probabilidad calibrada de intrusión ni nivel de riesgo empresarial.", 665)
    by_source = {row["source"]: row for row in data["confidence"]}
    for source in ("ml", "rules", "unknown"):
        row = by_source.get(source, {"total":0, "valid":0, "average":None, "minimum":None, "maximum":None, "very_high":0, "high":0, "medium":0, "low":0})
        y = c.section(SOURCE_LABELS[source], y-8)
        y = c.paragraph(f"Ataques: {row['total']:,} | Con puntuación válida: {row['valid']:,} | Sin puntuación válida: {row['total']-row['valid']:,}", y)
        y = c.paragraph(f"Media: {score_text(row['average'])} | Mínima: {score_text(row['minimum'])} | Máxima: {score_text(row['maximum'])}", y)
        y = c.paragraph(f"Muy alta: {row['very_high']:,} | Alta: {row['high']:,} | Media: {row['medium']:,} | Baja: {row['low']:,}", y, size=8.5)
    y = c.section("Cómo interpretar los resultados", y-8)
    for explanation in (
        "Modelo IA: notes=mlp_model identifica la predicción MLP. La puntuación guardada corresponde a la clase elegida, redondeada a dos decimales. No equivale a una validación externa.",
        "Reglas: notes comienza por rules=. La puntuación está definida en cada regla; no procede de una predicción de IA. El motor prioriza reglas y recurre al modelo si no hay coincidencia.",
        "Origen no identificado: no hay una marca reconocida. No se atribuyen estas detecciones a la IA. Las marcas describen el origen declarado por el registro; no certifican su autenticidad.",
        "Bandas descriptivas: muy alta >=90%; alta >=75% y <90%; media >=60% y <75%; baja <60%. Valores nulos, no numéricos o fuera de [0,1] se excluyen de medias y bandas. Un cero guardado cuenta como cero; podría ser un valor histórico por defecto.",
    ):
        y = c.paragraph(explanation, y, size=8.5, color=MUTED)

    c.page("06 / Evolución y metodología", interval)
    y = c.section("Ataques por día (UTC)", 665)
    daily = {day: hits or 0 for day, _, hits in data["daily"]}
    start, end = date.fromisoformat(data["start"]), date.fromisoformat(data["end"])
    days = (end-start).days+1
    values = [daily.get(str(start+timedelta(days=i)), 0) for i in range(days)]
    peak = max(values, default=0)
    c.rect(44, 475, 507, 137, PALE)
    step = 483/days
    for i, value in enumerate(values):
        if value:
            c.rect(56+i*step, 486, max(1,step-2), 108*value/max(peak,1), TEAL)
    c.text(44, 457, data["start"], 8, color=MUTED)
    c.text(440, 457, data["end"], 8, color=MUTED)
    y = c.paragraph(f"Escala: 0 a {peak:,} ataques/día. Cada barra representa un día; sin barra = cero eventos clasificados como ataque. Máximo observado: {peak:,}.", 435)
    y = c.section("Alcance y criterios de cálculo", y-8)
    for paragraph in (
        "Fuente: attack_logs del servidor central. Solo is_attack=1 se cuenta como ataque; severidad alta/crítica corresponde a high o critical. No se reclasifican eventos ni se modifica la base.",
        "Fechas inclusivas en UTC, entre 1 y 90 días; por defecto, los últimos 30. Comparación con igual número de días anteriores. El día actual es parcial. Fechas inválidas quedan fuera y las fechas sin zona se interpretan como UTC.",
        "Cada fila representa una detección, no un atacante ni un incidente único. Los rankings se ordenan por volumen descendente y etiqueta ascendente en empates. Los porcentajes usan el total de ataques; los top 10 pueden no sumar 100%.",
        "La retención, cambios de sensores y períodos sin telemetría afectan la comparación. Este esquema no permite separar clientes o agentes individuales. Cero eventos no demuestra disponibilidad ni ausencia de amenazas.",
        "Países: unión exacta por la IP almacenada con ip_geo_cache. No se amplía la caché ni se infiere un país ausente. Los ejemplos se abrevian; la ocultación de claves sensibles no es una anonimización completa.",
        "Para medir precisión, recall o falsos positivos de la IA se necesita una muestra etiquetada y validada de forma independiente. Revisar evidencia y contexto antes de aplicar medidas de contención.",
    ):
        y = c.paragraph(paragraph, y, size=8.5, color=MUTED)

    c.page("07 / Contexto técnico", interval)
    y = c.section("Severidad de los ataques", 665)
    for label, count in data["severity"]:
        y = c.paragraph(f"{safe_excerpt(label,80)}: {count:,} ({pct(count,attacks)})", y, size=8.5)
    y = c.section("Rutas objetivo / Top 10", y-3)
    # Compact appendix, capped per row so ten long paths still fit on one page.
    for label, count in data["paths"]:
        if y < 135:
            c.page("07 / Contexto técnico (continuación)", interval)
            y = c.section("Rutas objetivo / Top 10 (continuación)", 665)
        y = c.paragraph(f"{count:,} | {safe_excerpt(label,105)}", y, size=8)
    if not attacks:
        c.paragraph("Sin detecciones.", y)
    return c.finish()


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
