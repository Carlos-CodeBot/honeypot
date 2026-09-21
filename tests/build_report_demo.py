"""Generate a visibly synthetic preview, without accessing production data."""
import argparse
from pathlib import Path
import sqlite3
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from executive_report import collect, render_pdf


def main(output):
    categories = [
        ("sqli", "/products", "id=1 UNION SELECT NULL,NULL--"),
        ("xss", "/search", "q=<script>alert('demo')</script>"),
        ("path_traversal", "/download", "file=../../../../etc/passwd"),
        ("command_injection", "/diagnostics", "host=127.0.0.1;id"),
        ("scanner_bot", "/.env", ""),
        ("bruteforce", "/login", "username=admin&password=demo-secret"),
        ("lfi", "/index.php", "page=../../etc/passwd"),
        ("ssrf", "/fetch", "url=http://127.0.0.1/admin"),
        ("xxe", "/api/xml", ""),
        ("ssti", "/preview", "name={{7*7}}"),
    ]
    countries = ["Estados Unidos", "Brasil", "Alemania", "China", "Rusia", "Países Bajos", "India", "Francia", "Reino Unido", "Canadá"]
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "demo.db"
        db = sqlite3.connect(path)
        db.executescript("""CREATE TABLE attack_logs(id INTEGER PRIMARY KEY, timestamp TEXT,
            ip TEXT, method TEXT, path TEXT, query_string TEXT, body TEXT, user_agent TEXT,
            notes TEXT, is_attack INTEGER, attack_type TEXT, severity TEXT, confidence REAL);
            CREATE TABLE ip_geo_cache(ip TEXT PRIMARY KEY, country TEXT, is_private INTEGER);""")
        for i, country in enumerate(countries):
            db.execute("INSERT INTO ip_geo_cache VALUES (?,?,0)", (f"192.0.2.{i+1}", country))
        for i, (kind, target, query) in enumerate(categories):
            for j in range(100-i*9):
                stamp = f"2026-08-{1+j%30:02}T{j%24:02}:30:00"
                ip = f"192.0.2.{1+(i+j)%12}"
                notes = "mlp_model" if j%4==0 else f"rules={kind}"
                score = .64+(i%4)*.08 if notes=="mlp_model" else .93
                body = '<!DOCTYPE demo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><demo>&xxe;</demo>' if kind=="xxe" else ""
                db.execute("INSERT INTO attack_logs(timestamp,ip,method,path,query_string,body,user_agent,notes,is_attack,attack_type,severity,confidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                           (stamp, ip, "POST" if body else "GET", target, query, body, "Synthetic demo client", notes, 1, kind, "high" if i<4 else "medium", score))
        for j in range(840):
            db.execute("INSERT INTO attack_logs(timestamp,ip,path,is_attack,attack_type,severity,confidence) VALUES (?,?,?,?,?,?,?)",
                       (f"2026-08-{1+j%30:02}T12:00:00", "198.51.100.1", "/", 0, "benign", "low", 0))
        for j in range(420):
            db.execute("INSERT INTO attack_logs(timestamp,ip,path,is_attack,attack_type,severity,confidence) VALUES (?,?,?,?,?,?,?)",
                       (f"2026-07-{2+j%29:02}T12:00:00", "192.0.2.1", "/login", 1, "bruteforce", "medium", .86))
        db.commit()
        db.close()
        data = collect(path, "2026-08-01", "2026-08-30")
        data["demo"] = True
        Path(output).write_bytes(render_pdf(data))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    main(parser.parse_args().output)
