"""Report semantics: rankings, provenance, evidence and bounded PDF layout."""
import io
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import executive_report as report
from pypdf import PdfReader
from pypdf.generic import ContentStream


class ExecutiveV2(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "logs.db"
        self.db = sqlite3.connect(self.path)
        self.db.executescript("""
            CREATE TABLE attack_logs(id INTEGER PRIMARY KEY, timestamp TEXT,
                ip TEXT, method TEXT, path TEXT, query_string TEXT, body TEXT,
                user_agent TEXT, notes TEXT, is_attack INTEGER, attack_type TEXT,
                severity TEXT, confidence REAL);
            CREATE TABLE ip_geo_cache(ip TEXT PRIMARY KEY, country TEXT, is_private INTEGER);
        """)

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def event(self, ip="192.0.2.1", kind="sqli", confidence=.93,
              notes="rules=sqli", attack=1, stamp="2026-01-02T12:00:00", path="/search", query="q=' OR 1=1&token=private-secret"):
        self.db.execute("INSERT INTO attack_logs(timestamp,ip,method,path,query_string,body,user_agent,notes,is_attack,attack_type,severity,confidence) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                        (stamp, ip, "GET", path, query, "", "test", notes, attack, kind, "high", confidence))
        self.db.commit()

    def collect(self):
        return report.collect(self.path, "2026-01-01", "2026-01-02")

    def test_countries_count_events_and_keep_missing_outside_top(self):
        self.db.executemany("INSERT INTO ip_geo_cache VALUES (?,?,?)", [
            ("192.0.2.1", "Colombia", 0), ("192.0.2.2", "Colombia", 0),
            ("192.0.2.3", "Red interna", 1), ("192.0.2.4", "Desconocido", 0)])
        for ip in ("192.0.2.1", "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"):
            self.event(ip=ip)
        self.event(attack=0)
        self.event(stamp="2026-01-03T00:00:00")
        before = self.path.read_bytes()
        data = self.collect()
        self.assertEqual(data["countries"], [("Colombia", 3)])
        self.assertEqual((data["geo_known"], data["geo_unknown"], data["geo_internal"]), (3,2,1))
        self.assertEqual(data["ips_top"][0], ("192.0.2.1",2))
        self.assertEqual(before, self.path.read_bytes())

    def test_confidence_provenance_missing_and_invalid(self):
        for value in (.6,.75,.9,1,0,None,-1,2,"bad"):
            self.event(confidence=value, notes="mlp_model")
        self.event(notes="rules=sqli", confidence=.93)
        self.event(notes="external_sensor", confidence=.4)
        self.event(notes="mlp_model", confidence=.99, attack=0)
        by_source = {r["source"]:r for r in self.collect()["confidence"]}
        ml = by_source["ml"]
        self.assertEqual((ml["total"], ml["valid"]), (9,5))
        self.assertAlmostEqual(ml["average"], .65)
        self.assertEqual((ml["very_high"],ml["high"],ml["medium"],ml["low"]), (2,1,1,1))
        self.assertAlmostEqual(by_source["rules"]["average"], .93)
        self.assertEqual(by_source["unknown"]["total"], 1)

    def test_rankings_limit_and_examples_are_actual_latest_rows(self):
        for i in range(12):
            self.event(ip=f"192.0.2.{i+1}", kind=f"type-{i:02}")
        self.event(kind="type-00", path="/latest", stamp="2026-01-02T23:59:59")
        self.event(kind="type-00", path="/outside", stamp="2026-01-03T00:00:00")
        data = self.collect()
        self.assertEqual(len(data["types"]), 10)
        self.assertEqual(len(data["ips_top"]), 10)
        self.assertEqual(data["examples"][0]["path"], "/latest")
        self.assertEqual(data["examples"][0]["event_id"], 13)
        self.assertEqual(data["examples"][0]["count"], 2)
        text = "".join(p.extract_text() for p in PdfReader(io.BytesIO(report.render_pdf(data))).pages)
        self.assertIn("/latest", text)
        self.assertNotIn("/outside", text)
        self.assertIn("[OCULTO]", text)
        self.assertNotIn("private-secret", text)

    def test_null_and_empty_categories_share_one_group(self):
        self.event(kind=None)
        self.event(kind="")
        data = self.collect()
        self.assertEqual(data["types"], [("Desconocido", 2)])
        self.assertEqual(data["examples"][0]["count"], 2)

    def test_missing_geo_does_not_invent_countries(self):
        self.db.execute("DROP TABLE ip_geo_cache")
        self.event()
        data = self.collect()
        self.assertEqual(data["countries"], [])
        self.assertEqual(data["geo_unknown"], 1)

    def test_long_untrusted_text_stays_inside_page(self):
        for i in range(10):
            ip = str(i) + "X"*150
            self.event(ip=ip, kind=str(i)+"W"*200, path="/á(\\)"*1200, query="q="+"W"*6000)
            self.db.execute("INSERT INTO ip_geo_cache VALUES (?,?,0)", (ip, str(i)+"W"*200))
        self.db.commit()
        reader = PdfReader(io.BytesIO(report.render_pdf(self.collect())), strict=True)
        for page in reader.pages:
            for operands, operator in ContentStream(page.get_contents(), reader).operations:
                if operator == b"Tm":
                    self.assertGreaterEqual(operands[5], 60 if operands[5] != 33 else 30)
                    self.assertLessEqual(operands[5], 815)
                    self.assertGreaterEqual(operands[4], 44)
            self.assertNotIn("/Annots", page)


if __name__ == "__main__":
    unittest.main()
