import hashlib
import io
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
import executive_report as report
from pypdf import PdfReader

class Reports(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "events.db"
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TABLE attack_logs(timestamp TEXT, is_attack INTEGER, severity TEXT, ip TEXT, path TEXT, attack_type TEXT)")
            db.executemany("INSERT INTO attack_logs VALUES (?,?,?,?,?,?)", [
                ("2026-01-01T00:00:00",1,"high","192.0.2.1","/login","sqli"),
                ("2026-01-02T23:59:59.999",1,"critical","192.0.2.2","/á(" + "\\" + "x)"*1000,"xss"),
                ("2026-01-02T12:00:00",0,"high","192.0.2.3","/","benign"),
                ("2025-12-31T12:00:00",1,"low","192.0.2.1","/","sqli"),
                ("2026-01-03T00:00:00",1,"high","192.0.2.1","/excluded","sqli"),
                ("invalid",1,"high","192.0.2.1","/invalid","sqli"),
            ])
        db.close()
    def tearDown(self): self.tmp.cleanup()
    def data(self): return report.collect(self.db,"2026-01-01","2026-01-02")
    def test_counts_boundaries_comparison(self):
        d=self.data()
        self.assertEqual((d["total"],d["attacks"],d["urgent"],d["ips"]),(3,2,2,2))
        self.assertEqual(d["previous"]["attacks"],1)
        self.assertEqual(sum(x[1] for x in d["types"]),2)
    def test_read_only(self):
        before=self.db.read_bytes()
        self.data()
        self.assertEqual(before,self.db.read_bytes())
    def test_missing_database_not_created(self):
        missing=self.db.parent/"missing.db"
        with self.assertRaises(sqlite3.OperationalError): report.collect(missing)
        self.assertFalse(missing.exists())
    def test_date_validation(self):
        for a,b in [("bad","2026-01-01"),("2026-01-03","2026-01-01"),("2025-01-01","2026-01-01"),("9999-12-31","9999-12-31")]:
            with self.subTest(a=a,b=b), self.assertRaises(ValueError): report.period(a,b)
    def test_empty_pdf(self):
        d=report.collect(self.db,"2024-01-01","2024-01-02")
        text="".join(p.extract_text() for p in PdfReader(io.BytesIO(report.render_pdf(d)),strict=True).pages)
        self.assertIn("No hay eventos",text)
        self.assertIn("No calculable",text)
    def test_pdf_structure_text_and_escaping(self):
        pdf=report.render_pdf(self.data())
        reader=PdfReader(io.BytesIO(pdf),strict=True)
        self.assertGreaterEqual(len(reader.pages),2)
        text="".join(p.extract_text() for p in reader.pages)
        self.assertIn("Informe ejecutivo",text)
        self.assertIn("á(",text)
        self.assertIn("Página 1",text)
        self.assertNotIn("/excluded",text)
        self.assertNotIn("/invalid",text)
    def test_query_deadline(self):
        with patch.object(report.time,"monotonic",side_effect=[0]+[100]*10000):
            with sqlite3.connect(self.db) as db:
                db.executemany("INSERT INTO attack_logs VALUES (?,?,?,?,?,?)",
                    [("2026-01-01",1,"high","ip","/","sqli")]*1000)
            db.close()
            with self.assertRaises(sqlite3.OperationalError): self.data()
    def test_locked_database(self):
        db=sqlite3.connect(self.db)
        try:
            db.execute("BEGIN EXCLUSIVE")
            with self.assertRaises(sqlite3.OperationalError): self.data()
        finally: db.close()

class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory()
        root=Path(cls.tmp.name)
        cls.env=patch.dict(os.environ, {
            "DB_PATH":str(root/"honeypot.db"),"CUSTOM_FRONT_DIR":str(root/"front"),
            "MODEL_PATH":str(root/"model"),"TRAINING_FILE":str(root/"training"),
            "SECRET_KEY":"test-only","ADMIN_USER":"test","ADMIN_PASS":"test-password",
            "ENABLE_PUBLIC_SITE":"0","ENABLE_DASHBOARD":"1","SESSION_COOKIE_SECURE":"0"})
        cls.env.start()
        import app
        cls.module=app
        cls.app=app.app
        cls.app.config["TESTING"]=True
    @classmethod
    def tearDownClass(cls):
        cls.env.stop(); cls.tmp.cleanup()
    def setUp(self):
        self.client=self.app.test_client()
        self.app.config["ENABLE_DASHBOARD"]=True
    def login(self):
        with self.client.session_transaction() as session:
            session["dashboard_user_id"]=1
    def test_anonymous_denied(self):
        self.assertEqual(self.client.get("/dashboard/api/executive-report.pdf").status_code,401)
    def test_mail_real_auth_and_role_guards(self):
        self.assertEqual(self.client.get('/dashboard/api/report-mail').status_code,401)
        self.login()
        self.assertEqual(self.client.get('/dashboard/api/report-mail').status_code,200)
        db=sqlite3.connect(self.module.DB_PATH)
        db.execute("UPDATE dashboard_users SET role='analyst' WHERE id=1");db.commit()
        try:
            self.assertEqual(self.client.get('/dashboard/api/report-mail').status_code,403)
            self.assertEqual(self.client.post('/dashboard/api/report-mail/send',json={'kind':'test'}).status_code,403)
            self.assertNotIn(b'id="mail-form"',self.client.get('/dashboard').data)
        finally:
            db.execute("UPDATE dashboard_users SET role='admin' WHERE id=1");db.commit();db.close()
        self.app.config['ENABLE_DASHBOARD']=False
        try: self.assertEqual(self.client.get('/dashboard/api/report-mail').status_code,404)
        finally: self.app.config['ENABLE_DASHBOARD']=True
    def test_authenticated_pdf_and_dashboard(self):
        self.login()
        response=self.client.get("/dashboard/api/executive-report.pdf?start=2026-01-01&end=2026-01-02")
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.mimetype,"application/pdf")
        self.assertEqual(response.headers["Cache-Control"],"no-store")
        PdfReader(io.BytesIO(response.data),strict=True)
        response=self.client.get("/dashboard")
        self.assertEqual(response.status_code,200)
        self.assertIn(b"executive-report.pdf",response.data)
    def test_disabled_dashboard(self):
        self.login()
        self.app.config["ENABLE_DASHBOARD"]=False
        try: self.assertEqual(self.client.get("/dashboard/api/executive-report.pdf").status_code,404)
        finally: self.app.config["ENABLE_DASHBOARD"]=True
    def test_invalid_dates(self):
        self.login()
        self.assertEqual(self.client.get("/dashboard/api/executive-report.pdf?start=no").status_code,400)
    def test_database_failure(self):
        self.login()
        with patch.object(report,"collect",side_effect=sqlite3.OperationalError("locked")):
            self.assertEqual(self.client.get("/dashboard/api/executive-report.pdf").status_code,503)
    def test_inactive_user(self):
        self.login()
        db=sqlite3.connect(self.module.DB_PATH)
        db.execute("UPDATE dashboard_users SET is_active=0 WHERE id=1");db.commit()
        try: self.assertEqual(self.client.get("/dashboard/api/executive-report.pdf").status_code,401)
        finally:
            db.execute("UPDATE dashboard_users SET is_active=1 WHERE id=1");db.commit();db.close()

if __name__=="__main__": unittest.main()
