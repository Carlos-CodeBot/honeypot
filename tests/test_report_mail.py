import concurrent.futures
from contextlib import closing
from datetime import datetime, timedelta, timezone
from functools import wraps
import json
from pathlib import Path
import smtplib
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'app'))
import report_mail as mail
from flask import Flask, jsonify, session

MONDAY = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)
CONFIG = dict(mail.DEFAULTS, sender='honeypot@example.com', recipients=['soc@example.com'], password='secret-for-tests')


class MailTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name)/'honeypot.db'
        self.store = mail.Store(self.db_path)

    def tearDown(self):
        self.temp.cleanup()

    def save(self, **changes):
        self.store.save(dict(CONFIG, **changes), now=MONDAY-timedelta(days=1))

    def queued(self, kind='test'):
        self.save()
        self.store.tick(MONDAY)
        self.store.enqueue(kind, MONDAY)
        return self.store.tick(MONDAY)

    def test_credentials_encrypted_and_not_returned(self):
        self.save()
        self.assertNotIn(b'secret-for-tests', self.store.path.read_bytes())
        self.assertNotIn('secret-for-tests', json.dumps(self.store.status()))
        with closing(self.store.connect()) as db:
            token = db.execute('SELECT secret FROM settings').fetchone()[0]
        self.assertEqual(self.store.secrets(token)['password'], 'secret-for-tests')
        self.store.save(dict(CONFIG, password='', hour='09:00'), MONDAY)
        with closing(self.store.connect()) as db:
            token = db.execute('SELECT secret FROM settings').fetchone()[0]
        self.assertEqual(self.store.secrets(token)['password'], 'secret-for-tests')

    def test_invalid_settings(self):
        for change in [dict(sender='a@example.com\r\nBcc:x@y.com'), dict(recipients=['bad']),
                       dict(recipients=['a@example.com']*21), dict(hour='24:00'), dict(timezone='bogus'),
                       dict(weekday=True), dict(enabled='true'), dict(password=123), dict(transport='other'),
                       dict(transport='graph',tenant_id='../bad', client_id='invalid')]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.save(**change)

    def test_schedule_next_and_previous_complete_week(self):
        self.save(enabled=True)
        state = self.store.status()
        self.assertEqual(state['next_due'], '2026-09-21T12:00:00+00:00')
        job = self.store.tick(MONDAY)
        self.assertEqual((job['start'],job['end']), ('2026-09-14','2026-09-20'))
        self.assertEqual(self.store.status()['next_due'], '2026-09-28T12:00:00+00:00')
        self.assertIsNone(self.store.tick(MONDAY+timedelta(minutes=1)))

    def test_restart_does_not_duplicate_week(self):
        self.save(enabled=True)
        job = self.store.tick(MONDAY)
        self.store.mark(job['id'],'accepted')
        self.assertIsNone(mail.Store(self.db_path).tick(MONDAY+timedelta(minutes=2)))
        self.assertEqual(len(self.store.status()['jobs']), 1)

    def test_downtime_catches_only_latest_due_week(self):
        self.save(enabled=True)
        job = self.store.tick(MONDAY+timedelta(days=15))
        self.assertEqual(job['start'], '2026-09-28')
        self.assertEqual(len(self.store.status()['jobs']), 1)

    def test_dst_gap_and_fold(self):
        config = dict(CONFIG,timezone='America/New_York',weekday=6,hour='02:30')
        before = datetime(2026,3,8,6,0,tzinfo=timezone.utc)
        self.assertEqual(mail.slot(config,before), datetime(2026,3,8,7,30,tzinfo=timezone.utc))
        config['hour']='01:30'
        before = datetime(2026,11,1,4,0,tzinfo=timezone.utc)
        self.assertEqual(mail.slot(config,before), datetime(2026,11,1,5,30,tzinfo=timezone.utc))

    def test_settings_change_cancels_pending_and_disable_clears_schedule(self):
        self.save(enabled=True)
        self.store.tick(MONDAY-timedelta(minutes=1))
        self.store.enqueue('test',MONDAY)
        self.store.save(dict(CONFIG, enabled=False), MONDAY)
        self.assertEqual(self.store.status()['jobs'][0]['status'],'cancelled')
        self.assertIsNone(self.store.status()['next_due'])

    def test_manual_requires_worker_and_limits_double_clicks(self):
        self.save()
        with self.assertRaises(ValueError): self.store.enqueue('test', MONDAY)
        self.store.tick(MONDAY)
        self.store.enqueue('test', MONDAY)
        with self.assertRaises(ValueError): self.store.enqueue('test', MONDAY)

    def test_only_one_worker_claims_job(self):
        self.save(enabled=True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            jobs = list(pool.map(lambda _: self.store.tick(MONDAY), range(2)))
        self.assertEqual(sum(job is not None for job in jobs), 1)

    def test_crashed_send_is_uncertain_never_automatically_resent(self):
        job = self.queued()
        self.store.mark(job['id'],'sending')
        self.assertIsNone(self.store.tick(MONDAY+timedelta(minutes=16)))
        self.assertEqual(self.store.status()['jobs'][0]['status'],'uncertain')

    def test_snapshot_is_readonly_and_contains_correct_period(self):
        with closing(sqlite3.connect(self.db_path)) as db, db:
            db.execute('CREATE TABLE attack_logs(timestamp TEXT,is_attack INTEGER,severity TEXT,ip TEXT,path TEXT,attack_type TEXT)')
            db.execute("INSERT INTO attack_logs VALUES ('2026-09-15',1,'high','192.0.2.1','/search','sqli')")
        before = self.db_path.read_bytes()
        job = self.queued()
        data,pdf = mail.snapshot_report(self.store,job)
        self.assertEqual(data['attacks'],1)
        self.assertTrue(pdf.startswith(b'%PDF'))
        self.assertEqual(self.db_path.read_bytes(),before)
        self.assertFalse(list(self.store.directory.glob('pdf-*')))

    def test_smtp_starttls_before_login_and_pdf_attached(self):
        smtp = MagicMock()
        smtp.send_message.return_value={}
        sending = MagicMock()
        job = self.queued()
        with patch.object(mail.smtplib,'SMTP') as factory:
            factory.return_value.__enter__.return_value=smtp
            mail.deliver(CONFIG, {'password':'secret-for-tests'}, job,
                         dict(total=10,attacks=3,ips=2,urgent=1), b'%PDF-test',sending)
            factory.assert_called_once_with('smtp.office365.com',587,timeout=30)
        self.assertLess([c[0] for c in smtp.method_calls].index('starttls'),[c[0] for c in smtp.method_calls].index('login'))
        message=smtp.send_message.call_args.args[0]
        self.assertTrue(str(message['Subject']).startswith('[PRUEBA]'))
        self.assertEqual(next(message.iter_attachments()).get_content_type(),'application/pdf')
        sending.assert_called_once()

    def test_snapshot_finishes_with_commits_between_every_backup_batch(self):
        connect = sqlite3.connect
        with closing(connect(self.db_path)) as writer:
            writer.execute('PRAGMA journal_mode=WAL')
            writer.execute('CREATE TABLE attack_logs(timestamp TEXT,is_attack INTEGER,severity TEXT,ip TEXT,path TEXT,attack_type TEXT)')
            writer.execute("INSERT INTO attack_logs VALUES ('2026-09-15',1,'high','192.0.2.1','/search','sqli')")
            writer.execute('CREATE TABLE padding(data BLOB)')
            writer.executemany('INSERT INTO padding VALUES (zeroblob(4096))', [()]*800)
            writer.commit()
            batches=[]
            class ConcurrentCopy(sqlite3.Connection):
                def backup(source, target, **kwargs):
                    progress=kwargs['progress']
                    def with_write(status, remaining, total):
                        if remaining:
                            batches.append(remaining)
                            if len(batches)>20:
                                raise AssertionError('Backup restarted instead of retaining its snapshot')
                            writer.execute("INSERT INTO attack_logs VALUES ('2026-09-15',1,'high','192.0.2.2','/new','sqli')")
                            writer.commit()
                        progress(status,remaining,total)
                    return super().backup(target,**dict(kwargs,progress=with_write))
            def connection(path,*args,**kwargs):
                if kwargs.get('uri'): kwargs['factory']=ConcurrentCopy
                return connect(path,*args,**kwargs)
            with patch.object(mail.sqlite3,'connect',side_effect=connection):
                data,pdf=mail.snapshot_report(self.store,dict(start='2026-09-14',end='2026-09-20'))
            self.assertGreater(len(batches),1)
            self.assertEqual(data['attacks'],1)
            self.assertTrue(pdf.startswith(b'%PDF'))
            self.assertEqual(writer.execute('SELECT COUNT(*) FROM attack_logs').fetchone()[0],1+len(batches))
            self.assertEqual(writer.execute('PRAGMA journal_mode').fetchone()[0],'wal')

    def test_snapshot_timeout_releases_locks_cleans_temp_and_is_actionable(self):
        with closing(sqlite3.connect(self.db_path)) as db:
            db.execute('CREATE TABLE sample(id INTEGER)')
        with patch.object(mail.time,'monotonic',side_effect=[0,3]):
            with self.assertRaises(mail.SnapshotTimeout):
                mail.snapshot_report(self.store,dict(start='2026-09-14',end='2026-09-20'))
        self.assertFalse(list(self.store.directory.glob('pdf-*')))
        with closing(sqlite3.connect(self.db_path,timeout=.01)) as db, db:
            db.execute('INSERT INTO sample VALUES (1)')
        job=self.queued()
        with patch.object(mail,'snapshot_report',side_effect=mail.SnapshotTimeout('La copia SQLite superó el límite.')):
            mail.process_job(self.store,job)
        self.assertEqual(self.store.status()['jobs'][0]['detail'],'La copia SQLite superó el límite.')

    def test_graph_uses_fixed_endpoints_and_saves_sent_message(self):
        job=self.queued()
        config=dict(CONFIG,transport='graph',tenant_id='00000000-0000-0000-0000-000000000001',client_id='00000000-0000-0000-0000-000000000002')
        with patch.object(mail,'graph_json',side_effect=[(200,b'{"access_token":"TOKEN"}'),(202,b'')]) as graph:
            mail.deliver(config,{'client_secret':'secret'},job,dict(total=1,attacks=1,ips=1,urgent=1),b'%PDF',lambda:None)
        self.assertTrue(graph.call_args_list[0].args[0].startswith('https://login.microsoftonline.com/'))
        self.assertEqual(graph.call_args.args[0], 'https://graph.microsoft.com/v1.0/users/honeypot%40example.com/sendMail')
        body=json.loads(graph.call_args.args[1])
        self.assertTrue(body['saveToSentItems'])
        self.assertEqual(body['message']['attachments'][0]['contentBytes'],'JVBERg==')

    def test_failure_messages_never_persist_provider_secrets(self):
        job=self.queued()
        with patch.object(mail,'snapshot_report',return_value=({},b'pdf')), patch.object(mail,'deliver',side_effect=smtplib.SMTPAuthenticationError(535,b'password=secret-for-tests')):
            mail.process_job(self.store,job)
        state=self.store.status()
        self.assertEqual(state['jobs'][0]['status'],'failed')
        self.assertNotIn('secret-for-tests',json.dumps(state))

    def test_unknown_delivery_outcome_not_retried(self):
        job=self.queued()
        def unknown(*args):
            args[-1]()
            raise TimeoutError('secret-for-tests')
        with patch.object(mail,'snapshot_report',return_value=({},b'pdf')), patch.object(mail,'deliver',side_effect=unknown):
            mail.process_job(self.store,job)
        self.assertEqual(self.store.status()['jobs'][0]['status'],'uncertain')


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.path=Path(self.temp.name)/'data.db'
        app=Flask(__name__)
        app.secret_key='test-only'
        def admin_required(fn):
            @wraps(fn)
            def wrapped(*a,**kw):
                if session.get('role')!='admin': return jsonify(error='denied'),403
                return fn(*a,**kw)
            return wrapped
        mail.register_mail(app,admin_required,self.path)
        self.client=app.test_client()
    def tearDown(self): self.temp.cleanup()
    def login(self):
        with self.client.session_transaction() as s: s['role']='admin'
        return self.client.get('/dashboard/api/report-mail').json['csrf']
    def test_no_admin_no_access(self):
        self.assertEqual(self.client.get('/dashboard/api/report-mail').status_code,403)
        self.assertEqual(self.client.post('/dashboard/api/report-mail',json=CONFIG).status_code,403)
    def test_csrf_and_no_secret_roundtrip(self):
        token=self.login()
        self.assertEqual(self.client.post('/dashboard/api/report-mail',json=CONFIG).status_code,403)
        r=self.client.post('/dashboard/api/report-mail',json=CONFIG,headers={'X-CSRF-Token':token})
        self.assertEqual(r.status_code,200)
        self.assertNotIn('secret-for-tests',r.get_data(as_text=True))
        self.assertEqual(r.headers['Cache-Control'],'no-store')
    def test_send_enqueues_only_never_calls_network_in_request(self):
        token=self.login()
        self.client.post('/dashboard/api/report-mail',json=CONFIG,headers={'X-CSRF-Token':token})
        mail.Store(self.path).tick()
        with patch.object(mail,'deliver') as deliver:
            r=self.client.post('/dashboard/api/report-mail/send',json={'kind':'test'},headers={'X-CSRF-Token':token})
            self.assertEqual(r.status_code,202)
            deliver.assert_not_called()
    def test_reject_large_settings(self):
        token=self.login()
        r=self.client.post('/dashboard/api/report-mail',json=dict(CONFIG,password='x'*35000),headers={'X-CSRF-Token':token})
        self.assertEqual(r.status_code,413)


if __name__=='__main__': unittest.main()
