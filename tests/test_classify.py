import http.server
import imaplib
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))

import classify  # noqa: E402
import fixtures  # noqa: E402
import imap_audit  # noqa: E402
import llm_local  # noqa: E402
import mock_imap  # noqa: E402
import report  # noqa: E402


def export_fixture():
    state = fixtures.build_state()
    srv = mock_imap.start(state)
    tmp = tempfile.mkdtemp()
    out = os.path.join(tmp, "audit.jsonl")
    argv = ["--host", "127.0.0.1", "--port", str(srv.server_address[1]), "--user", mock_imap.USER,
            "--output", out, "--log", os.path.join(tmp, "a.jsonl"), "--include-trash-junk"]
    with redirect_stdout(io.StringIO()):
        imap_audit.main(argv, password=mock_imap.PASSWORD,
                        client_factory=lambda h, p: imaplib.IMAP4(h, p))
    srv.shutdown()
    return tmp, out, classify.load_jsonl(out)


class ClassifyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp, cls.audit_path, cls.records = export_fixture()
        cls.results = classify.classify_all(cls.records, mock_imap.USER)
        cls.by_subject = {r["subject"]: r for r in cls.results}

    def get(self, prefix):
        for s, r in self.by_subject.items():
            if s.startswith(prefix):
                return r
        self.fail("no message " + prefix)

    def check(self, prefix, cat, action):
        r = self.get(prefix)
        self.assertEqual((r["category"], r["action"]), (cat, action), r["reason"])
        return r

    def test_protected_mail_is_kept(self):
        self.check("Skattemelding", "government_or_legal", "keep")
        self.check("Middag", "important_or_personal", "keep")
        self.check("Faktura for oktober", "financial_or_receipt", "keep")
        self.check("Sikkerhetsvarsel", "security_or_account", "keep")
        self.check("Hei", "important_or_personal", "keep")        # known correspondent via Sent
        self.assertIn(self.get("Re: Møtereferat")["category"], ("work", "important_or_personal"))
        self.assertEqual(self.get("Re: Møtereferat")["action"], "keep")
        self.assertEqual(self.get("Prosjektplan")["action"], "keep")

    def test_legit_mail_in_junk_is_never_quarantined(self):
        r = self.check("Kvittering fra Vipps", "financial_or_receipt", "keep")
        self.assertEqual(r["folder_role"], "junk")

    def test_phishing_and_spam(self):
        r = self.check("Din konto er sperret", "spam_or_phishing", "quarantine_candidate")
        self.assertEqual(r["threat_kind"], "phishing")
        self.assertTrue(r["signals"])
        self.check("Congratulations", "spam_or_phishing", "quarantine_candidate")
        self.check("Cheap viagra", "spam_or_phishing", "quarantine_candidate")

    def test_bulk(self):
        self.check("Ukens nyhetsbrev", "newsletter", "archive_candidate")
        for s in ("50% rabatt", "Nye tilbud", "Salg!"):
            r = self.check(s, "marketing", "quarantine_candidate")
            self.assertTrue(r["recurring_bulk_sender"])
        self.assertEqual(self.get("[repo] Run failed")["category"], "automated_notification")

    def test_uncertain_goes_to_review(self):
        self.check("Se her", "uncertain", "review")

    def test_nothing_protected_is_destructive(self):
        for r in self.results:
            if r["protected"]:
                self.assertNotIn(r["action"], ("quarantine_candidate", "archive_candidate"), r["subject"])

    def test_classified_output_has_no_body(self):
        for r in self.results:
            self.assertNotIn("body_text_sample", r)

    def test_report_generation(self):
        cls_path = os.path.join(self.tmp, "classified.jsonl")
        with open(cls_path, "w", encoding="utf-8") as fh:
            for r in self.results:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        with redirect_stdout(io.StringIO()) as buf:
            report.main(["--classified", cls_path, "--output-dir", self.tmp])
        md = open(os.path.join(self.tmp, "report.md"), encoding="utf-8").read()
        for heading in ("Summary", "Top senders", "Phishing", "Newsletter", "Uncertain", "Recommended actions"):
            self.assertIn(heading, md)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "candidates.csv")))
        # stdout summary must be aggregate only: no subjects or sender addresses
        self.assertNotIn("Skattemelding", buf.getvalue())
        self.assertNotIn("@", buf.getvalue())


class FakeOllama(http.server.BaseHTTPRequestHandler):
    reply = {"category": "marketing", "confidence": 0.9, "reason": "tilbud", "phishing_suspected": False}
    seen = []

    def log_message(self, *a):
        pass

    def do_GET(self):
        body = json.dumps({"models": [{"name": "fake:1b"}]}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        n = int(self.headers["Content-Length"])
        FakeOllama.seen.append(json.loads(self.rfile.read(n)))
        body = json.dumps({"message": {"content": json.dumps(FakeOllama.reply)}}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)


class LlmTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = http.server.HTTPServer(("127.0.0.1", 0), FakeOllama)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.url = "http://127.0.0.1:%d" % cls.srv.server_address[1]
        cls.tmp, cls.path, cls.records = export_fixture()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_refuses_remote_endpoints(self):
        for url in ("https://openrouter.ai/api/v1", "http://192.168.1.5:11434", "http://example.com"):
            with self.assertRaises(llm_local.LocalOnlyError):
                llm_local.LocalLLM("ollama", url, "m")
        llm_local.LocalLLM("ollama", "http://localhost:11434", "m")
        llm_local.LocalLLM("ollama", "http://[::1]:11434", "m")

    def test_verdict_validation(self):
        self.assertIsNone(llm_local.parse_verdict("not json"))
        self.assertIsNone(llm_local.parse_verdict('{"category":"hack","confidence":0.9}'))
        self.assertIsNone(llm_local.parse_verdict('{"category":"work","confidence":7}'))
        v = llm_local.parse_verdict('x {"category":"work","confidence":0.8,"reason":"r"} y')
        self.assertEqual(v["category"], "work")

    def test_llm_resolves_uncertain_but_cannot_quarantine_alone(self):
        llm = llm_local.LocalLLM("ollama", self.url, "fake:1b")
        llm.check_available()
        FakeOllama.seen.clear()
        res = classify.classify_all(self.records, mock_imap.USER, llm, "uncertain")
        r = next(x for x in res if x["subject"] == "Se her")
        self.assertTrue(r["llm_used"])
        self.assertEqual(r["category"], "marketing")
        self.assertEqual(r["action"], "archive_candidate")
        # only the uncertain message was sent to the (local) model
        self.assertEqual(len(FakeOllama.seen), 1)
        prompt = FakeOllama.seen[0]["messages"][1]["content"]
        self.assertIn("UNTRUSTED", prompt)
        # protected mail unchanged
        self.assertEqual(next(x for x in res if x["subject"].startswith("Middag"))["action"], "keep")

    def test_llm_cannot_demote_protected(self):
        FakeOllama.reply = {"category": "spam_or_phishing", "confidence": 0.99, "reason": "x",
                            "phishing_suspected": True}
        try:
            llm = llm_local.LocalLLM("ollama", self.url, "fake:1b")
            res = classify.classify_all(self.records, mock_imap.USER, llm, "all")
            for x in res:
                if x["protected"]:
                    self.assertNotIn(x["action"], ("quarantine_candidate", "archive_candidate"), x["subject"])
            vipps = next(x for x in res if x["subject"].startswith("Kvittering"))
            self.assertEqual(vipps["category"], "financial_or_receipt")
        finally:
            FakeOllama.reply = {"category": "marketing", "confidence": 0.9, "reason": "tilbud",
                                "phishing_suspected": False}


    def test_llm_cannot_launder_detected_phishing(self):
        FakeOllama.reply = {"category": "security_or_account", "confidence": 0.95, "reason": "x",
                            "phishing_suspected": False}
        try:
            llm = llm_local.LocalLLM("ollama", self.url, "fake:1b")
            res = classify.classify_all(self.records, mock_imap.USER, llm, "all")
            x = next(r for r in res if r["subject"].startswith("Din konto er sperret"))
            self.assertFalse(x["protected"])
            self.assertEqual(x["category"], "spam_or_phishing")
            self.assertEqual(x["action"], "quarantine_candidate")
        finally:
            FakeOllama.reply = {"category": "marketing", "confidence": 0.9, "reason": "tilbud",
                                "phishing_suspected": False}


if __name__ == "__main__":
    unittest.main()
