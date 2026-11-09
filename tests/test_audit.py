import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))

import imaplib  # noqa: E402

import fixtures  # noqa: E402
import imap_audit  # noqa: E402
import mock_imap  # noqa: E402
from oc_common import (ReadOnlyViolation, SafeImap, parse_list_item,  # noqa: E402
                       parse_message, utf7_decode, utf7_encode)


class Utf7Tests(unittest.TestCase):
    def test_roundtrip(self):
        for s in ["INBOX", "Søppelpost", "Prosjekter æøå", "A&B", "日本語", "a/b c"]:
            self.assertEqual(utf7_decode(utf7_encode(s)), s)
        self.assertEqual(utf7_decode("S&APg-ppelpost"), "Søppelpost")

    def test_list_parsing(self):
        f = parse_list_item(b'(\\HasNoChildren) "." "INBOX.Sent Items"')
        self.assertEqual((f.name, f.delimiter), ("INBOX.Sent Items", "."))
        self.assertEqual(f.role, "sent")
        f = parse_list_item(b'(\\Noselect \\HasChildren) "/" Public')
        self.assertFalse(f.selectable)
        f = parse_list_item(b'() "." "INBOX.S&APg-ppelpost"')
        self.assertEqual((f.name, f.role), ("INBOX.Søppelpost", "junk"))
        f = parse_list_item((b'() "/" {9}', b'My "Mail"'))
        self.assertEqual(f.name, 'My "Mail"')
        self.assertEqual(parse_list_item(b'(\\Trash) "/" "Slettede elementer"').role, "trash")


class ParseTests(unittest.TestCase):
    def test_phishing_features(self):
        raw = mock_imap.make_msg("DNB <a@dnb-x.xyz>", "me@x.no", "s", "t",
                                 {"Authentication-Results": "x; spf=fail; dkim=pass; dmarc=fail"},
                                 html=fixtures.PHISH_HTML)
        rec = parse_message(raw)
        self.assertEqual(rec["auth"]["spf"], "fail")
        self.assertEqual(rec["auth"]["dkim"], "pass")
        self.assertEqual(rec["ip_links"], 1)
        self.assertEqual(rec["href_text_mismatch"], 1)
        self.assertEqual(rec["from_domain"], "dnb-x.xyz")


class ImapAuditTests(unittest.TestCase):
    def setUp(self):
        self.state = fixtures.build_state()
        self.srv = mock_imap.start(self.state)
        self.port = self.srv.server_address[1]
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        self.srv.shutdown()

    def run_cli(self, *extra, password=mock_imap.PASSWORD):
        out = os.path.join(self.tmp, "audit.jsonl")
        argv = ["--host", "127.0.0.1", "--port", str(self.port), "--user", mock_imap.USER,
                "--output", out, "--log", os.path.join(self.tmp, "actions.jsonl"),
                "--include-trash-junk", *extra]
        with redirect_stdout(io.StringIO()) as buf:
            meta = imap_audit.main(argv, password=password,
                                   client_factory=lambda h, p: imaplib.IMAP4(h, p))
        return out, meta, buf.getvalue()

    def snapshot(self):
        return {n: {u: (m["raw"], frozenset(m["flags"])) for u, m in b[1].msgs.items()}
                for n, b in self.state.boxes.items() if b[1]}

    def test_export_is_read_only(self):
        before = self.snapshot()
        out, meta, _ = self.run_cli()
        self.assertEqual(self.snapshot(), before, "mailbox content or flags changed")
        self.assertEqual(self.state.writes(), [])
        self.assertFalse([c for c in self.state.log if c[0] == "SELECT"], "must use EXAMINE")
        self.assertTrue(any(c[0] == "EXAMINE" for c in self.state.log))
        recs = [json.loads(l) for l in open(out, encoding="utf-8")]
        self.assertEqual(len(recs), len(fixtures.MSGS))
        self.assertEqual(meta["failed"], 0)
        folders = {r["folder"] for r in recs}
        self.assertIn("INBOX.Prosjekter æøå", folders)
        self.assertIn("INBOX.Søppelpost", folders)
        self.assertNotIn("INBOX.Public", folders)
        r = next(r for r in recs if r["subject"].startswith("Middag"))
        self.assertEqual(r["uidvalidity"], 1001)
        self.assertIn("\\Answered", r["flags"])
        self.assertEqual(r["folder_role"], "inbox")

    def test_log_has_no_password_and_marks_nonmutating(self):
        self.run_cli()
        text = open(os.path.join(self.tmp, "actions.jsonl"), encoding="utf-8").read()
        self.assertNotIn(mock_imap.PASSWORD, text)
        recs = [json.loads(l) for l in text.splitlines()]
        self.assertTrue(recs and not any(r["mutating"] for r in recs))

    def test_skips_trash_junk_by_default(self):
        out = os.path.join(self.tmp, "a2.jsonl")
        argv = ["--host", "127.0.0.1", "--port", str(self.port), "--user", mock_imap.USER,
                "--output", out, "--log", os.path.join(self.tmp, "l.jsonl")]
        with redirect_stdout(io.StringIO()):
            imap_audit.main(argv, password=mock_imap.PASSWORD,
                            client_factory=lambda h, p: imaplib.IMAP4(h, p))
        folders = {json.loads(l)["folder"] for l in open(out, encoding="utf-8")}
        self.assertNotIn("INBOX.Søppelpost", folders)

    def test_connection_test_exports_nothing(self):
        out, meta, text = self.run_cli("--test-connection")
        self.assertFalse(os.path.exists(out))
        self.assertIn("Connection test OK", text)
        self.assertEqual(self.state.writes(), [])
        self.assertFalse([c for c in self.state.log if c[0] == "UID"])

    def test_bad_password_does_not_leak(self):
        with self.assertRaises(RuntimeError) as cm:
            self.run_cli(password="wrong-secret-123")
        self.assertNotIn("wrong-secret-123", str(cm.exception))

    def test_partial_fetch_and_limits(self):
        out, meta, _ = self.run_cli("--limit", "2", "--batch", "1")
        recs = [json.loads(l) for l in open(out, encoding="utf-8")]
        per_folder = {}
        for r in recs:
            per_folder[r["folder"]] = per_folder.get(r["folder"], 0) + 1
        self.assertTrue(all(v <= 2 for v in per_folder.values()))
        self.assertEqual(recs[0]["uid"], recs[0]["uid"])


class SafeImapGuardTests(unittest.TestCase):
    def setUp(self):
        self.state = fixtures.build_state()
        self.srv = mock_imap.start(self.state)
        self.c = SafeImap("127.0.0.1", self.srv.server_address[1],
                          factory=lambda h, p: imaplib.IMAP4(h, p))
        self.c.connect()
        self.c.login(mock_imap.USER, mock_imap.PASSWORD)

    def tearDown(self):
        self.c.logout()
        self.srv.shutdown()

    def test_non_peek_fetch_blocked(self):
        self.c.examine("INBOX")
        for bad in ["(BODY[])", "(RFC822)", "(UID BODY[TEXT])", "(BINARY[1])", "(RFC822.HEADER)"]:
            with self.assertRaises(ReadOnlyViolation, msg=bad):
                self.c.uid_fetch([1], bad)
        self.assertTrue(self.c.uid_fetch([1], "(UID FLAGS BODY.PEEK[]<0.500>)"))
        self.assertTrue(self.c.uid_fetch([1], "(UID RFC822.SIZE)"))

    def test_no_generic_passthrough(self):
        for name in ("store", "copy", "expunge", "delete", "append", "create", "rename"):
            self.assertFalse(hasattr(self.c, name))
        with self.assertRaises(ReadOnlyViolation):
            self.c.uid_search("DELETED")
        with self.assertRaises(ReadOnlyViolation):
            self.c.uid_search("ALL", "1:*; STORE")


if __name__ == "__main__":
    unittest.main()
