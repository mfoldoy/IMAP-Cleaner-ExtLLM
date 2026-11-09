import imaplib
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

import classify  # noqa: E402
import mock_imap  # noqa: E402
import quarantine  # noqa: E402
from test_classify import export_fixture  # noqa: E402
import fixtures  # noqa: E402
import imap_audit  # noqa: E402


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.state = fixtures.build_state()
        self.srv = mock_imap.start(self.state)
        self.port = self.srv.server_address[1]
        self.tmp = tempfile.mkdtemp()
        audit = os.path.join(self.tmp, "audit.jsonl")
        with redirect_stdout(io.StringIO()):
            imap_audit.main(["--host", "127.0.0.1", "--port", str(self.port), "--user", mock_imap.USER,
                             "--output", audit, "--log", os.path.join(self.tmp, "a.jsonl"),
                             "--include-trash-junk"], password=mock_imap.PASSWORD,
                            client_factory=lambda h, p: imaplib.IMAP4(h, p))
        self.rows = classify.classify_all(classify.load_jsonl(audit), mock_imap.USER)
        self.state.log.clear()
        self.logpath = os.path.join(self.tmp, "q.jsonl")
        self.classified = os.path.join(self.tmp, "classified.jsonl")
        with open(self.classified, "w", encoding="utf-8") as fh:
            for r in self.rows:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        self.planpath = os.path.join(self.tmp, "plan.json")

    def tearDown(self):
        self.srv.shutdown()

    def make_plan(self, *extra):
        with redirect_stdout(io.StringIO()):
            return quarantine.main(["plan", "--classified", self.classified, "--output", self.planpath, *extra])

    def apply(self, *extra, confirm=lambda prompt: ""):
        with redirect_stdout(io.StringIO()) as buf:
            res = quarantine.main(["apply", "--plan", self.planpath, "--host", "127.0.0.1",
                                   "--port", str(self.port), "--user", mock_imap.USER,
                                   "--log", self.logpath, *extra],
                                  password=mock_imap.PASSWORD,
                                  client_factory=lambda h, p: imaplib.IMAP4(h, p), confirm=confirm)
        return res, buf.getvalue()

    def count(self):
        return {n: len(b[1].msgs) for n, b in self.state.boxes.items() if b[1]}

    def test_plan_never_contains_protected(self):
        plan = self.make_plan("--action", "quarantine_candidate", "--action", "archive_candidate")
        self.assertTrue(plan["items"])
        protected = {(r["folder"], r["uid"]) for r in self.rows if r["protected"]}
        self.assertFalse(protected & {(i["folder"], i["uid"]) for i in plan["items"]})

    def test_dry_run_changes_nothing(self):
        self.make_plan()
        before = self.count()
        res, _ = self.apply()
        self.assertEqual(res["moved"], 0)
        self.assertEqual(self.state.writes(), [])
        self.assertEqual(self.count(), before)

    def test_wrong_confirmation_changes_nothing(self):
        self.make_plan()
        res, _ = self.apply("--execute", confirm=lambda p: "yes")
        self.assertEqual(res["moved"], 0)
        self.assertEqual(self.state.writes(), [])

    def test_execute_moves_only_planned_and_never_deletes(self):
        plan = self.make_plan()
        n = len(plan["items"])
        self.assertGreater(n, 0)
        before_total = sum(self.count().values())
        res, _ = self.apply("--execute", confirm=lambda p: "MOVE %d" % n)
        self.assertEqual(res["moved"], n)
        after = self.count()
        self.assertEqual(sum(after.values()), before_total)  # nothing lost
        dest = [k for k in after if k.endswith("Hermes-Review")]
        self.assertEqual(len(dest), 1)
        self.assertEqual(after[dest[0]], n)
        subjects = [m["raw"] for m in self.state.boxes[dest[0]][1].msgs.values()]
        self.assertTrue(all(b"Vipps" not in s and b"Skattemelding" not in s for s in subjects))
        entries = [json.loads(l) for l in open(self.logpath, encoding="utf-8")]
        self.assertEqual(sum(1 for e in entries if e["action"] == "move"), n)
        self.assertNotIn(mock_imap.PASSWORD, open(self.logpath, encoding="utf-8").read())
        self.assertFalse([c for c in self.state.log if c[0] == "DELETE"])

    def test_uidvalidity_change_blocks_move(self):
        plan = self.make_plan()
        folder = plan["items"][0]["folder"]
        self.state.boxes[folder][1].uidvalidity += 1
        before = self.count()
        res, out = self.apply("--execute", confirm=lambda p: "MOVE 0")
        self.assertEqual(res["moved"], 0)
        self.assertIn("UIDVALIDITY", out)
        self.assertEqual(self.count(), before)

    def test_message_id_mismatch_is_skipped(self):
        plan = self.make_plan()
        it = plan["items"][0]
        it["message_id"] = "<other@x>"
        with open(self.planpath, "w", encoding="utf-8") as fh:
            json.dump(plan, fh)
        res, out = self.apply()
        self.assertIn("Message-ID", out)
        self.assertEqual(res["verified"], len(plan["items"]) - 1)

    def test_trash_destination_refused(self):
        with self.assertRaises(SystemExit):
            self.make_plan("--dest", "Trash")

    def test_no_move_without_move_or_uidplus(self):
        plan = self.make_plan()
        self.state.capability = "IMAP4rev1"
        n = len(plan["items"])
        with self.assertRaises(RuntimeError):
            self.apply("--execute", confirm=lambda p: "MOVE %d" % n)
        self.assertEqual([c for c in self.state.writes() if c[0] == "UID"], [])

    def test_uidplus_copy_fallback(self):
        plan = self.make_plan()
        self.state.capability = "IMAP4rev1 UIDPLUS"
        n = len(plan["items"])
        res, _ = self.apply("--execute", confirm=lambda p: "MOVE %d" % n)
        self.assertEqual(res["moved"], n)


if __name__ == "__main__":
    unittest.main()
