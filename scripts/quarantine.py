#!/usr/bin/env python3
"""Approved cleanup (Phase 4): move reviewed messages to a review folder. Never deletes.

Sub-commands:
  plan   Select candidates from classified.jsonl into an explicit plan file (no IMAP access).
  apply  Verify the plan against the live mailbox (read-only EXAMINE). Only with --execute AND
         a typed confirmation does it move messages (UID MOVE, or UID COPY + \\Deleted + UID EXPUNGE
         of exactly the copied UIDs when the server supports UIDPLUS).

Safety: protected messages can never be planned; UIDVALIDITY and Message-ID are re-checked
right before moving; permanent deletion, Trash/Junk destinations, unsubscribe and
mark-as-spam are not implemented.
"""
import argparse
import getpass
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

from oc_common import (ActionLog, DEFAULT_HOST, DEFAULT_PORT, ReadOnlyViolation, SafeImap,
                       decode_mime, quote_mailbox)

MOVABLE_ACTIONS = ("quarantine_candidate", "archive_candidate")
FORBIDDEN_DEST = re.compile(r"trash|deleted|slettede|papirkurv|søppel|junk|spam|bin$", re.I)
DEFAULT_DEST = "Hermes-Review"


def _norm(mid):
    return " ".join((mid or "").split())


# ---------------------------------------------------------------- plan
def build_plan(rows, categories=None, actions=None, senders=None, folders=None, min_conf=0.7):
    actions = actions or ["quarantine_candidate"]
    bad = set(actions) - set(MOVABLE_ACTIONS)
    if bad:
        raise SystemExit("Actions not movable: %s (allowed: %s)" % (", ".join(bad), ", ".join(MOVABLE_ACTIONS)))
    items = []
    for r in rows:
        if r.get("protected") or r.get("own_message") or r["action"] not in actions:
            continue
        if r["confidence"] < min_conf:
            continue
        if categories and r["category"] not in categories:
            continue
        if folders and r["folder"] not in folders:
            continue
        if senders and not any(r["from_addr"] == s or r["from_addr"].endswith("@" + s) or
                               r.get("sender_domain") == s for s in senders):
            continue
        items.append({k: r.get(k) for k in ("folder", "uidvalidity", "uid", "message_id", "from_addr",
                                            "subject", "date", "category", "action", "confidence")})
    return items


def print_plan(items, dest):
    print("Proposed action: MOVE to '%s' (no deletion). Count: %d\n" % (dest, len(items)))
    print("%-24s %-8s %-10s %-30s %-45s %s" % ("Folder", "UID", "Date", "Sender", "Subject", "Action"))
    for i in items:
        print("%-24s %-8s %-10s %-30s %-45s %s" % (
            i["folder"][:24], i["uid"], (i.get("date") or "")[:10], i["from_addr"][:30],
            (i["subject"] or "")[:45], i["action"]))


# ---------------------------------------------------------------- live
class WriteImap(SafeImap):
    """SafeImap plus the minimum write operations needed for moving into a review folder."""

    def select_rw(self, folder):
        typ, _ = self._c.select(quote_mailbox(folder), readonly=False)
        if typ != "OK":
            return None
        self._current = folder
        _, uv = self._c.response("UIDVALIDITY")
        return int(uv[0]) if uv and uv[0] else None

    def create(self, folder):
        if FORBIDDEN_DEST.search(folder):
            raise ReadOnlyViolation("destination looks like Trash/Junk: %s" % folder)
        typ, _ = self._c.create(quote_mailbox(folder))
        return typ == "OK"

    def has(self, cap):
        typ, data = self._c.capability()
        caps = (data[0] or b"").decode("utf-8", "replace").upper().split() if typ == "OK" and data else []
        return cap.upper() in caps

    def move(self, uids, dest):
        if FORBIDDEN_DEST.search(dest):
            raise ReadOnlyViolation("destination looks like Trash/Junk: %s" % dest)
        seq = ",".join(str(u) for u in uids)
        if self.has("MOVE"):
            typ, _ = self._c.uid("MOVE", seq, quote_mailbox(dest))
            return typ == "OK"
        if not self.has("UIDPLUS"):
            raise RuntimeError("Server supports neither MOVE nor UIDPLUS; refusing to move "
                               "(a plain EXPUNGE could remove unrelated messages).")
        typ, _ = self._c.uid("COPY", seq, quote_mailbox(dest))
        if typ != "OK":
            return False
        typ, _ = self._c.uid("STORE", seq, "+FLAGS.SILENT", "(\\Deleted)")
        if typ != "OK":
            return False
        typ, _ = self._c.uid("EXPUNGE", seq)
        return typ == "OK"


def pick_dest(folders, name):
    """Place the default review folder inside the INBOX namespace when the server uses one."""
    if name != DEFAULT_DEST:
        return name
    for f in folders:
        if f.delimiter and f.name.upper().startswith("INBOX" + f.delimiter):
            return "INBOX" + f.delimiter + DEFAULT_DEST
    return DEFAULT_DEST


def message_ids(client, uids):
    got = client.uid_fetch(uids, "(UID BODY.PEEK[HEADER.FIELDS (MESSAGE-ID)])")
    out = {}
    for uid, item in got.items():
        m = re.search(rb"(?im)^message-id:\s*(.+?)\s*$", item["raw"])
        out[uid] = _norm(m.group(1).decode("utf-8", "replace")) if m else ""
    return out


def verify(client, items, log):
    """Return ({folder: (uidvalidity, ok_items)}, problems). Read-only (EXAMINE)."""
    by_folder = defaultdict(list)
    for i in items:
        by_folder[i["folder"]].append(i)
    ok, problems = {}, []
    for folder, group in by_folder.items():
        info = client.examine(folder)
        if info is None:
            problems += [(i, "folder does not exist") for i in group]
            continue
        if info["uidvalidity"] != group[0]["uidvalidity"]:
            problems += [(i, "UIDVALIDITY changed (%s -> %s); the export is outdated" %
                          (group[0]["uidvalidity"], info["uidvalidity"])) for i in group]
            continue
        existing = set(client.uid_search("ALL"))
        live = [i for i in group if i["uid"] in existing]
        problems += [(i, "message no longer exists") for i in group if i["uid"] not in existing]
        ids = {}
        for k in range(0, len(live), 50):
            ids.update(message_ids(client, [i["uid"] for i in live[k:k + 50]]))
        good = []
        for i in live:
            if i.get("message_id") and ids.get(i["uid"], "") != _norm(i["message_id"]):
                problems.append((i, "Message-ID does not match"))
            else:
                good.append(i)
        ok[folder] = (group[0]["uidvalidity"], good)
    log.write("verify_plan", messages=len(items),
              verified=sum(len(g) for _, g in ok.values()), problems=len(problems))
    return ok, problems


def apply_plan(client, plan, execute, dest, log, confirm=input):
    folders = client.list_folders()
    dest = pick_dest(folders, dest)
    if FORBIDDEN_DEST.search(dest):
        raise SystemExit("Refusing destination %r (Trash/Junk-like)." % dest)
    ok, problems = verify(client, plan["items"], log)
    total = sum(len(g) for _, g in ok.values())
    print("Verified against the mailbox: %d can be moved, %d skipped." % (total, len(problems)))
    for i, why in problems:
        print("  SKIPPING %s UID %s: %s" % (i["folder"], i["uid"], why))
    if not execute:
        print("\nDRY RUN: nothing was changed. Use --execute to move to '%s'." % dest)
        return {"moved": 0, "verified": total, "skipped": len(problems)}
    if total == 0:
        return {"moved": 0, "verified": 0, "skipped": len(problems)}
    answer = confirm("\nType exactly 'MOVE %d' to move these %d messages to '%s': " % (total, total, dest))
    if answer.strip() != "MOVE %d" % total:
        print("Aborted. Nothing was changed.")
        log.write("execute_declined", planned=total)
        return {"moved": 0, "verified": total, "skipped": len(problems)}
    if dest not in [f.name for f in folders]:
        if not client.create(dest):
            raise SystemExit("Could not create %s" % dest)
        log.write("create_folder", mutating=True, folder=dest)
    moved = failed = 0
    for folder, (uv, good) in ok.items():
        if client.select_rw(folder) != uv:  # re-check right before writing
            print("  UIDVALIDITY changed for %s, skipping the folder" % folder)
            failed += len(good)
            continue
        for k in range(0, len(good), 25):
            batch = good[k:k + 25]
            uids = [i["uid"] for i in batch]
            if client.move(uids, dest):
                moved += len(batch)
                for i in batch:
                    log.write("move", mutating=True, folder=folder, uidvalidity=uv, uid=i["uid"],
                              message_id=i.get("message_id"), dest=dest, category=i["category"])
            else:
                failed += len(batch)
                log.write("move_failed", mutating=True, folder=folder, uids=uids, dest=dest)
    print("\nDone: %d moved to '%s', %d failed/skipped. Nothing was deleted." %
          (moved, dest, failed + len(problems)))
    return {"moved": moved, "verified": total, "skipped": failed + len(problems)}


def main(argv=None, password=None, client_factory=None, confirm=input):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--classified", default="reports/classified.jsonl")
    p.add_argument("--output", default="reports/plan.json")
    p.add_argument("--category", action="append", help="repeatable")
    p.add_argument("--action", action="append", choices=MOVABLE_ACTIONS, help="default: quarantine_candidate")
    p.add_argument("--sender", action="append", help="address or domain; repeatable")
    p.add_argument("--folder", action="append")
    p.add_argument("--min-confidence", type=float, default=0.7)
    p.add_argument("--dest", default=DEFAULT_DEST)
    a = sub.add_parser("apply")
    a.add_argument("--plan", default="reports/plan.json")
    a.add_argument("--host", default=DEFAULT_HOST)
    a.add_argument("--port", type=int, default=DEFAULT_PORT)
    a.add_argument("--user", required=True)
    a.add_argument("--log", default="logs/actions.jsonl")
    a.add_argument("--execute", action="store_true", help="Actually move (otherwise verified dry-run)")
    args = ap.parse_args(argv)

    if args.cmd == "plan":
        if FORBIDDEN_DEST.search(args.dest):
            raise SystemExit("Refusing destination %r (Trash/Junk-like)." % args.dest)
        with open(args.classified, encoding="utf-8") as fh:
            rows = [json.loads(l) for l in fh if l.strip()]
        items = build_plan(rows, args.category, args.action, args.sender, args.folder, args.min_confidence)
        print_plan(items, args.dest)
        plan = {"created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "dest": args.dest, "items": items}
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(plan, fh, ensure_ascii=False, indent=1)
        print("\nPlan saved: %s (nothing was moved)." % args.output)
        return plan

    with open(args.plan, encoding="utf-8") as fh:
        plan = json.load(fh)
    log = ActionLog(args.log, "quarantine")
    if password is None:
        if not sys.stdin.isatty():
            sys.exit("Run in an interactive terminal: the password is read via a hidden prompt.")
        password = getpass.getpass("IMAP password (input hidden): ")
    client = WriteImap(args.host, args.port, factory=client_factory, log=log)
    try:
        client.connect()
        client.login(args.user, password)
        password = None
        return apply_plan(client, plan, args.execute, plan.get("dest", DEFAULT_DEST), log, confirm)
    finally:
        client.logout()


if __name__ == "__main__":
    main()
