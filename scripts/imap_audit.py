#!/usr/bin/env python3
"""Read-only IMAP mailbox auditor (standard library only).

Never modifies the mailbox: folders are opened with EXAMINE, bodies are fetched
with BODY.PEEK, and only whitelisted commands are reachable (see SafeImap).
The password is read with a hidden prompt and is never stored or logged.
"""
import argparse
import getpass
import imaplib
import json
import os
import re
import socket
import ssl
import sys
from datetime import datetime, timezone

from oc_common import (ActionLog, DEFAULT_HOST, DEFAULT_PORT, SafeImap,
                       parse_message)

SKIP_ROLES = ("trash", "junk")


def folder_inventory(client, folders):
    rows = []
    for f in folders:
        row = {"name": f.name, "role": f.role, "flags": f.flags,
               "selectable": f.selectable}
        if f.selectable:
            try:
                row.update(client.status(f))
            except Exception as exc:  # inventory must not abort on one folder
                row["status_error"] = type(exc).__name__
        rows.append(row)
    return rows


def _fetch_batch(client, batch, spec, log, folder):
    for attempt in range(3):
        try:
            return client.uid_fetch(batch, spec)
        except (imaplib.IMAP4.abort, ssl.SSLError, socket.timeout, OSError, EOFError):
            log.write("reconnect", folder=folder, attempt=attempt + 1)
            client.reconnect()
    raise RuntimeError("giving up on batch in %s" % folder)


def export_folder(client, folder, out, args, log, stats):
    info = client.examine(folder.name)
    if info is None:
        print("  SKIP (cannot open read-only): %s" % folder.name)
        log.write("skip_folder", folder=folder.name, reason="examine_failed")
        return 0
    criteria = ["ALL"]
    if args.since:
        d = datetime.strptime(args.since, "%Y-%m-%d")
        criteria = ["SINCE", d.strftime("%d-%b-%Y")]
    uids = client.uid_search(*criteria)
    if args.limit:
        uids = uids[-args.limit:]
    n_done, failed = 0, 0
    spec = "(UID FLAGS RFC822.SIZE INTERNALDATE BODY.PEEK[]<0.%d>)" % args.fetch_bytes
    for i in range(0, len(uids), args.batch):
        batch = uids[i:i + args.batch]
        got = _fetch_batch(client, batch, spec, log, folder.name)
        for uid in batch:
            item = got.get(uid)
            if not item or not item["raw"]:
                failed += 1
                continue
            try:
                rec = parse_message(item["raw"], args.body_limit)
            except Exception:
                failed += 1
                log.write("parse_error", folder=folder.name, uid=uid)
                continue
            rec.update({
                "folder": folder.name, "folder_role": folder.role, "uid": uid,
                "uidvalidity": info["uidvalidity"],
                "flags": item["flags"], "size": item["size"],
                "internaldate": item["internaldate"],
                "body_truncated": bool(item["size"] and item["size"] > args.fetch_bytes),
            })
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n_done += 1
        print("\r  %s: %d/%d" % (folder.name, min(i + args.batch, len(uids)), len(uids)),
              end="", flush=True)
    print()
    log.write("export_folder", folder=folder.name, exported=n_done, failed=failed,
              uidvalidity=info["uidvalidity"])
    stats["failed"] += failed
    return n_done


def run_audit(client, args, log):
    folders = client.list_folders()
    inventory = folder_inventory(client, folders)
    print("Folders (%d):" % len(folders))
    for row in inventory:
        print("  %-40s role=%-8s messages=%s unseen=%s" % (
            row["name"], row["role"], row.get("messages", "-"), row.get("unseen", "-")))
    if args.test_connection:
        return {"folders": inventory, "exported": 0, "failed": 0}

    wanted = []
    for f in folders:
        if not f.selectable:
            continue
        if args.folders and f.name not in args.folders:
            continue
        if not args.include_trash_junk and f.role in SKIP_ROLES and not args.folders:
            print("  (skipping %s, use --include-trash-junk)" % f.name)
            continue
        wanted.append(f)

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    stats = {"failed": 0}
    total = 0
    with open(args.output, "w", encoding="utf-8") as out:
        for f in wanted:
            total += export_folder(client, f, out, args, log, stats)
    meta = {
        "account": args.user, "host": args.host,
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "folders": inventory, "exported": total, "failed": stats["failed"],
    }
    meta_path = re.sub(r"\.jsonl$", "", args.output) + ".folders.json"
    with open(meta_path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh, ensure_ascii=False, indent=2)
    return meta


def build_parser():
    ap = argparse.ArgumentParser(description="Read-only IMAP mailbox audit")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--user", required=True, help="Full email address")
    ap.add_argument("--output", default="reports/mailbox-audit.jsonl")
    ap.add_argument("--log", default="logs/actions.jsonl", help="Action log (JSONL)")
    ap.add_argument("--body-limit", type=int, default=4000,
                    help="Max text characters exported per message")
    ap.add_argument("--fetch-bytes", type=int, default=150000,
                    help="Max bytes fetched per message (partial fetch)")
    ap.add_argument("--batch", type=int, default=25, help="Messages per FETCH")
    ap.add_argument("--include-trash-junk", action="store_true",
                    help="Also scan Trash/Junk folders")
    ap.add_argument("--folders", nargs="*", help="Only these exact folder names")
    ap.add_argument("--limit", type=int, default=0, help="Newest N messages per folder")
    ap.add_argument("--since", help="Only messages since YYYY-MM-DD")
    ap.add_argument("--test-connection", action="store_true",
                    help="Login, list folders and counts only; export nothing")
    return ap


def main(argv=None, password=None, client_factory=None):
    args = build_parser().parse_args(argv)
    if "@" not in args.user:
        sys.exit("--user must be the full email address")
    if password is None:
        if not sys.stdin.isatty():
            sys.exit("Run in an interactive terminal: the password is read via a hidden prompt.")
        password = getpass.getpass("IMAP password (input hidden): ")
    log = ActionLog(args.log, "imap_audit")
    client = SafeImap(args.host, args.port, factory=client_factory, log=log)
    try:
        client.connect()
        client.login(args.user, password)
        password = None
        meta = run_audit(client, args, log)
    finally:
        client.logout()
    if args.test_connection:
        print("\nConnection test OK. Nothing was exported or modified.")
    else:
        print("\nRead-only audit complete: %d messages exported to %s (%d failed)." %
              (meta["exported"], args.output, meta["failed"]))
        print("The export contains private email content. Keep it local.")
    print("No mailbox flags, folders, or messages were modified.")
    return meta


if __name__ == "__main__":
    main()
