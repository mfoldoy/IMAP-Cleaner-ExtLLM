#!/usr/bin/env python3
"""Build the human-readable review report (Markdown + CSV) from classified.jsonl.

The console output contains aggregate numbers only (no senders/subjects), so it is safe
to relay through an agent that uses a remote model. The report files themselves contain
private details and must stay on this machine.
"""
import argparse
import csv
import json
import os
from collections import Counter, defaultdict
from datetime import datetime

CAT_LABEL = {
    "important_or_personal": "Important/personal", "work": "Work", "financial_or_receipt": "Financial/receipt",
    "government_or_legal": "Government/legal", "security_or_account": "Security/account",
    "newsletter": "Newsletter", "marketing": "Marketing", "automated_notification": "Automated notification",
    "spam_or_phishing": "Spam/phishing", "low_value": "Low value", "uncertain": "Uncertain",
}
ACT_LABEL = {"keep": "Keep", "review": "Review", "archive_candidate": "Archive candidate",
             "quarantine_candidate": "Quarantine candidate"}


def load(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(l) for l in fh if l.strip()]


def cell(s, n=90):
    s = " ".join(str(s if s is not None else "").split()).replace("|", "¦")
    return s if len(s) <= n else s[:n - 1] + "…"


def csv_safe(s):
    s = str(s if s is not None else "")
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def table(headers, rows):
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    out += ["| " + " | ".join(cell(c, 90) for c in r) + " |" for r in rows]
    return "\n".join(out) + "\n"


def sender_rows(items, top=None):
    g = defaultdict(list)
    for r in items:
        g[r["from_addr"]].append(r)
    rows = []
    for addr, rs in sorted(g.items(), key=lambda kv: -len(kv[1])):
        cats = Counter(r["category"] for r in rs).most_common(1)[0][0]
        acts = Counter(r["action"] for r in rs).most_common(1)[0][0]
        unseen = sum(1 for r in rs if not r["seen"])
        rows.append([addr or "(unknown)", len(rs), unseen, CAT_LABEL.get(cats, cats), ACT_LABEL.get(acts, acts)])
    return rows[:top] if top else rows


def msg_rows(items, limit):
    items = sorted(items, key=lambda r: (r["folder"], str(r.get("date") or "")))
    return [[r["folder"], r["uid"], (r.get("date") or "")[:10], r["from_addr"], r["subject"],
             "%.2f" % r["confidence"], r["reason"]] for r in items[:limit]]


MSG_HEAD = ["Folder", "UID", "Date", "Sender", "Subject", "Conf.", "Reason"]


def build_markdown(res, meta):
    own = [r for r in res if r.get("own_message")]
    inc = [r for r in res if not r.get("own_message")]
    cats = Counter(r["category"] for r in inc)
    acts = Counter(r["action"] for r in inc)
    total = len(inc)
    md = []
    md.append("# Mailbox report (read-only)\n")
    md.append("Generated %s. No emails have been moved, deleted or modified.\n" % datetime.now().strftime("%Y-%m-%d %H:%M"))
    md.append("> This file contains private information. Keep it local; do not upload it or paste it into an online service.\n")

    md.append("## 1. Summary\n")
    md.append("- Incoming/stored messages analysed: **%d** (plus %d of your own sent/draft messages, which are always kept)\n" % (total, len(own)))
    agent = any(r.get("agent_mode") for r in res)
    if agent:
        md.append("- Uncertain messages were classified by the Hermes model (agent mode; location is decided by the user's model choice). "
                  "Hermes model verdicts used on %d messages.\n" % sum(1 for r in res if r.get("llm_source") == "agent"))
    else:
        md.append("- Local LLM used on %d messages.\n" % sum(1 for r in res if r.get("llm_used")))
    md.append("\n### By category\n")
    md.append(table(["Category", "Count", "Share"], [[CAT_LABEL.get(c, c), n, "%.1f%%" % (100 * n / total if total else 0)]
                                                     for c, n in cats.most_common()]))
    md.append("\n### By folder and category\n")
    per_folder = defaultdict(Counter)
    for r in inc:
        per_folder[r["folder"]][r["category"]] += 1
    md.append(table(["Folder", "Total", "Protected", "Bulk (newsletter/marketing)", "Spam/phishing", "Uncertain"],
                    [[f, sum(c.values()),
                      sum(v for k, v in c.items() if k in ("important_or_personal", "work", "financial_or_receipt", "government_or_legal", "security_or_account")),
                      c["newsletter"] + c["marketing"], c["spam_or_phishing"], c["uncertain"]]
                     for f, c in sorted(per_folder.items())]))

    md.append("\n## 2. Top senders by volume (top 25)\n")
    md.append(table(["Sender", "Count", "Unread", "Main category", "Main action"], sender_rows(inc, 25)))

    bulk = [r for r in inc if r["category"] in ("newsletter", "marketing") and not r["protected"]]
    md.append("\n## 3. Newsletter and marketing candidates\n")
    md.append("%d messages from %d senders. \"Unread\" shows how many you have never opened.\n\n" %
              (len(bulk), len({r['from_addr'] for r in bulk})))
    md.append(table(["Sender", "Count", "Unread", "Main category", "Main action"], sender_rows(bulk, 60)))

    threats = [r for r in inc if r["category"] == "spam_or_phishing"]
    phish = [r for r in threats if r.get("threat_kind") == "phishing"]
    md.append("\n## 4. Spam and phishing candidates\n")
    md.append("**Phishing (%d):** do not open links or attachments in these messages.\n\n" % len(phish))
    md.append(table(MSG_HEAD, msg_rows(phish, 200)))
    md.append("\n**Other spam (%d):**\n\n" % (len(threats) - len(phish)))
    md.append(table(MSG_HEAD, msg_rows([r for r in threats if r not in phish], 200)))

    junk_ok = [r for r in inc if r["folder_role"] == "junk" and r["protected"]]
    md.append("\n## 5. Possible false positives in Junk (protected content)\n")
    md.append("%d messages in Junk look legitimate and should be considered for manual move back.\n\n" % len(junk_ok))
    md.append(table(MSG_HEAD, msg_rows(junk_ok, 100)))
    md.append("\n### Protected messages in total\n")
    md.append(table(["Category", "Count"], [[CAT_LABEL[c], cats[c]] for c in
               ("important_or_personal", "work", "financial_or_receipt", "government_or_legal", "security_or_account")]))

    unc = [r for r in inc if r["category"] == "uncertain" or r["action"] == "review"]
    md.append("\n## 6. Uncertain messages that need manual review (%d)\n" % len(unc))
    md.append(table(MSG_HEAD, msg_rows(unc, 200)))
    if len(unc) > 200:
        md.append("\n(Showing 200 of %d; see candidates.csv for all.)\n" % len(unc))

    md.append("\n## 7. Recommended actions and estimated effect\n")
    q = [r for r in inc if r["action"] == "quarantine_candidate"]
    a = [r for r in inc if r["action"] == "archive_candidate"]
    md.append(table(["Action", "Messages", "Share of mailbox"],
                    [[ACT_LABEL[k], acts[k], "%.1f%%" % (100 * acts[k] / total if total else 0)] for k in ACT_LABEL]))
    md.append("\n1. **Quarantine (%d):** moved to `Hermes-Review` after your approval - can be undone by moving back.\n" % len(q))
    md.append("2. **Archive (%d):** low risk; can be moved to `Hermes-Review` or an archive folder after approval.\n" % len(a))
    md.append("3. **Review (%d):** no automatic action recommended.\n" % acts["review"])
    md.append("4. **Keep (%d):** important/protected - left untouched.\n" % acts["keep"])
    md.append("5. Unsubscribing and permanent deletion require separate approval and have not been done.\n")
    md.append("\nEstimated effect if 1 and 2 are approved: **%d** fewer messages in active folders (%.1f%%).\n" %
              (len(q) + len(a), 100 * (len(q) + len(a)) / total if total else 0))
    md.append("\n## 8. Method and safety\n")
    if agent:
        md.append("- The rule engine runs locally. Excerpts of uncertain messages (sender, subject, short text excerpt) were given to the Hermes model "
                  "(agent mode). **Classified by the Hermes model (location decided by the user's model choice):** with Ollama locally the "
                  "content does not leave the machine; with OpenRouter or another hosted model the excerpts are sent to that provider.\n")
    else:
        md.append("- Classification was done locally (rule engine + optional local LLM). No email content was sent to external services.\n")
    md.append("- Protection: messages you have answered/flagged, senders you have written to, your own domain, reply threads, "
              "and bank/government/security messages take precedence and are never proposed for quarantine.\n"
              "- All actions are logged in `logs/actions.jsonl` (without passwords).\n")
    return "\n".join(md)


def write_csv(res, path):
    cols = ["folder", "uid", "uidvalidity", "date", "from_addr", "subject", "category", "confidence",
            "action", "threat_kind", "reason"]
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for r in res:
            if r["action"] != "keep":
                w.writerow([csv_safe(r.get(c)) for c in cols])


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--classified", default="reports/classified.jsonl")
    ap.add_argument("--output-dir", default="reports")
    args = ap.parse_args(argv)
    res = load(args.classified)
    os.makedirs(args.output_dir, exist_ok=True)
    md_path = os.path.join(args.output_dir, "report.md")
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(build_markdown(res, None))
    csv_path = os.path.join(args.output_dir, "candidates.csv")
    write_csv(res, csv_path)
    inc = [r for r in res if not r.get("own_message")]
    cats, acts = Counter(r["category"] for r in inc), Counter(r["action"] for r in inc)
    print("Report written (only aggregate numbers are shown here):")
    print("  Messages analysed: %d" % len(inc))
    for c, n in cats.most_common():
        print("  %-24s %d" % (c, n))
    print("  Recommended actions:", dict(acts))
    print("  Report:     %s" % md_path)
    print("  Candidates: %s" % csv_path)
    print("No email was changed. The files contain private data and must stay local.")


if __name__ == "__main__":
    main()
