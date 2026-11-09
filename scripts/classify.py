#!/usr/bin/env python3
"""Local, offline classification of an IMAP Cleaner export (standard library only).

Layer 1: transparent heuristics (headers, authentication, domains, keywords,
         sender history). Layer 2 (optional): a *local* LLM for uncertain
         messages. The LLM can never trigger an action and can never override
         protection of important mail.

Nothing here touches the network except an optional loopback LLM endpoint. "Agent mode"
(--export-uncertain / --import-verdicts) only reads and writes local files; what the Hermes
agent does with the exported excerpts depends on the model the user has chosen in Hermes.
"""
import argparse
import json
import os
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone

import rules as R
from llm_local import LocalLLM, parse_verdict
from oc_common import ActionLog, registrable_domain

CATEGORIES = ["important_or_personal", "work", "financial_or_receipt", "government_or_legal",
              "security_or_account", "newsletter", "marketing", "automated_notification",
              "spam_or_phishing", "low_value", "uncertain"]
PROTECTED = {"important_or_personal", "work", "financial_or_receipt", "government_or_legal",
             "security_or_account"}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _hits(text, words):
    return [w for w in words if w in text]


def looks_like_person(name):
    name = (name or "").strip()
    if not name or re.search(r"\d|@|\b(as|asa|ab|inc|ltd|llc|gmbh|support|team|kundeservice|"
                              r"service|noreply|no-reply|info|sikkerhet|varsling|nyhetsbrev|"
                              r"admin|butikk|shop|store|bank)\b", name, re.I):
        return False
    words = name.replace(",", " ").split()
    return 2 <= len(words) <= 4 and all(w[:1].isupper() for w in words)


def is_gov_domain(reg, host):
    return reg in R.GOVERNMENT_DOMAINS or any(host.endswith(s) for s in R.GOVERNMENT_SUFFIXES)


def parse_dt(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def is_bulk(r):
    return bool(r.get("list_id") or r.get("list_unsubscribe") or
                r.get("precedence") in ("bulk", "list", "junk"))


# --------------------------------------------------------------------------
# context built from the full export
# --------------------------------------------------------------------------
class Context:
    def __init__(self, records, account=None, now=None):
        self.now = now or datetime.now(timezone.utc)
        self.account = (account or "").lower()
        self.own_domain = registrable_domain(self.account.split("@")[-1]) if "@" in self.account else ""
        self.own_is_freemail = self.own_domain in R.FREEMAIL_DOMAINS
        self.known = set()
        self.sender_n = Counter()
        self.sender_unseen = Counter()
        self.sender_answered = Counter()
        self.sender_bulk = Counter()
        for r in records:
            if r.get("folder_role") in ("sent", "drafts"):
                self.known.update(r.get("to_addrs", []) + r.get("cc_addrs", []))
                continue
            a = r.get("from_addr", "")
            self.sender_n[a] += 1
            if "\\Seen" not in r.get("flags", []):
                self.sender_unseen[a] += 1
            if "\\Answered" in r.get("flags", []):
                self.sender_answered[a] += 1
            if is_bulk(r):
                self.sender_bulk[a] += 1
        self.known.discard(self.account)


# --------------------------------------------------------------------------
# heuristic classifier
# --------------------------------------------------------------------------
def analyse(r, ctx):
    subj = (r.get("subject") or "").lower()
    body = (r.get("body_text_sample") or "").lower()
    text = subj + " " + body
    frm = r.get("from_addr", "")
    host = r.get("from_domain", "")
    reg = registrable_domain(host)
    name = r.get("from_name", "")
    flags = r.get("flags", [])
    auth = r.get("auth") or {}
    bulk = is_bulk(r)
    reasons, signals = [], []
    score = defaultdict(float)
    hard = []

    def add(cat, w, why):
        score[cat] += w
        reasons.append(why)

    auth_fail = auth.get("spf") == "fail" or auth.get("dmarc") == "fail"
    auth_ok = auth.get("dmarc") == "pass" or (auth.get("dkim") == "pass" and auth.get("spf") != "fail") \
        or (auth.get("spf") == "pass" and auth.get("dkim") != "fail")
    rp_reg = registrable_domain((r.get("return_path_addr") or "").split("@")[-1])
    esp = reg in R.ESP_DOMAINS or rp_reg in R.ESP_DOMAINS or \
        any(registrable_domain(d) in R.ESP_DOMAINS for d in r.get("dkim_domains", []))

    # --- threat score ---------------------------------------------------
    threat = 0.0
    threat_why = []

    def t(w, why):
        nonlocal threat
        threat += w
        threat_why.append(why)

    brand = None
    probe = set(re.split(r"[^a-z0-9]+", (name + " " + host).lower()))
    for b, legit in R.BRANDS.items():
        if b in probe and reg not in legit:
            brand = b
            break
    if brand:
        t(4, "sender claims to be '%s' but the domain is %s" % (brand, host))
    if auth.get("spf") == "fail":
        t(3, "SPF failed")
    if auth.get("dmarc") == "fail":
        t(2, "DMARC failed")
    if auth.get("dkim") == "fail":
        t(2, "DKIM failed")
    if auth.get("spf") == "softfail":
        t(1, "SPF softfail")
    if r.get("ip_links"):
        t(3, "link to a raw IP address")
    if r.get("href_text_mismatch"):
        t(3, "link text shows a different domain than the link target")
    if r.get("shortener_links"):
        t(1, "link shortener")
    if r.get("punycode_links"):
        t(2, "punycode domain in link")
    if any(host.endswith(x) for x in R.TLD_SUSPICIOUS):
        t(2, "sender domain with suspicious top-level domain")
    rt = r.get("reply_to_addr", "")
    if rt and registrable_domain(rt.split("@")[-1]) != reg and not esp:
        t(2, "Reply-To points to a different domain")
    if re.search(r"[\w.+-]+@[\w-]+\.\w+", name) and name.lower() != frm:
        t(3, "display name contains a different email address")
    risky = [a["name"] for a in r.get("attachments", [])
             if a.get("name", "").lower().endswith(R.RISKY_EXT)]
    if risky:
        t(3, "risky attachment (%s)" % ", ".join(risky[:2]))
    if r.get("x_spam_flag") == "yes" or r.get("x_spam_status", "").lower().startswith("yes"):
        t(4, "the server's spam filter flagged the message")
    ph = _hits(text, R.KW_PHISH)
    if ph:
        t(min(3, len(ph)), "typical phishing phrases (%s)" % ", ".join(ph[:3]))
    sp = _hits(text, R.KW_SPAM)
    if sp:
        t(min(6, 2 * len(sp)), "typical spam phrases (%s)" % ", ".join(sp[:3]))
    if r.get("folder_role") == "junk":
        t(1, "located in the Junk folder")
    direct = ctx.account in r.get("to_addrs", []) + r.get("cc_addrs", [])
    if ctx.account and not direct and not bulk:
        t(1, "you are not listed as a direct recipient")

    trusted_domain = reg in R.GOVERNMENT_DOMAINS or reg in R.FINANCIAL_DOMAINS or \
        reg in R.ACCOUNT_SECURITY_DOMAINS or host in R.ACCOUNT_SECURITY_DOMAINS or is_gov_domain(reg, host)
    if trusted_domain and auth_ok and not auth_fail:
        threat -= 4
    if ctx.sender_answered.get(frm) or frm in ctx.known:
        threat -= 3
    threat = max(0.0, threat)

    # --- hard protection --------------------------------------------------
    if frm in ctx.known and not bulk:
        hard.append("you have written to this sender yourself")
        add("important_or_personal", 6, "you have previously emailed this sender")
    if "\\Answered" in flags or "\\Forwarded" in flags:
        hard.append("message has been answered/forwarded")
        add("important_or_personal", 5, "message was answered or forwarded")
    if "\\Flagged" in flags:
        hard.append("message was flagged by you")
        add("important_or_personal", 4, "message is flagged")
    if ctx.sender_answered.get(frm) and not bulk:
        hard.append("you have answered earlier email from this sender")
        add("important_or_personal", 3, "sender previously answered")
    internal = bool(ctx.own_domain) and not ctx.own_is_freemail and reg == ctx.own_domain \
        and not auth_fail and not bulk
    if internal:
        hard.append("sender in own domain")
        add("work", 5, "sender in the same domain as the mailbox")
    thread = r.get("in_reply_to") and re.match(r"\s*(re|sv|fw|vs|fwd)\s*:", subj) and not bulk
    if thread:
        hard.append("part of a conversation (reply thread)")
        add("important_or_personal", 2, "part of a conversation thread")

    # --- category scoring -------------------------------------------------
    promo_kw = _hits(subj, R.KW_MARKETING)
    promo_body = _hits(body, R.KW_MARKETING)
    pct = bool(re.search(r"\d{1,3}\s?%", subj + " " + body[:600]))
    mkt = min(6, 2 * len(promo_kw)) + min(3, len(promo_body)) + \
        (2 if pct and (promo_kw or promo_body) else 0)
    if mkt and bulk:
        mkt += 1
    if mkt and esp:
        mkt += 1
    receipt_subj = _hits(subj, R.KW_RECEIPT)
    promotional = mkt >= 5 and not receipt_subj

    nl = _hits(text, R.KW_NEWSLETTER)
    nlw = (3 if r.get("list_id") else 0) + (2 if r.get("list_unsubscribe") else 0) + \
        min(3, len(nl)) + (2 if _hits(subj, R.KW_NEWSLETTER) else 0)
    if nlw:
        add("newsletter", nlw, "newsletter signals (List-Id/unsubscribe/phrases)")
    if mkt:
        add("marketing", mkt, "marketing language/infrastructure (%s)" %
            ", ".join((promo_kw + promo_body)[:3]))

    noreply = bool(re.search(R.NOREPLY_RX, frm))
    auto_kw = _hits(text, R.KW_AUTOMATED)
    auto = (2 if noreply else 0) + (3 if r.get("auto_submitted", "no") not in ("", "no") else 0) + \
        min(3, len(auto_kw))
    if auto:
        add("automated_notification", auto, "automatically generated message")

    if is_gov_domain(reg, host) and not promotional and not auth_fail and (auth_ok or not auth.get("spf")):
        add("government_or_legal", 6, "government sender domain (%s)" % reg)
    gov_s, gov_b = _hits(subj, R.KW_GOV_LEGAL), _hits(body, R.KW_GOV_LEGAL)
    if gov_s or gov_b:
        add("government_or_legal", 3 * min(1, len(gov_s)) + min(2, len(gov_b)), "government/legal content")
    if reg in R.FINANCIAL_DOMAINS and not promotional and not auth_fail:
        add("financial_or_receipt", 4, "known bank/vendor (%s)" % reg)
    if receipt_subj:
        add("financial_or_receipt", 4, "invoice/receipt/order in subject (%s)" % ", ".join(receipt_subj[:2]))
    rb = _hits(body, R.KW_RECEIPT)
    if rb and not promotional:
        add("financial_or_receipt", min(2, len(rb)), "finance-related content")
    sec_s, sec_b = _hits(subj, R.KW_SECURITY), _hits(body, R.KW_SECURITY)
    if sec_s or sec_b:
        add("security_or_account", 4 * min(1, len(sec_s)) + min(2, len(sec_b)),
            "account security/one-time code (%s)" % ", ".join((sec_s + sec_b)[:2]))
        if (reg in R.ACCOUNT_SECURITY_DOMAINS or host in R.ACCOUNT_SECURITY_DOMAINS) and auth_ok:
            add("security_or_account", 3, "known account provider (%s)" % reg)

    if not bulk and not esp and not noreply and looks_like_person(name) and not trusted_domain and \
            not promotional and threat < 4 and direct and len(text) > 30 and not auto:
        add("important_or_personal", 3, "looks like a personal message from a named person")
    work_kw = _hits(text, ["møte", "referat", "prosjekt", "leveranse", "frist", "deadline",
                           "meeting", "agenda", "teams", "vedlagt", "status"])
    if work_kw and internal:
        add("work", min(2, len(work_kw)), "work-related content")

    if threat >= 4:
        score["spam_or_phishing"] = threat
        reasons.extend(threat_why)

    # --- resolve ------------------------------------------------------------
    if not score or max(score.values()) < 3:
        cat, conf = "uncertain", 0.3
    else:
        ranked = sorted(score.items(), key=lambda kv: -kv[1])
        top_cat, top = ranked[0]
        second = ranked[1][1] if len(ranked) > 1 else 0
        prot = [(c, s) for c, s in ranked if c in PROTECTED and s >= 4]
        cat = top_cat
        if prot and top_cat not in PROTECTED and not (top_cat == "spam_or_phishing" and threat >= 8 and not hard):
            cat, top = prot[0]
            reasons.append("protected category takes precedence over %s" % top_cat)
        conf = min(0.97, 0.45 + 0.06 * top + 0.04 * max(0, top - second))

    protected = cat in PROTECTED
    conflict = threat >= 4 and (protected or bool(hard))
    if cat == "spam_or_phishing" and hard:
        cat, protected, conflict, conf = "uncertain", False, True, 0.4

    never_read = ctx.sender_n[frm] >= 3 and ctx.sender_unseen[frm] / ctx.sender_n[frm] >= 0.9
    recurring_bulk = ctx.sender_n[frm] >= 3 and ctx.sender_bulk[frm] / ctx.sender_n[frm] >= 0.5
    dt = parse_dt(r.get("date") or r.get("internaldate"))
    age = (ctx.now - dt).days if dt and dt.tzinfo else None

    if cat in ("newsletter", "marketing") and never_read and recurring_bulk:
        reasons.append("recurring bulk sender where %d of %d messages are unread" %
                       (ctx.sender_unseen[frm], ctx.sender_n[frm]))

    # --- action ------------------------------------------------------------
    if cat in PROTECTED:
        action = "keep" if conf >= 0.65 and not conflict else "review"
    elif cat == "spam_or_phishing":
        action = "quarantine_candidate" if threat >= 6 and conf >= 0.7 else "review"
    elif cat in ("newsletter", "marketing"):
        if conf < 0.6:
            action = "review"
        elif never_read and recurring_bulk:
            action = "quarantine_candidate"
        else:
            action = "archive_candidate"
    elif cat == "automated_notification":
        old_and_read = age is not None and age > 90 and "\\Seen" in flags and conf >= 0.6
        action = "archive_candidate" if old_and_read else ("keep" if conf >= 0.6 else "review")
    else:
        action = "review"
    if hard and action in ("quarantine_candidate", "archive_candidate"):
        action = "review"

    kind = None
    if cat == "spam_or_phishing":
        kind = "phishing" if (brand or r.get("ip_links") or r.get("href_text_mismatch") or len(ph) >= 2) else "spam"
    if conflict or kind == "phishing":
        signals.append("possible phishing: do not open links or attachments")

    return {
        "category": cat, "confidence": round(conf, 2), "action": action,
        "threat_score": round(threat, 1), "threat_kind": kind,
        "protected": protected or bool(hard), "protection_facts": hard,
        "bulk": bulk or esp, "recurring_bulk_sender": recurring_bulk,
        "sender_messages": ctx.sender_n[frm], "sender_unseen": ctx.sender_unseen[frm],
        "reason": "; ".join(dict.fromkeys(reasons))[:400] or "no strong signals",
        "signals": signals, "age_days": age,
        "sender_domain": reg or host, "llm_used": False,
    }


# --------------------------------------------------------------------------
# optional local-LLM layer
# --------------------------------------------------------------------------
def needs_llm(res, mode):
    if mode == "off":
        return False
    if mode == "all":
        return True
    return res["category"] == "uncertain" or res["confidence"] < 0.6


def merge_llm(res, verdict, label="local LLM"):
    """Merge a validated LLM verdict. Protection always wins; the LLM can only
    escalate a destructive suggestion when the heuristics already saw a threat."""
    if not verdict:
        return res
    out = dict(res)
    out["llm_used"] = True
    out["llm"] = verdict
    lcat, lconf = verdict["category"], verdict["confidence"]
    note = "%s: %s" % (label, verdict["reason"])
    if res["protection_facts"]:
        if lcat in PROTECTED and lcat != res["category"] and lconf >= 0.7:
            out["category"] = lcat
    elif lcat in PROTECTED and res["threat_score"] >= 8:
        # Phishing imitates legitimate mail: the LLM must not launder a rule-detected threat.
        out["action"] = res["action"]
        note += " (LLM suggested %s, but the rule engine found strong threat signals)" % lcat
    elif lcat in PROTECTED and lconf >= 0.6:
        out.update(category=lcat, protected=True,
                   confidence=round(max(res["confidence"], lconf * 0.9), 2),
                   action="keep" if lconf >= 0.8 else "review")
    elif res["category"] == "uncertain":
        out["category"] = lcat
        out["confidence"] = round(lconf * 0.9, 2)
        out["action"] = "review"
        if lconf >= 0.85:
            if lcat == "spam_or_phishing" and res["threat_score"] >= 4:
                out["action"] = "quarantine_candidate"
            elif lcat in ("newsletter", "marketing", "low_value"):
                out["action"] = "archive_candidate"
    elif lcat != res["category"] and lconf >= 0.8:
        out["action"] = "review"
        note += " (disagrees with the rule engine: %s)" % lcat
    elif lcat == res["category"]:
        out["confidence"] = round(min(0.98, res["confidence"] + 0.1), 2)
    if verdict.get("phishing_suspected") and not out["protected"]:
        out["threat_kind"] = out["threat_kind"] or "phishing"
        if out["action"] in ("keep", "archive_candidate"):
            out["action"] = "review"
    out["reason"] = (out["reason"] + "; " + note)[:520]
    return out


# --------------------------------------------------------------------------
def classify_all(records, account=None, llm=None, llm_mode="uncertain", llm_max=300, now=None,
                 progress=None):
    ctx = Context(records, account, now)
    out, used = [], 0
    for i, r in enumerate(records):
        if r.get("folder_role") in ("sent", "drafts"):
            res = {"category": "important_or_personal", "confidence": 1.0, "action": "keep",
                   "threat_score": 0, "threat_kind": None, "protected": True,
                   "protection_facts": ["own sent message/draft"], "bulk": False,
                   "recurring_bulk_sender": False, "sender_messages": 0, "sender_unseen": 0,
                   "reason": "own sent message or draft", "signals": [], "age_days": None,
                   "sender_domain": "", "llm_used": False, "own_message": True}
        else:
            res = analyse(r, ctx)
            if llm and used < llm_max and needs_llm(res, llm_mode):
                used += 1
                res = merge_llm(res, llm.classify(r, res), getattr(llm, "label", "local LLM"))
                if res["llm_used"] and getattr(llm, "source", None):
                    res["llm_source"] = llm.source
        out.append({
            "folder": r["folder"], "uid": r["uid"], "uidvalidity": r.get("uidvalidity"),
            "message_id": r.get("message_id"), "date": r.get("date"),
            "from": r.get("from"), "from_addr": r.get("from_addr"),
            "subject": r.get("subject"), "seen": "\\Seen" in r.get("flags", []),
            "folder_role": r.get("folder_role"), **res})
        if progress and (i + 1) % 200 == 0:
            progress(i + 1, len(records))
    return out


def load_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


# --------------------------------------------------------------------------
# agent mode: the Hermes agent (whatever model the user picked) writes the verdicts
# --------------------------------------------------------------------------
AGENT_PRIVACY_NOTICE = (
    "PRIVACY NOTICE: %s contains excerpts of your uncertain emails (sender, subject, short text excerpt).\n"
    "The Hermes model you have selected decides where the excerpts are sent when the agent reads the file: Ollama locally = stays on the machine;\n"
    "OpenRouter or another hosted model = the excerpts are sent to that provider. This skill cannot enforce local\n"
    "processing. Use Ollama for real email. Delete the export file when you are done.")
MAX_VERDICT_BYTES = 5_000_000


def agent_id(r):
    return "%s|%s|%s" % (r["folder"], r.get("uidvalidity"), r["uid"])


def _flat(text, n):
    return re.sub(r"\s+", " ", str(text or ""))[:n]


def _export_view(r, chars):
    """Copy of the record with a short body excerpt; '---' runs are collapsed so the excerpt
    cannot forge the UNTRUSTED BODY markers, and header fields are flattened to one line."""
    v = dict(r)
    v["body_text_sample"] = re.sub(r"-{3,}", "--", (r.get("body_text_sample") or "")[:chars])
    for k in ("from", "subject", "folder"):
        v[k] = _flat(r.get(k), 200)
    return v


class _Collector:
    """Stand-in 'LLM' that records which messages would be asked, and answers nothing."""
    def __init__(self):
        self.asked = []

    def classify(self, rec, heuristic):
        self.asked.append((rec, heuristic))


def export_uncertain(records, account, path, llm_max=300, chars=600):
    col = _Collector()
    results = classify_all(records, account, col, "uncertain", llm_max)
    with open(path, "w", encoding="utf-8") as fh:
        for rec, heur in col.asked:
            fh.write(json.dumps({"id": agent_id(rec),
                                 "prompt": LocalLLM.build_user_prompt(_export_view(rec, chars), heur, chars)},
                                ensure_ascii=False) + "\n")
    return results, len(col.asked)


class AgentVerdicts:
    """Validated verdicts written by the Hermes agent. Unknown ids and invalid verdicts are dropped;
    everything goes through parse_verdict and merge_llm, so protection guarantees are unchanged."""
    label = "Hermes model"
    source = "agent"

    def __init__(self, path):
        if os.path.getsize(path) > MAX_VERDICT_BYTES:
            raise SystemExit("ERROR: the verdict file is too large (max %d bytes)." % MAX_VERDICT_BYTES)
        self.verdicts, self.invalid, self.duplicate, self.requested = {}, 0, 0, set()
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    vid, conf = obj["id"], obj["confidence"]
                    if not isinstance(vid, str) or isinstance(conf, bool):
                        raise ValueError
                    verdict = parse_verdict(json.dumps({k: obj.get(k) for k in
                                                        ("category", "confidence", "reason", "phishing_suspected")}))
                except (ValueError, TypeError, KeyError, AttributeError):
                    verdict = None
                if verdict is None:
                    self.invalid += 1
                elif vid in self.verdicts:
                    self.duplicate += 1
                else:
                    self.verdicts[vid] = verdict

    def classify(self, rec, heuristic):
        vid = agent_id(rec)
        self.requested.add(vid)
        return self.verdicts.get(vid)

    @property
    def unknown(self):
        return len(set(self.verdicts) - self.requested)

    @property
    def applied(self):
        return len(set(self.verdicts) & self.requested)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Classify an IMAP Cleaner export locally")
    ap.add_argument("--input", default="reports/mailbox-audit.jsonl")
    ap.add_argument("--output", default="reports/classified.jsonl")
    ap.add_argument("--log", default="logs/actions.jsonl")
    ap.add_argument("--account", help="Own address (default: read from <input>.folders.json)")
    ap.add_argument("--llm", choices=["off", "ollama", "openai"], default="off",
                    help="Local LLM backend (loopback endpoints only)")
    ap.add_argument("--llm-url", default=None)
    ap.add_argument("--llm-model", default=None)
    ap.add_argument("--llm-mode", choices=["uncertain", "all"], default="uncertain")
    ap.add_argument("--llm-max", type=int, default=300, help="Max messages sent to the local LLM / exported to the agent")
    ap.add_argument("--llm-timeout", type=int, default=180)
    ap.add_argument("--export-uncertain", metavar="FILE",
                    help="Agent mode: write uncertain messages (short excerpts) to FILE for the Hermes agent")
    ap.add_argument("--import-verdicts", metavar="FILE",
                    help="Agent mode: merge the agent's verdicts (JSONL: id, category, confidence, reason, phishing_suspected)")
    ap.add_argument("--export-chars", type=int, default=600, help="Body excerpt length in the agent export")
    args = ap.parse_args(argv)
    if args.export_uncertain and args.import_verdicts:
        ap.error("--export-uncertain and --import-verdicts cannot be used together")
    if (args.export_uncertain or args.import_verdicts) and args.llm != "off":
        ap.error("agent mode cannot be combined with --llm")

    records = load_jsonl(args.input)
    account = args.account
    meta_path = re.sub(r"\.jsonl$", "", args.input) + ".folders.json"
    if not account and os.path.exists(meta_path):
        with open(meta_path, encoding="utf-8") as fh:
            account = json.load(fh).get("account")

    llm = None
    if args.llm != "off":
        llm = LocalLLM(args.llm, args.llm_url, args.llm_model, timeout=args.llm_timeout)
        llm.check_available()
    elif args.import_verdicts:
        llm = AgentVerdicts(args.import_verdicts)
    agent = bool(args.export_uncertain or args.import_verdicts)
    log = ActionLog(args.log, "classify")
    log.write("classify_start", input=args.input, messages=len(records), llm=args.llm,
              llm_model=args.llm_model, agent_mode=agent)
    exported = 0
    if args.export_uncertain:
        results, exported = export_uncertain(records, account, args.export_uncertain, args.llm_max, args.export_chars)
        log.write("agent_export", messages=exported, file=os.path.basename(args.export_uncertain))
    else:
        results = classify_all(records, account, llm, args.llm_mode if llm else "off", args.llm_max,
                               progress=lambda a, b: print("\r  %d/%d" % (a, b), end="", flush=True))
    for r in results:
        if agent:
            r["agent_mode"] = True
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        for r in results:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    cats = Counter(r["category"] for r in results)
    acts = Counter(r["action"] for r in results)
    used = sum(1 for r in results if r["llm_used"])
    log.write("classify_done", messages=len(results), categories=dict(cats), actions=dict(acts),
              llm_used=used, agent_mode=agent)
    if args.import_verdicts:
        log.write("agent_import", applied=llm.applied, invalid=llm.invalid, unknown=llm.unknown,
                  duplicate=llm.duplicate)
        print("\nClassified %d messages (Hermes model verdicts used on %d)." % (len(results), used))
        print("Verdicts: %d used, %d invalid, %d unknown ids, %d duplicates discarded." % (
            llm.applied, llm.invalid, llm.unknown, llm.duplicate))
    else:
        print("\nClassified %d messages locally (local LLM used on %d)." % (len(results), used))
    if args.export_uncertain:
        print("Exported %d uncertain messages to %s." % (exported, args.export_uncertain))
        print(AGENT_PRIVACY_NOTICE % args.export_uncertain)
    print("Categories:", dict(cats))
    print("Recommended actions:", dict(acts))
    print("No email was changed.")
    return results


if __name__ == "__main__":
    main()
