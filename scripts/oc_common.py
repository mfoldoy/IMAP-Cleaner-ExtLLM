"""Shared helpers for IMAP Cleaner (standard library only).

Contains: IMAP modified UTF-7, LIST parsing, a command-whitelisting IMAP client
(`SafeImap`), message parsing/feature extraction and the action log.
"""
import base64
import email
import imaplib
import json
import re
import ssl
import uuid
from datetime import datetime, timezone
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime
from html.parser import HTMLParser
from urllib.parse import urlsplit

DEFAULT_HOST = "imap1.stwcp.net"
DEFAULT_PORT = 993


# --------------------------------------------------------------------------
# Modified UTF-7 (RFC 3501 5.1.3)
# --------------------------------------------------------------------------
def utf7_decode(s):
    def repl(m):
        chunk = m.group(1)
        if chunk == "":
            return "&"
        b64 = chunk.replace(",", "/")
        b64 += "=" * (-len(b64) % 4)
        return base64.b64decode(b64).decode("utf-16-be", errors="replace")

    return re.sub(r"&([^-]*)-", repl, s)


def utf7_encode(s):
    out, buf = [], []

    def flush():
        if buf:
            raw = "".join(buf).encode("utf-16-be")
            enc = base64.b64encode(raw).decode("ascii").rstrip("=").replace("/", ",")
            out.append("&" + enc + "-")
            buf.clear()

    for ch in s:
        if 0x20 <= ord(ch) <= 0x7E:
            flush()
            out.append("&-" if ch == "&" else ch)
        else:
            buf.append(ch)
    flush()
    return "".join(out)


def quote_mailbox(decoded_name):
    enc = utf7_encode(decoded_name)
    return '"' + enc.replace("\\", "\\\\").replace('"', '\\"') + '"'


# --------------------------------------------------------------------------
# Folder listing
# --------------------------------------------------------------------------
_LIST_RE = re.compile(
    r'^\((?P<flags>[^)]*)\)\s+(?P<delim>"(?:[^"\\]|\\.)*"|NIL)\s+(?P<name>.*)$', re.S)


class Folder:
    __slots__ = ("name", "delimiter", "flags", "role")

    def __init__(self, name, delimiter, flags, role):
        self.name, self.delimiter, self.flags, self.role = name, delimiter, flags, role

    @property
    def selectable(self):
        low = {f.lower() for f in self.flags}
        return "\\noselect" not in low and "\\nonexistent" not in low


_ROLE_FLAGS = {"\\trash": "trash", "\\junk": "junk", "\\sent": "sent",
               "\\drafts": "drafts", "\\archive": "archive", "\\all": "archive"}
_ROLE_NAMES = [
    ("junk", re.compile(r"junk|spam|søppelpost|bulk")),
    ("trash", re.compile(r"trash|deleted|slettede|papirkurv|søppelkurv|^bin$")),
    ("sent", re.compile(r"sent|sendte")),
    ("drafts", re.compile(r"draft|utkast")),
    ("archive", re.compile(r"archive|arkiv")),
]


def detect_role(name, delimiter, flags):
    for f in flags:
        if f.lower() in _ROLE_FLAGS:
            return _ROLE_FLAGS[f.lower()]
    if name.upper() == "INBOX":
        return "inbox"
    leaf = name.split(delimiter)[-1].lower() if delimiter else name.lower()
    for role, rx in _ROLE_NAMES:
        if rx.search(leaf):
            return role
    return "other"


def _unquote(tok):
    tok = tok.strip()
    if len(tok) >= 2 and tok[0] == '"' and tok[-1] == '"':
        return re.sub(r"\\(.)", r"\1", tok[1:-1])
    return tok


def parse_list_item(item):
    """Parse one imaplib LIST item (bytes, or (bytes, literal) tuple)."""
    if isinstance(item, tuple):
        head = item[0].decode("utf-8", "replace")
        lit = item[1].decode("utf-8", "replace")
        head = re.sub(r"\{\d+\}\s*$", "", head)
        line = head + '"' + lit.replace("\\", "\\\\").replace('"', '\\"') + '"'
    elif isinstance(item, bytes):
        line = item.decode("utf-8", "replace")
    else:
        return None
    m = _LIST_RE.match(line.strip())
    if not m:
        return None
    flags = m.group("flags").split()
    delim = m.group("delim")
    delim = None if delim == "NIL" else _unquote(delim)
    name = utf7_decode(_unquote(m.group("name")))
    return Folder(name, delim, flags, detect_role(name, delim, flags))


# --------------------------------------------------------------------------
# Action log (never contains passwords or message content)
# --------------------------------------------------------------------------
class ActionLog:
    def __init__(self, path, tool):
        self.path, self.tool, self.run_id = path, tool, uuid.uuid4().hex[:12]
        if path:
            import os
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def write(self, action, mutating=False, **fields):
        if not self.path:
            return
        rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "run": self.run_id, "tool": self.tool, "action": action,
               "mutating": mutating}
        rec.update(fields)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")


# --------------------------------------------------------------------------
# Read-only IMAP client
# --------------------------------------------------------------------------
class ReadOnlyViolation(RuntimeError):
    pass


_FETCH_BAD = re.compile(r"(?<!\.PEEK)\bBODY\[|\bRFC822(?!\.SIZE)\b|\bBINARY\[", re.I)
_FETCH_OK_ATTR = re.compile(r"^[A-Z0-9.\[\]<>() ,_-]+$", re.I)


class SafeImap:
    """Thin wrapper exposing only non-mutating IMAP operations.

    Mailboxes are opened with EXAMINE (read-only) and message bodies are fetched
    with BODY.PEEK only, so \\Seen flags are never altered. Any attempt to use
    another command raises ReadOnlyViolation (there is no generic passthrough).
    """

    def __init__(self, host=DEFAULT_HOST, port=DEFAULT_PORT, timeout=60,
                 factory=None, log=None):
        self.host, self.port, self.timeout, self.log = host, port, timeout, log
        self._factory = factory
        self._c = None
        self._creds = None
        self._current = None

    def connect(self):
        if self._factory:
            self._c = self._factory(self.host, self.port)
        else:
            ctx = ssl.create_default_context()  # certificate + hostname verification
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            self._c = imaplib.IMAP4_SSL(self.host, self.port, ssl_context=ctx,
                                        timeout=self.timeout)
        if self.log:
            self.log.write("connect", host=self.host, port=self.port,
                           tls=not self._factory)

    def login(self, user, password):
        self._creds = (user, password)
        try:
            self._c.login(user, password)
        except imaplib.IMAP4.error as exc:
            raise RuntimeError("IMAP login failed: %s" % _scrub(str(exc), password))
        if self.log:
            self.log.write("login", user=user)

    def reconnect(self):
        try:
            self._c.logout()
        except Exception:
            pass
        self.connect()
        self.login(*self._creds)
        if self._current:
            self.examine(self._current)

    def logout(self):
        try:
            self._c.logout()
        except Exception:
            pass
        if self.log:
            self.log.write("logout")

    def capabilities(self):
        return [c.decode() if isinstance(c, bytes) else c for c in self._c.capabilities]

    def list_folders(self):
        typ, data = self._c.list()
        if typ != "OK":
            raise RuntimeError("LIST failed")
        folders = [f for f in (parse_list_item(i) for i in data or []) if f]
        if self.log:
            self.log.write("list", folders=len(folders))
        return folders

    def status(self, folder):
        typ, data = self._c.status(quote_mailbox(folder.name),
                                   "(MESSAGES UNSEEN UIDNEXT UIDVALIDITY)")
        if typ != "OK" or not data or not data[0]:
            return {}
        txt = data[0].decode("utf-8", "replace") if isinstance(data[0], bytes) else str(data[0])
        return {k.lower(): int(v) for k, v in re.findall(r"(MESSAGES|UNSEEN|UIDNEXT|UIDVALIDITY)\s+(\d+)", txt, re.I)}

    def examine(self, folder_name):
        typ, data = self._c.select(quote_mailbox(folder_name), readonly=True)
        if typ != "OK":
            return None
        self._current = folder_name
        _, uv = self._c.response("UIDVALIDITY")
        uidvalidity = int(uv[0]) if uv and uv[0] else None
        count = int(data[0]) if data and data[0] else 0
        if self.log:
            self.log.write("examine", folder=folder_name, readonly=True,
                           messages=count, uidvalidity=uidvalidity)
        return {"messages": count, "uidvalidity": uidvalidity}

    def uid_search(self, *criteria):
        for c in criteria:
            if not re.fullmatch(r"ALL|SINCE|BEFORE|\d{1,2}-[A-Za-z]{3}-\d{4}", c):
                raise ReadOnlyViolation("search criterion not allowed: %r" % c)
        typ, data = self._c.uid("SEARCH", None, *criteria)
        if typ != "OK" or not data or not data[0]:
            return []
        return [int(x) for x in data[0].split()]

    def uid_fetch(self, uids, spec):
        if _FETCH_BAD.search(spec) or not _FETCH_OK_ATTR.match(spec):
            raise ReadOnlyViolation("fetch spec may change flags: %r" % spec)
        typ, data = self._c.uid("FETCH", ",".join(str(u) for u in uids), spec)
        if typ != "OK":
            raise RuntimeError("FETCH failed")
        return parse_fetch(data)


def _scrub(text, secret):
    return text.replace(secret, "***") if secret else text


def parse_fetch(data):
    """imaplib FETCH data -> {uid: {"flags": [...], "size": int, "internaldate": str, "raw": bytes}}"""
    out = {}
    items = list(data or [])
    for i, item in enumerate(items):
        if isinstance(item, (bytes, bytearray)):
            if not re.match(rb"^\d+ \(", item):
                continue
            meta, raw = item.decode("utf-8", "replace"), b""
        elif isinstance(item, tuple):
            meta = item[0].decode("utf-8", "replace")
            raw = item[1] if isinstance(item[1], (bytes, bytearray)) else b""
            if i + 1 < len(items) and isinstance(items[i + 1], bytes):
                tail = items[i + 1].decode("utf-8", "replace")
                if not re.match(r"^\d+ \(", tail):
                    meta += " " + tail
        else:
            continue
        m = re.search(r"\bUID (\d+)", meta)
        if not m:
            continue
        flags = re.search(r"FLAGS \(([^)]*)\)", meta)
        size = re.search(r"RFC822\.SIZE (\d+)", meta)
        idate = re.search(r'INTERNALDATE "([^"]+)"', meta)
        out[int(m.group(1))] = {
            "flags": flags.group(1).split() if flags else [],
            "size": int(size.group(1)) if size else None,
            "internaldate": idate.group(1) if idate else None,
            "raw": bytes(raw),
        }
    return out


# --------------------------------------------------------------------------
# Message parsing
# --------------------------------------------------------------------------
def decode_mime(value):
    if not value:
        return ""
    try:
        return str(make_header(decode_header(str(value))))
    except Exception:
        return str(value)


def parse_date(value):
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return None


_TWO_LEVEL = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "co.nz", "co.jp",
              "com.br", "co.za", "com.tr", "com.cn"}


def registrable_domain(host):
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in _TWO_LEVEL:
        return ".".join(parts[-3:])
    if host.endswith(".kommune.no") or host.endswith(".fylke.no"):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def addr_list(value):
    out = []
    for _, a in getaddresses([decode_mime(value)] if value else []):
        a = a.strip().lower()
        if "@" in a:
            out.append(a)
    return out


class _TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links, self._skip = [], [], 0
        self._href, self._anchor = None, []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "head"):
            self._skip += 1
        elif tag == "a":
            self._href = dict(attrs).get("href")
            self._anchor = []
        elif tag in ("br", "p", "div", "tr", "li"):
            self.text.append(" ")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "head") and self._skip:
            self._skip -= 1
        elif tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._anchor).strip()))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._href is not None:
            self._anchor.append(data)


def html_to_text(html):
    p = _TextExtractor()
    try:
        p.feed(html)
        p.close()
    except Exception:
        pass
    return " ".join(p.text), p.links


_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
_HOSTLIKE_RE = re.compile(r"^(?:https?://)?([a-z0-9.-]+\.[a-z]{2,})(?:[/:?#]|$)", re.I)
_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly",
               "rb.gy", "shorturl.at", "tiny.cc", "buff.ly", "lnkd.in"}


def _host(url):
    try:
        return (urlsplit(url).hostname or "").lower()
    except Exception:
        return ""


def parse_message(raw, body_limit=4000):
    msg = email.message_from_bytes(raw)
    plain, html_parts, attachments, links = [], [], [], []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        ctype = part.get_content_type()
        fname = decode_mime(part.get_filename() or "")
        if fname or part.get_content_disposition() == "attachment":
            attachments.append({"name": fname[:120], "type": ctype})
            continue
        if ctype not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True)
        if payload is None:
            continue
        try:
            content = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except LookupError:
            content = payload.decode("utf-8", errors="replace")
        (plain if ctype == "text/plain" else html_parts).append(content)

    anchors = []
    if html_parts:
        htext, anchors = html_to_text("\n".join(html_parts))
    text = " ".join(plain) if plain else (htext if html_parts else "")
    for p in plain:
        links.extend(_URL_RE.findall(p))
    links.extend(h for h, _ in anchors if h and h.lower().startswith(("http://", "https://")))

    hosts, ip_links, short_links, punycode = [], 0, 0, 0
    for u in links:
        h = _host(u)
        if not h:
            continue
        if re.fullmatch(r"[\d.]+|\[[0-9a-f:]+\]", h):
            ip_links += 1
        if registrable_domain(h) in _SHORTENERS:
            short_links += 1
        if "xn--" in h:
            punycode += 1
        hosts.append(registrable_domain(h))
    mismatch = 0
    for href, label in anchors:
        m = _HOSTLIKE_RE.match(label or "")
        if m and href and href.lower().startswith("http"):
            if registrable_domain(m.group(1)) != registrable_domain(_host(href)):
                mismatch += 1

    frm = decode_mime(msg.get("From"))
    from_addrs = addr_list(msg.get("From"))
    from_addr = from_addrs[0] if from_addrs else ""
    from_name = ""
    parsed = getaddresses([frm])
    if parsed:
        from_name = parsed[0][0]
    reply_to = addr_list(msg.get("Reply-To"))
    return_path = addr_list(msg.get("Return-Path"))
    auth_hdr = decode_mime(msg.get("Authentication-Results"))
    spf_hdr = decode_mime(msg.get("Received-SPF"))
    auth = _parse_auth(auth_hdr, spf_hdr)
    dkim_sig = " ".join(decode_mime(h) for h in (msg.get_all("DKIM-Signature") or []))
    dkim_domains = sorted(set(re.findall(r"\bd=([A-Za-z0-9.-]+)", dkim_sig)))
    unique_hosts = sorted(set(hosts))

    return {
        "message_id": (msg.get("Message-ID") or "").strip(),
        "in_reply_to": bool(msg.get("In-Reply-To")),
        "references": len((msg.get("References") or "").split()),
        "date": parse_date(msg.get("Date")),
        "from": frm,
        "from_name": from_name,
        "from_addr": from_addr,
        "from_domain": from_addr.split("@")[-1] if from_addr else "",
        "reply_to_addr": reply_to[0] if reply_to else "",
        "return_path_addr": return_path[0] if return_path else "",
        "to_addrs": addr_list(msg.get("To"))[:20],
        "cc_addrs": addr_list(msg.get("Cc"))[:20],
        "subject": decode_mime(msg.get("Subject")),
        "list_id": decode_mime(msg.get("List-Id")),
        "list_unsubscribe": decode_mime(msg.get("List-Unsubscribe"))[:300],
        "list_unsubscribe_post": bool(msg.get("List-Unsubscribe-Post")),
        "precedence": decode_mime(msg.get("Precedence")).lower(),
        "auto_submitted": decode_mime(msg.get("Auto-Submitted")).lower(),
        "x_mailer": decode_mime(msg.get("X-Mailer") or msg.get("User-Agent"))[:100],
        "x_spam_flag": decode_mime(msg.get("X-Spam-Flag")).lower(),
        "x_spam_status": decode_mime(msg.get("X-Spam-Status"))[:200],
        "x_spam_level": decode_mime(msg.get("X-Spam-Level"))[:60],
        "authentication_results": auth_hdr[:600],
        "received_spf": spf_hdr[:200],
        "auth": auth,
        "dkim_domains": dkim_domains[:5],
        "link_domains": unique_hosts[:30],
        "link_count": len(links),
        "ip_links": ip_links,
        "shortener_links": short_links,
        "punycode_links": punycode,
        "href_text_mismatch": mismatch,
        "has_html": bool(html_parts),
        "attachments": attachments[:20],
        "body_text_sample": re.sub(r"\s+", " ", text).strip()[:body_limit],
    }


def _parse_auth(auth_hdr, spf_hdr):
    seen = {"spf": [], "dkim": [], "dmarc": []}
    for mech, val in re.findall(r"\b(spf|dkim|dmarc)=([a-z]+)", auth_hdr.lower()):
        seen[mech].append(val)
    res = {}
    for mech, vals in seen.items():
        if not vals:
            res[mech] = None
        elif "fail" in vals:
            res[mech] = "fail"
        elif "softfail" in vals:
            res[mech] = "softfail"
        elif "pass" in vals:
            res[mech] = "pass"
        else:
            res[mech] = vals[0]
    if res["spf"] is None and spf_hdr:
        m = re.match(r"\s*([a-z]+)", spf_hdr.lower())
        if m:
            res["spf"] = m.group(1)
    return res
