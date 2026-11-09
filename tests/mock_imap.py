"""Minimal in-process IMAP server for tests (plain TCP, not for production)."""
import re
import socketserver
import threading

from email.message import EmailMessage

PASSWORD = "correct horse"
USER = "test@example.no"

WRITE_CMDS = {"STORE", "COPY", "MOVE", "EXPUNGE", "APPEND", "DELETE", "RENAME",
              "CREATE", "SUBSCRIBE", "UNSUBSCRIBE"}


class Mailbox:
    def __init__(self, uidvalidity):
        self.uidvalidity = uidvalidity
        self.msgs = {}  # uid -> {"raw": bytes, "flags": set}
        self.next_uid = 1

    def add(self, raw, flags=()):
        uid = self.next_uid
        self.next_uid += 1
        self.msgs[uid] = {"raw": raw, "flags": set(flags)}
        return uid


class State:
    def __init__(self):
        self.boxes = {}        # name -> (flags, Mailbox or None)
        self.delim = "."
        self.log = []          # every (command, args) received after login
        self.capability = "IMAP4rev1 UIDPLUS MOVE"
        self.password = PASSWORD

    def writes(self):
        return [c for c in self.log if c[0] in WRITE_CMDS or
                (c[0] == "UID" and c[1].split()[0].upper() in WRITE_CMDS)]


def make_msg(frm, to, subject, body, extra=None, html=None):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, to, subject
    m["Date"] = "Mon, 02 Mar 2026 10:00:00 +0100"
    m["Message-ID"] = "<%s@test>" % abs(hash((frm, subject)))
    for k, v in (extra or {}).items():
        m[k] = v
    m.set_content(body)
    if html:
        m.add_alternative(html, subtype="html")
    return m.as_bytes()


def utf7(s):
    from oc_common import utf7_encode
    return utf7_encode(s)


def mbox_name(enc):
    from oc_common import utf7_decode
    return utf7_decode(re.sub(r"\\(.)", r"\1", enc))


class Handler(socketserver.StreamRequestHandler):
    def send(self, line):
        self.wfile.write(line if isinstance(line, bytes) else line.encode("utf-8"))
        self.wfile.write(b"\r\n")

    def handle(self):
        st = self.server.state
        self.send("* OK IMAP4 ready")
        authed, selected, readonly = False, None, True
        while True:
            line = self.rfile.readline()
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip("\r\n")
            tag, _, rest = text.partition(" ")
            cmd, _, args = rest.partition(" ")
            cmd = cmd.upper()
            if cmd == "LOGIN":
                m = re.match(r'"?([^" ]+)"? "?(.*?)"?$', args)
                if m and m.group(1) == USER and m.group(2) == st.password:
                    authed = True
                    self.send(tag + " OK LOGIN done")
                else:
                    self.send(tag + " NO [AUTHENTICATIONFAILED] bad credentials")
                continue
            if cmd == "CAPABILITY":
                self.send("* CAPABILITY " + st.capability)
                self.send(tag + " OK done")
                continue
            if cmd == "LOGOUT":
                self.send("* BYE")
                self.send(tag + " OK done")
                return
            if not authed:
                self.send(tag + " NO not authenticated")
                continue
            st.log.append((cmd, args))
            if cmd == "LIST":
                for name, (flags, box) in st.boxes.items():
                    self.send('* LIST (%s) "%s" "%s"' % (flags, st.delim, utf7(name)))
                self.send(tag + " OK LIST done")
            elif cmd == "STATUS":
                name = mbox_name(re.match(r'"((?:[^"\\]|\\.)*)"', args).group(1))
                box = st.boxes.get(name, (None, None))[1]
                if box is None:
                    self.send(tag + " NO no such mailbox")
                else:
                    unseen = sum(1 for m in box.msgs.values() if "\\Seen" not in m["flags"])
                    self.send('* STATUS "%s" (MESSAGES %d UNSEEN %d UIDNEXT %d UIDVALIDITY %d)' % (
                        utf7(name), len(box.msgs), unseen, box.next_uid, box.uidvalidity))
                    self.send(tag + " OK done")
            elif cmd in ("SELECT", "EXAMINE"):
                m = re.match(r'"((?:[^"\\]|\\.)*)"', args)
                name = mbox_name(m.group(1)) if m else None
                box = st.boxes.get(name, (None, None))[1] if name else None
                if box is None:
                    self.send(tag + " NO no such mailbox")
                    continue
                selected, readonly = box, cmd == "EXAMINE"
                self.send("* %d EXISTS" % len(box.msgs))
                self.send("* OK [UIDVALIDITY %d] ok" % box.uidvalidity)
                self.send(tag + (" OK [READ-ONLY] done" if readonly else " OK [READ-WRITE] done"))
            elif cmd == "UID":
                self.uid_cmd(tag, args, selected, st)
            elif cmd == "CREATE":
                name = mbox_name(re.match(r'"((?:[^"\\]|\\.)*)"', args).group(1))
                st.boxes[name] = ("\\HasNoChildren", Mailbox(999))
                self.send(tag + " OK done")
            elif cmd == "NOOP":
                self.send(tag + " OK done")
            else:
                self.send(tag + " BAD unsupported")

    def uid_cmd(self, tag, args, box, st):
        sub, _, rest = args.partition(" ")
        sub = sub.upper()
        if box is None:
            self.send(tag + " NO no mailbox selected")
            return
        if sub == "SEARCH":
            self.send("* SEARCH " + " ".join(str(u) for u in sorted(box.msgs)))
            self.send(tag + " OK done")
        elif sub == "FETCH":
            seq, _, spec = rest.partition(" ")
            part = re.search(r"BODY(\.PEEK)?\[\](?:<0\.(\d+)>)?", spec)
            for uid in [int(x) for x in seq.split(",") if x]:
                m = box.msgs.get(uid)
                if m is None:
                    continue
                if part and not part.group(1):
                    m["flags"].add("\\Seen")  # non-PEEK fetch: tests assert this never happens
                hf = re.search(r"BODY(\.PEEK)?\[HEADER\.FIELDS \(([^)]*)\)\]", spec)
                if hf:
                    if not hf.group(1):
                        m["flags"].add("\\Seen")
                    wanted = [w.lower() for w in hf.group(2).split()]
                    head = m["raw"].split(b"\r\n\r\n", 1)[0].split(b"\n\n", 1)[0]
                    lines = [l for l in head.splitlines() if l.split(b":", 1)[0].strip().lower().decode() in wanted]
                    raw = b"\r\n".join(lines) + b"\r\n\r\n"
                    self.wfile.write(("* %d FETCH (UID %d BODY[HEADER.FIELDS (%s)] {%d}\r\n" % (
                        uid, uid, hf.group(2), len(raw))).encode())
                    self.wfile.write(raw)
                    self.wfile.write(b")\r\n")
                    continue
                raw = m["raw"]
                if part and part.group(2):
                    raw = raw[:int(part.group(2))]
                attrs = 'UID %d FLAGS (%s) RFC822.SIZE %d INTERNALDATE "02-Mar-2026 10:00:00 +0100"' % (
                    uid, " ".join(sorted(m["flags"])), len(m["raw"]))
                if part:
                    self.wfile.write(("* %d FETCH (%s BODY[]<0> {%d}\r\n" % (uid, attrs, len(raw))).encode())
                    self.wfile.write(raw)
                    self.wfile.write(b")\r\n")
                else:
                    self.send("* %d FETCH (%s)" % (uid, attrs))
            self.send(tag + " OK FETCH done")
        elif sub in ("COPY", "MOVE"):
            seq, _, dest = rest.partition(" ")
            dname = mbox_name(re.match(r'"((?:[^"\\]|\\.)*)"', dest).group(1))
            dbox = st.boxes.get(dname, (None, None))[1]
            if dbox is None:
                self.send(tag + " NO [TRYCREATE] no such mailbox")
                return
            for uid in [int(x) for x in seq.split(",")]:
                if uid in box.msgs:
                    dbox.add(box.msgs[uid]["raw"], box.msgs[uid]["flags"])
                    if sub == "MOVE":
                        del box.msgs[uid]
            self.send(tag + " OK done")
        elif sub == "STORE":
            seq, _, spec = rest.partition(" ")
            for uid in [int(x) for x in seq.split(",")]:
                if uid in box.msgs and "\\Deleted" in spec:
                    box.msgs[uid]["flags"].add("\\Deleted")
            self.send(tag + " OK done")
        elif sub == "EXPUNGE":
            for uid in [int(x) for x in rest.split(",")]:
                box.msgs.pop(uid, None)
            self.send(tag + " OK done")
        else:
            self.send(tag + " BAD")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start(state):
    srv = Server(("127.0.0.1", 0), Handler)
    srv.state = state
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
