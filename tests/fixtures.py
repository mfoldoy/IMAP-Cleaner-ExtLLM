"""Synthetic mailbox used by the tests (no real data)."""
from mock_imap import Mailbox, State, make_msg, USER

PHISH_HTML = ('<html><body><p>Din konto er sperret.</p>'
              '<a href="http://198.51.100.7/login">www.dnb.no/logg-inn</a></body></html>')
UNSUB = {"List-Unsubscribe": "<mailto:unsub@example.com>, <https://e.example.com/u/1>"}
AUTH_PASS = {"Authentication-Results": "mx.stwcp.net; spf=pass; dkim=pass; dmarc=pass"}
AUTH_FAIL = {"Authentication-Results": "mx.stwcp.net; spf=fail; dkim=none; dmarc=fail"}

# (key, folder, flags, raw) -> expectations live in EXPECTED
MSGS = {}


def _add(key, box, flags, raw):
    MSGS[key] = (box, flags, raw)


def build_state():
    st = State()
    inbox, junk, sent, proj = Mailbox(1001), Mailbox(1002), Mailbox(1003), Mailbox(1004)
    st.boxes = {
        "INBOX": ("\\HasChildren", inbox),
        "INBOX.Sent Items": ("\\Sent", sent),
        "INBOX.Søppelpost": ("\\Junk", junk),
        "INBOX.Prosjekter æøå": ("\\HasNoChildren", proj),
        "INBOX.Public": ("\\Noselect", None),
    }
    items = [
        ("skatt", inbox, [], make_msg("Skatteetaten <noreply@skatteetaten.no>", USER,
            "Skattemelding for 2025 er klar", "Din skattemelding er klar til gjennomgang i Altinn.", AUTH_PASS)),
        ("kari", inbox, ["\\Seen", "\\Answered"], make_msg("Kari Nordmann <kari.nordmann@gmail.com>", USER,
            "Middag på søndag?", "Hei! Kan dere komme på middag søndag kl 17? Klem Kari")),
        ("tu", inbox, [], make_msg("Teknisk Ukeblad <nyhetsbrev@tu.no>", USER,
            "Ukens nyhetsbrev: de viktigste sakene", "Her er ukens nyhetsbrev med de viktigste sakene. Avmeld nyhetsbrevet nederst.",
            dict(UNSUB, **{"List-Id": "<tu.nyhetsbrev.tu.no>"}, **AUTH_PASS))),
        ("elkjop1", inbox, [], make_msg("Elkjøp <tilbud@e.elkjop.no>", USER,
            "50% rabatt – kun i dag!", "Svarte fredag-tilbud! Spar 50% på TV. Kjøp nå. Avmeld deg her.", dict(UNSUB, **AUTH_PASS))),
        ("elkjop2", inbox, [], make_msg("Elkjøp <tilbud@e.elkjop.no>", USER,
            "Nye tilbud denne uken", "Spar opptil 30% rabatt på kampanjevarer. Kjøp nå.", dict(UNSUB, **AUTH_PASS))),
        ("elkjop3", inbox, [], make_msg("Elkjøp <tilbud@e.elkjop.no>", USER,
            "Salg! Siste sjanse", "Salg på alt. Rabatt opptil 40%. Kjøp nå.", dict(UNSUB, **AUTH_PASS))),
        ("phish", inbox, [], make_msg("DNB Sikkerhet <support@dnb-sikkerhet.xyz>", USER,
            "Din konto er sperret - bekreft nå", "Din konto er sperret. Verifiser kontoen din umiddelbart ellers stenges den.",
            AUTH_FAIL, html=PHISH_HTML)),
        ("lotto", inbox, [], make_msg("Winner <lotto@random-prize.top>", "undisclosed-recipients:;",
            "Congratulations you have won $1,000,000!!!", "You have won the lottery. Click here to claim your prize. Send bitcoin fee.", AUTH_FAIL)),
        ("faktura", inbox, [], make_msg("Telenor <faktura@telenor.no>", USER,
            "Faktura for oktober", "Din faktura for oktober er klar. Beløp å betale: 599,00 kr. Forfallsdato 15.11.", AUTH_PASS)),
        ("work", inbox, ["\\Seen"], make_msg("Per Kollega <per@example.no>", USER,
            "Re: Møtereferat prosjekt Alfa", "Her er referatet fra møtet. Kan du sende status på leveransen?", {"In-Reply-To": "<x@y>"})),
        ("google", inbox, [], make_msg("Google <no-reply@accounts.google.com>", USER,
            "Sikkerhetsvarsel: ny pålogging", "Ny pålogging på kontoen din. Hvis dette ikke var deg, bytt passord.", AUTH_PASS)),
        ("github", inbox, ["\\Seen"], make_msg("GitHub <notifications@github.com>", USER,
            "[repo] Run failed: CI", "Your workflow run failed.", dict(AUTH_PASS, **{"Auto-Submitted": "auto-generated"}))),
        ("bob", inbox, [], make_msg("Bob <bob@bobsbedrift.no>", USER, "Hei", "Hei, tid for en prat?")),
        ("unknown", inbox, [], make_msg("Ukjent <hei@lite-selskap.com>", USER, "Se her", "Sjekk dette.")),
        ("viagra_junk", junk, [], make_msg("Pharma <deal@cheap-pills.top>", USER,
            "Cheap viagra casino", "Buy viagra now, click here", AUTH_FAIL)),
        ("vipps_junk", junk, [], make_msg("Vipps <noreply@vipps.no>", USER,
            "Kvittering fra Vipps", "Kvittering: du betalte 249 kr til Kafe Nord.", AUTH_PASS)),
        ("sent1", sent, ["\\Seen"], make_msg(USER, "Bob Bedrift <bob@bobsbedrift.no>", "Re: tilbud", "Takk, det passer fint.")),
        ("proj", proj, ["\\Seen"], make_msg("Per Kollega <per@example.no>", USER,
            "Prosjektplan Alfa", "Vedlagt prosjektplan for Alfa. Frist for levering er 1. desember.")),
    ]
    for key, box, flags, raw in items:
        box.add(raw, flags)
        MSGS[key] = raw
    return st
