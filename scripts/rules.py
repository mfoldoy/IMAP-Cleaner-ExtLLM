"""Editable rule data for the local classifier (Norwegian + English)."""

# Official domains per protected organisation. Matching is on registrable domain.
GOVERNMENT_DOMAINS = {
    "skatteetaten.no", "nav.no", "altinn.no", "digipost.no", "helsenorge.no",
    "politiet.no", "regjeringen.no", "norge.no", "lanekassen.no", "udi.no",
    "domstol.no", "brreg.no", "vegvesen.no", "statens-vegvesen.no", "toll.no",
    "kemneren.no", "kartverket.no", "folkeregisteret.no", "id-porten.no",
    "digdir.no", "fhi.no", "helsedirektoratet.no", "arbeidstilsynet.no",
    "forbrukertilsynet.no", "datatilsynet.no", "stortinget.no", "difi.no",
    "skatteetaten.no", "sivilforsvaret.no", "mattilsynet.no", "ssb.no",
    "gov.uk", "gov", "europa.eu", "irs.gov", "usps.com",
}
GOVERNMENT_SUFFIXES = (".kommune.no", ".fylke.no", ".gov", ".gov.uk")

FINANCIAL_DOMAINS = {
    "dnb.no", "nordea.no", "nordea.com", "sbanken.no", "sparebank1.no", "storebrand.no",
    "gjensidige.no", "if.no", "tryg.no", "fremtind.no", "vipps.no", "vipps.mobilepay.com",
    "mobilepay.no", "paypal.com", "klarna.com", "klarna.no", "stripe.com", "visa.com",
    "mastercard.com", "santander.no", "bank-norwegian.no", "bulder.no",
    "handelsbanken.no", "danskebank.no", "skandiabanken.no", "kron.no", "resurs.no",
    "telenor.no", "telia.no", "ice.no", "lyse.no", "fortum.no", "tibber.com",
    "posten.no", "bring.no", "dhl.com", "ups.com", "fedex.com", "postnord.no",
    "amazon.com", "amazon.de", "amazon.co.uk", "apple.com", "ebay.com", "finn.no",
    "ikea.com", "ikea.no", "norwegian.no", "sas.no", "flysas.com", "booking.com",
    "airbnb.com", "ruter.no", "vy.no", "entur.no", "ticketmaster.no", "hotels.com",
}

ACCOUNT_SECURITY_DOMAINS = {
    "accounts.google.com", "google.com", "microsoft.com", "microsoftonline.com",
    "live.com", "outlook.com", "apple.com", "github.com", "id.apple.com",
    "bankid.no", "bankidnorge.no", "buypass.no", "facebookmail.com", "linkedin.com",
    "dropbox.com", "adobe.com", "1password.com", "lastpass.com",
}

# Brands commonly impersonated. brand token -> legitimate registrable domains.
BRANDS = {
    "dnb": {"dnb.no"}, "vipps": {"vipps.no", "vipps.mobilepay.com"},
    "nordea": {"nordea.no", "nordea.com"}, "sparebank": {"sparebank1.no", "sparebank.no"},
    "skatteetaten": {"skatteetaten.no"}, "nav": {"nav.no"}, "altinn": {"altinn.no"},
    "posten": {"posten.no", "bring.no"}, "bring": {"bring.no", "posten.no"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "outlook.com", "live.com"},
    "paypal": {"paypal.com"}, "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.de", "amazon.co.uk"}, "netflix": {"netflix.com"},
    "google": {"google.com", "accounts.google.com"}, "facebook": {"facebook.com", "facebookmail.com"},
    "telenor": {"telenor.no", "telenor.com"}, "telia": {"telia.no", "telia.com"},
    "bankid": {"bankid.no", "bankidnorge.no"}, "klarna": {"klarna.com", "klarna.no"},
    "dhl": {"dhl.com", "dhl.de"}, "ups": {"ups.com"}, "fedex": {"fedex.com"},
    "digipost": {"digipost.no"}, "politiet": {"politiet.no"}, "tolletaten": {"toll.no"},
}

FREEMAIL_DOMAINS = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "hotmail.no", "live.com",
    "live.no", "icloud.com", "me.com", "yahoo.com", "yahoo.no", "online.no", "getmail.no",
    "start.no", "frisurf.no", "broadpark.no", "tele2.no", "proton.me", "protonmail.com",
    "msn.com", "c2i.net", "lyse.net", "stwcp.net",
}

ESP_DOMAINS = {  # bulk/marketing infrastructure
    "mailchimp.com", "mcsv.net", "mcdlv.net", "sendgrid.net", "sendgrid.com", "sparkpostmail.com",
    "mandrillapp.com", "amazonses.com", "mailgun.org", "mailgun.com", "cmail19.com", "cmail20.com",
    "createsend.com", "klaviyomail.com", "hubspotemail.net", "hs-analytics.net", "rsgsv.net",
    "mktomail.com", "marketo.com", "exacttarget.com", "salesforce.com", "pardot.com",
    "sendinblue.com", "brevo.com", "mailerlite.com", "campaign-archive.com", "list-manage.com",
    "emarsys.net", "dotdigital.com", "episerver.net", "optimizely.com", "braze.com",
    "customeriomail.com", "constantcontact.com", "postmarkapp.com", "e-mail.nu", "ngpvan.com",
}

TLD_SUSPICIOUS = {".xyz", ".top", ".click", ".work", ".loan", ".win", ".bid", ".gq", ".tk",
                  ".ml", ".cf", ".ga", ".icu", ".rest", ".monster", ".buzz", ".cyou", ".zip", ".mov"}

RISKY_EXT = (".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".bat", ".cmd", ".com", ".pif",
             ".lnk", ".iso", ".img", ".msi", ".hta", ".jar", ".docm", ".xlsm", ".pptm",
             ".html", ".htm", ".svg", ".one", ".ps1", ".wsf")

NOREPLY_RX = r"(^|[._-])(no-?reply|donotreply|do-not-reply|mailer-daemon|notifications?|noreply)([._-]|@)"

# --- keyword groups (lower-case, matched as substrings in subject/body) -------------
KW_PHISH = [
    "verifiser kontoen", "bekreft kontoen", "bekreft din konto", "konto er sperret",
    "kontoen din er sperret", "kontoen er begrenset", "oppdater betalingsinformasjon",
    "passordet ditt utløper", "passord utløper", "logg inn for å", "umiddelbart",
    "ellers stenges", "ellers vil kontoen", "sikkerhetsbrudd", "uvanlig aktivitet",
    "verify your account", "confirm your account", "account has been suspended",
    "account suspended", "unusual sign-in", "update your payment", "password expires",
    "your account will be closed", "immediately", "within 24 hours", "action required",
    "pakken din", "tollgebyr", "ubetalt faktura", "refusjon", "tilbakebetaling",
    "du har mottatt en betaling", "gift card", "gavekort", "wire transfer",
]
KW_SPAM = [
    "you have won", "du har vunnet", "gratulerer, du", "congratulations you", "lottery",
    "lotteri", "claim your prize", "bitcoin", "crypto", "kryptovaluta", "viagra", "cialis",
    "casino", "pharmacy", "inheritance", "arv fra", "nigerian", "million dollar",
    "click here", "klikk her", "earn money", "tjen penger", "work from home", "weight loss",
    "forex", "investment opportunity", "make money fast", "singel", "dating", "xxx",
    "adult", "penis", "enlarge", "100% free", "risk-free", "no obligation",
]
KW_MARKETING = [
    "rabatt", "tilbud", "salg", "kampanje", "kupong", "gratis frakt", "black friday",
    "svarte fredag", "spar ", "kjøp nå", "handle nå", "begrenset tid", "kun i dag",
    "siste sjanse", "% off", "discount", "sale", "deal", "coupon", "free shipping",
    "buy now", "shop now", "limited time", "exclusive offer", "eksklusivt tilbud",
    "medlemstilbud", "bonus", "poeng", "vinn ", "konkurranse", "nyhet:",
]
KW_NEWSLETTER = [
    "nyhetsbrev", "newsletter", "ukens", "ukentlig", "månedens", "weekly digest",
    "daily digest", "dagens", "oppsummering", "digest", "avmeld", "unsubscribe",
    "view in browser", "vis i nettleser", "les i nettleser", "i denne utgaven",
    "this week", "denne uken", "bulletin",
]
KW_RECEIPT = [
    "faktura", "kvittering", "ordrebekreftelse", "bestillingsbekreftelse", "bestilling",
    "betaling", "betalingsbekreftelse", "purchase", "receipt", "invoice", "order confirmation",
    "your order", "payment received", "forfallsdato", "kid-nummer", "kontonummer",
    "billett", "boardingkort", "reservasjon", "booking", "e-ticket", "leveringsbekreftelse",
    "pakkesporing", "sporingsnummer", "skattekort", "skattemelding", "lønnsslipp",
    "lønnsslipp", "årsoppgjør", "forsikring", "polise", "lån", "avtale", "kontrakt",
]
KW_GOV_LEGAL = [
    "skatteetaten", "skattemelding", "skatteoppgjør", "altinn", "nav ", "folkeregister",
    "politiet", "bot ", "inkasso", "namsmann", "tingrett", "stevning", "krav om",
    "vedtak", "innkalling", "søknad", "lånekassen", "helsenorge", "legetime",
    "timeavtale", "pasient", "resept", "digipost", "tax return", "court", "legal notice",
]
KW_SECURITY = [
    "engangskode", "verifiseringskode", "bekreftelseskode", "sikkerhetskode", "one-time code",
    "verification code", "your code is", "security alert", "sikkerhetsvarsel", "ny pålogging",
    "new sign-in", "new login", "reset your password", "tilbakestill passord",
    "nullstill passord", "password reset", "two-factor", "2fa", "to-faktor", "bankid",
    "passkey", "recovery", "gjenopprett",
]
KW_AUTOMATED = [
    "automatisk generert", "auto-generated", "do not reply", "ikke svar på denne",
    "this is an automated", "dette er en automatisk", "notification", "varsel",
    "build failed", "run failed", "pull request", "new comment", "reminder", "påminnelse",
    "calendar", "invitation:", "kalender", "delivered", "shipped", "sendt fra lager",
]
