import streamlit as st
import re
from collections import Counter

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Phishing Shield",
    page_icon=":shield:",
    layout="centered",
)

# ── Custom CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    .stApp { background-color: #0d1117; color: #e6edf3; }

    .header-card {
        background: linear-gradient(135deg, #161b22 0%, #1c2128 100%);
        border: 1px solid #30363d;
        border-radius: 14px;
        padding: 32px;
        margin-bottom: 24px;
        text-align: center;
    }
    .header-card h1 { color: #58a6ff; font-size: 2.4rem; margin: 0 0 8px 0; letter-spacing:1px; }
    .header-card p  { color: #8b949e; font-size: 1rem; margin: 0; }

    /* Green border input */
    label[data-testid="stTextAreaLabel"] { color: #3fb950 !important; font-weight:600; font-size:1rem; }
    textarea {
        background-color: #161b22 !important;
        color: #e6edf3 !important;
        border: 2px solid #3fb950 !important;
        border-radius: 8px !important;
        font-size: 0.95rem !important;
    }
    textarea:focus { border-color: #56d364 !important; box-shadow: 0 0 0 3px rgba(63,185,80,0.2) !important; }

    /* Button */
    div.stButton > button {
        background-color: #238636; color:#fff; border:none;
        border-radius:8px; padding:10px 32px;
        font-size:1rem; font-weight:600; width:100%;
    }
    div.stButton > button:hover { background-color: #2ea043; }

    /* Result cards */
    .result-safe    { background:#0d2b12; border:1px solid #3fb950; border-radius:10px; padding:18px 22px; margin-bottom:16px; }
    .result-warning { background:#2b1f0a; border:1px solid #d29922; border-radius:10px; padding:18px 22px; margin-bottom:16px; }
    .result-danger  { background:#2b0d0d; border:1px solid #f85149; border-radius:10px; padding:18px 22px; margin-bottom:16px; }

    .percent-label  { font-size:3rem; font-weight:700; }
    .safe-color     { color:#3fb950; }
    .warn-color     { color:#d29922; }
    .danger-color   { color:#f85149; }

    .reason-card {
        background:#161b22; border:1px solid #30363d;
        border-radius:8px; padding:12px 16px; margin-bottom:10px;
    }
    .reason-title { font-weight:600; font-size:0.95rem; margin-bottom:4px; }
    .reason-body  { color:#8b949e; font-size:0.88rem; line-height:1.6; }
    .highlight    { background:#3d1f00; color:#ffa657; padding:1px 5px; border-radius:4px; font-family:monospace; font-size:0.85rem; }
    .highlight-red{ background:#3d0000; color:#ff7b72; padding:1px 5px; border-radius:4px; font-family:monospace; font-size:0.85rem; }

    .divider { border-top:1px solid #30363d; margin:20px 0; }
    .metric-row { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:16px; }
    .metric-box {
        flex:1; min-width:120px;
        background:#161b22; border:1px solid #30363d;
        border-radius:8px; padding:12px; text-align:center;
    }
    .metric-val { font-size:1.6rem; font-weight:700; color:#58a6ff; }
    .metric-lbl { font-size:0.78rem; color:#8b949e; margin-top:2px; }
</style>
""", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
#  DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

# ── 1. Urgency / pressure words ───────────────────────────────────────────────
URGENCY_WORDS = [
    "urgent", "immediately", "act now", "right away", "as soon as possible",
    "without delay", "last chance", "expires today", "expiring soon",
    "limited time", "don't wait", "do not ignore", "respond now",
    "your account will be", "will be suspended", "will be terminated",
    "will be closed", "will be deactivated",
    "immediate action", "verify now", "confirm now", "update now",
    # Payment / billing urgency
    "settle immediately", "pay immediately", "immediate payment",
    "payment required", "payment is overdue", "past due",
    "within 24 hours", "within 48 hours", "before it's too late",
    "or your account will", "services will be suspended",
    "forwarded to collections", "sent to collections",
]

# ── 2. Threat / fear words ────────────────────────────────────────────────────
THREAT_WORDS = [
    "suspended", "terminated", "closed", "deactivated", "blocked",
    "unauthorized access", "suspicious activity", "unusual activity",
    "security alert", "security breach", "hacked", "compromised",
    "your account has been", "we have detected", "illegal activity",
    "legal action", "lawsuit", "police", "fbi", "authorities",
    # Financial / billing threats
    "collections department", "collection agency", "debt collection",
    "late payment fee", "penalty fee", "overdue balance", "overdue invoice",
    "outstanding balance", "outstanding invoice", "your services will be",
    "account will be forwarded", "account will be referred",
    "suspension of your services", "suspension of services",
    "temporary suspension", "service interruption",
]

# ── 2b. Financial fraud / invoice scam patterns ──────────────────────────────
# NOTE: keep these specific — single words like "invoice" are too broad
# and appear in legitimate billing notifications.
FINANCIAL_FRAUD_WORDS = [
    # Overdue / pressure combos (require context)
    "past due", "overdue invoice", "overdue balance",
    "outstanding balance", "outstanding invoice",
    "payment portal", "billing portal", "billing center", "payment center",
    "settle the balance", "settle your balance", "clear your balance",
    "settle the outstanding", "settle your outstanding",
    "remit payment", "remittance",
    # Fake urgency + money combo
    "avoid late fee", "avoid penalty", "avoid suspension",
    "to avoid interruption", "to avoid disruption",
    "to avoid a late", "late payment fee",
    "pay now", "pay today", "make payment now",
    "immediate payment required", "immediate payment needed",
    # Fake invoice / financial authority language
    "final notice", "second notice", "third and final notice",
    "last notice before", "will be referred to our",
    "legal proceedings", "collections department", "collection agency",
    "forwarded to our collections", "referred to collections",
]

# ── 3. Reward / greed bait ────────────────────────────────────────────────────
REWARD_WORDS = [
    "you have won", "winner", "congratulations", "prize", "reward",
    "free gift", "claim your", "you are selected", "lucky draw",
    "lottery", "inheritance", "million dollars", "billion dollars",
    "transfer funds", "wire transfer", "western union",
]

# ── 4. Credential harvesting ──────────────────────────────────────────────────
CREDENTIAL_WORDS = [
    "enter your password", "confirm your password", "verify your password",
    "enter your username", "login details", "sign in to", "your credentials",
    "bank details", "credit card", "debit card", "card number",
    "cvv", "social security", "ssn", "date of birth", "mother's maiden",
    "security question", "pin number",
]

# ── 5. Suspicious link patterns ───────────────────────────────────────────────
SUSPICIOUS_LINK_PATTERNS = [
    r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',   # IP address URL
    r'bit\.ly|tinyurl|goo\.gl|t\.co|ow\.ly|is\.gd',       # URL shorteners
    r'click here',                                          # vague CTA
    r'login\.|signin\.|verify\.|secure\.|update\.',         # fake subdomains
    r'paypal.*\.(?!com)|apple.*\.(?!com)|google.*\.(?!com)',# brand spoofing
    r'\.xyz|\.top|\.club|\.work|\.online|\.site',          # shady TLDs
    # Generic compound service/billing/portal domains (not tied to a real brand)
    r'[\w-]+-service-portal\.',                            # invoicing-service-portal.com
    r'[\w-]+-billing-center\.',                            # xyz-billing-center.com
    r'[\w-]+-payment-portal\.',                            # abc-payment-portal.com
    r'[\w-]+-secure-portal\.',                             # something-secure-portal.com
    r'[\w-]+-resolution-center\.',                         # paypal-resolution-center.com
]

# ── 6. Brand database — real companies frequently impersonated in phishing ────
# Each entry: (display_name, official_domain, common_variations_to_flag)
KNOWN_BRANDS = [
    # Finance & Banking
    ("PayPal",          "paypal.com",           ["paypa1", "paypall", "paypa-l", "pay-pal", "paypalservice", "paypal-secure", "paypalsupport"]),
    ("Chase Bank",      "chase.com",            ["chasee", "chasebank", "chase-bank", "mychase", "chase-secure", "chaseonline"]),
    ("Bank of America", "bankofamerica.com",     ["bankofamerica-", "bofa-secure", "bankamerica", "bank0famerica"]),
    ("Wells Fargo",     "wellsfargo.com",        ["wellsfarg0", "wells-fargo", "wellsfargosecure", "wellfargo"]),
    ("Citibank",        "citibank.com",          ["citi-bank", "citibanksecure", "citibank-alert", "cit1bank"]),
    ("American Express","americanexpress.com",   ["amex-secure", "americanexpress-", "amex-alert", "americanexpress.net"]),
    ("Barclays",        "barclays.co.uk",        ["barclays-secure", "barclays-online", "barclay5", "barclayss"]),
    ("HSBC",            "hsbc.com",              ["hsbc-secure", "hsbc-online", "hsbcbank", "hsbc-alert"]),
    ("SBI",             "sbi.co.in",             ["sbi-alert", "sbibank", "sbionline", "sbi-secure", "sbi.net.in"]),
    ("HDFC",            "hdfcbank.com",          ["hdfc-bank", "hdfcbanksecure", "hdfc-secure", "hdfc-alert"]),
    ("ICICI",           "icicibank.com",         ["icici-bank", "icicisecure", "icici-alert", "icicibank-"]),
    # Tech Giants
    ("Apple",           "apple.com",             ["apple-id", "appleid-secure", "apple-support", "apple-account", "applecare", "appie", "app1e"]),
    ("Google",          "google.com",            ["google-security", "googgle", "g00gle", "google-account", "google-support", "gooogle"]),
    ("Microsoft",       "microsoft.com",         ["micros0ft", "microsofft", "microsoft-", "microsoft-secure", "microsooft", "mircrosoft"]),
    ("Amazon",          "amazon.com",            ["amaz0n", "amazzon", "amazon-", "amazon-secure", "amazonn", "amazon-support"]),
    ("Netflix",         "netflix.com",           ["netfliix", "netfl1x", "netflix-", "netflex", "netflix-billing", "netfix"]),
    # Social media — only flag typo variants, NOT the plain brand name itself,
    # because newsletters legitimately list "Follow us on Facebook / Instagram / Twitter"
    ("Facebook",        "facebook.com",          ["faceb00k", "facebok", "facebook-secure", "faceboook", "facebbok"]),
    ("Instagram",       "instagram.com",         ["instagarm", "instagram-secure", "inst4gram", "instagramm"]),
    ("Twitter",         "twitter.com",           ["tw1tter", "twitter-secure", "twiitter", "twltter"]),
    ("LinkedIn",        "linkedin.com",          ["linkedln", "linked-in-secure", "1inkedin"]),
    ("Dropbox",         "dropbox.com",           ["dr0pbox", "dropbox-", "dropboxx", "drop-box"]),
    ("Adobe",           "adobe.com",             ["adobe-", "ad0be", "adobee", "adobe-secure"]),
    # E-commerce & Delivery
    ("eBay",            "ebay.com",              ["ebay-", "eba-y", "3bay", "ebayy", "ebaysecure"]),
    ("Walmart",         "walmart.com",           ["walmartt", "wallmart", "walmart-", "walmar-t"]),
    ("DHL",             "dhl.com",               ["dhl-express", "dhl-delivery", "dhl-secure", "dhl-tracking", "dh1"]),
    ("FedEx",           "fedex.com",             ["fedex-", "fedEX-delivery", "f3dex", "feddex"]),
    ("UPS",             "ups.com",               ["ups-delivery", "ups-tracking", "upss", "up5"]),
    # Government & Utilities
    ("IRS",             "irs.gov",               ["irs-refund", "irs-gov", "irs-alert", "irs-tax"]),
    ("HMRC",            "hmrc.gov.uk",           ["hmrc-refund", "hmrc-gov", "hmrc-tax", "hmrc-alert"]),
    ("Social Security", "ssa.gov",               ["ssa-gov", "socialsecurity-", "ssa-alert"]),
    # Telecom
    ("AT&T",            "att.com",               ["att-secure", "att-billing", "attt", "at-t"]),
    ("Verizon",         "verizon.com",           ["veriz0n", "verizon-", "veriizon", "verizon-secure"]),
    ("Airtel",          "airtel.in",             ["airtel-", "airtel-recharge", "aiirtel"]),
    ("Jio",             "jio.com",               ["jio-", "jio-recharge", "jioo", "myjio-"]),
    # Streaming & Software
    ("Spotify",         "spotify.com",           ["spotlfy", "spottify", "spotify-", "sp0tify"]),
    ("YouTube",         "youtube.com",           ["y0utube", "youtubee", "youtube-secure", "youtuube"]),
    ("Steam",           "steampowered.com",      ["steam-", "ste4m", "steemm", "steamm"]),
    ("Zoom",            "zoom.us",               ["zo0m", "zoom-meeting", "zoomsecure", "zoomm"]),
    ("WhatsApp",        "whatsapp.com",          ["whatsapp-secure", "whataspp", "whatsap", "whatsappp"]),
]

# ── Homoglyph normalisation map ──────────────────────────────────────────────
# Attackers substitute visually identical characters: capital I → l, 0 → o, etc.
# We normalise BOTH the email text AND brand names before comparing.
HOMOGLYPH_MAP = str.maketrans({
    'I': 'l',   # capital I  → lowercase l  (PayPaI → paypai → paypal after norm)
    '0': 'o',   # digit zero → letter o     (g00gle → google)
    '1': 'l',   # digit one  → letter l     (paypa1 → paypal)
    '3': 'e',   # digit 3    → letter e     (f3dex  → fedex)
    '4': 'a',   # digit 4    → letter a     (inst4gram → instagram)
    '5': 's',   # digit 5    → letter s     (barclay5 → barclays)
    '@': 'a',   # @ → a
    '$': 's',   # $ → s
    '!': 'i',   # ! → i
    '\u00f3': 'o',  # ó → o
    '\u00e9': 'e',  # é → e
    '\u00e0': 'a',  # à → a
})


def _normalise(s):
    """Lowercase + apply homoglyph substitutions so PayPaI == paypal."""
    return s.lower().translate(HOMOGLYPH_MAP)


# Build a flat lookup: typo_variant -> (brand_name, official_domain)
BRAND_TYPO_MAP = {}
for brand_name, official_domain, variants in KNOWN_BRANDS:
    for v in variants:
        BRAND_TYPO_MAP[_normalise(v)] = (brand_name, official_domain)

# Also build normalised brand name lookup
OFFICIAL_DOMAINS   = {domain.lower() for _, domain, _ in KNOWN_BRANDS}
BRAND_NAMES_LOWER  = {name.lower(): (name, domain) for name, domain, _ in KNOWN_BRANDS}
# Normalised brand names (catches PayPaI, G00gle, Amaz0n etc.)
BRAND_NAMES_NORMED = {_normalise(name): (name, domain) for name, domain, _ in KNOWN_BRANDS}


def _levenshtein(a, b):
    """Edit-distance between two strings."""
    if abs(len(a) - len(b)) > 3:
        return 99
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            cost = 0 if a[i-1] == b[j-1] else 1
            dp[j] = min(dp[j] + 1, dp[j-1] + 1, prev[j-1] + cost)
    return dp[n]


def _domain_tokens(domain):
    """
    Break a domain like 'paypai-resolution-center-security.com'
    into meaningful tokens: ['paypai', 'resolution', 'center', 'security']
    This lets the fuzzy matcher test each token individually.
    """
    # Remove TLD (.com / .net / .org etc.)
    core = re.sub(r'\.[a-z]{2,6}$', '', domain)
    # Split on hyphens and dots
    tokens = re.split(r'[-.]', core)
    return [t for t in tokens if len(t) >= 3]   # skip very short tokens


def check_brand_spoofing(text):
    """
    Detects brand impersonation via four layers:
      1. Normalised text scan — catches homoglyph substitution (PayPaI, G00gle)
      2. Known typo variants — curated list of brand lookalikes
      3. Fuzzy domain token match — each hyphen-separated token tested with
         Levenshtein distance against every brand (catches long compound domains)
      4. Brand name in body but sending domain doesn't belong to that brand
    """
    issues      = []
    tl          = text.lower()
    tl_norm     = _normalise(text)          # normalised version for homoglyph checks

    # ── Extract all email addresses and URLs ──────────────────────────────────
    emails_found = re.findall(r'[\w.\-+]+@([\w.\-]+)', tl)
    urls_found   = re.findall(r'https?://([\w.\-]+)', tl)
    # Also pull raw display-name domains like <service@paypaI-security.com>
    angle_emails = re.findall(r'<[\w.+\-]+@([\w.\-]+)>', tl)
    all_domains  = set(emails_found + urls_found + angle_emails)

    # ── 1. Homoglyph / normalised brand name scan ─────────────────────────────
    homoglyph_hits = []
    for norm_name, (brand_name, official_domain) in BRAND_NAMES_NORMED.items():
        if norm_name in tl_norm:
            # Make sure it isn't simply the real domain appearing legitimately
            real_core = official_domain.split('.')[0]
            legitimate = any(
                '.'.join(d.split('.')[-2:]) == official_domain
                for d in all_domains
            )
            if not legitimate:
                # Check the raw text too — if the original brand name appears verbatim
                # it's caught by mismatch check; only flag here if it differs
                raw_match = brand_name.lower() in tl
                if not raw_match:
                    # Homoglyph version detected (e.g. PayPaI instead of PayPal)
                    # Find the actual token in the normalised text that triggered this
                    homoglyph_hits.append(
                        f'"{brand_name}" impersonated using look-alike characters '
                        f'(e.g. capital "I" instead of "l", "0" instead of "o")'
                    )

    if homoglyph_hits:
        issues.append({
            "check": "homoglyph",
            "detail": "The email uses visually identical characters to disguise a brand name — "
                      "a classic trick to fool both humans and spam filters.",
            "hits": list(dict.fromkeys(homoglyph_hits))[:4],
        })

    # ── 2. Exact typo-variant match anywhere in normalised text ──────────────
    # Skip if the sender is legitimately from that brand's official domain
    legitimate_domains = {
        '.'.join(d.split('.')[-2:]) for d in all_domains
    }
    # Social media names appear in every newsletter footer — skip them here too
    _FOOTER_BRANDS_OFFICIAL = {
        "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
        "youtube.com", "whatsapp.com", "spotify.com", "steampowered.com",
    }
    typo_hits = []
    for variant, (brand, official) in BRAND_TYPO_MAP.items():
        if official in _FOOTER_BRANDS_OFFICIAL:
            continue   # social media footer brands — skip entirely in typo check
        if variant in tl_norm:
            # Don't flag if this email is genuinely from the official domain
            if official not in legitimate_domains:
                typo_hits.append((variant, brand, official))

    if typo_hits:
        issues.append({
            "check": "typo_variant",
            "detail": "Known typo/lookalike variants of trusted brand names were found.",
            "hits": [f'"{v}" (impersonating {b}, real domain: {o})' for v, b, o in typo_hits[:6]],
        })

    # ── 3. Fuzzy token match on ALL domain tokens ─────────────────────────────
    # Splits "paypai-resolution-center-security.com" → ["paypai","resolution","center","security"]
    # then tests each token with Levenshtein against every known brand core.
    fuzzy_hits = []
    for domain in all_domains:
        norm_domain = _normalise(domain)
        tokens      = _domain_tokens(norm_domain)

        for brand_name, official_domain, _ in KNOWN_BRANDS:
            official_core = _normalise(official_domain.split('.')[0])
            # Skip if this IS the real domain
            if '.'.join(domain.split('.')[-2:]) == official_domain:
                continue
            for token in tokens:
                dist = _levenshtein(token, official_core)
                if dist <= 1:          # 0 = exact match after normalisation, 1 = 1-edit typosquat
                    fuzzy_hits.append(
                        f'"{domain}" contains token "{token}" ≈ "{official_domain}" '
                        f'({brand_name}) — similarity score: {max(0, 100 - dist*20)}%'
                    )
                    break              # one hit per domain per brand is enough

    if fuzzy_hits:
        issues.append({
            "check": "fuzzy_domain",
            "detail": "A URL or sender domain contains a token that closely matches a trusted "
                      "brand's domain — a strong indicator of typosquatting.",
            "hits": list(dict.fromkeys(fuzzy_hits))[:6],
        })

    # ── 4. Brand name in body but sending domain doesn't match ───────────────
    # Social media platforms are commonly listed in email footers by ALL senders —
    # "Follow us on Facebook / Instagram / Twitter" is not a phishing signal.
    # Only check brands where impersonation actually matters (financial, tech, delivery).
    FOOTER_ONLY_BRANDS = {
        "facebook", "instagram", "twitter", "linkedin", "youtube",
        "whatsapp", "spotify", "steam", "pinterest", "tiktok",
    }

    mismatch_hits = []
    # Check both raw brand names AND normalised (catches PayPaI → paypal)
    combined_brand_map = dict(BRAND_NAMES_LOWER)
    combined_brand_map.update(BRAND_NAMES_NORMED)

    for brand_key, (brand_name, official_domain) in combined_brand_map.items():
        # Skip social platforms — they appear in every newsletter footer
        if brand_name.lower() in FOOTER_ONLY_BRANDS:
            continue
        raw_found  = brand_key in tl
        norm_found = brand_key in tl_norm
        if raw_found or norm_found:
            legitimate_sender = any(
                '.'.join(d.split('.')[-2:]) == official_domain
                for d in all_domains
            )
            if all_domains and not legitimate_sender:
                mismatch_hits.append(
                    f'{brand_name} is mentioned but no link/sender uses the real '
                    f'domain "{official_domain}"'
                )

    if mismatch_hits:
        issues.append({
            "check": "brand_mismatch",
            "detail": "A trusted company name appears in the email, but the actual sender "
                      "or link domain does not belong to that company.",
            "hits": list(dict.fromkeys(mismatch_hits))[:5],
        })

    return issues


# ── 6b. Suspicious sender domain flags ───────────────────────────────────────
def check_sender_flags(text):
    """Flag suspicious sender address patterns."""
    issues = []
    tl = text.lower()

    # Extract From: / Reply-To: / sender lines
    sender_lines = re.findall(r'(?:from|reply-to|sender)[:\s]+([^\n]+)', tl)
    all_emails   = re.findall(r'[\w.\-+]+@([\w.\-]+)', tl)

    suspicious_tlds = ['.ru', '.cn', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.xyz']
    free_providers  = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com',
                       'aol.com', 'protonmail.com', 'mail.com', 'yandex.com']

    free_hits = []
    tld_hits  = []

    for domain in all_emails:
        # Company emails from free providers
        if domain in free_providers:
            # Only flag if the email body mentions a brand (real companies don't use Gmail)
            for brand_lower in BRAND_NAMES_LOWER:
                if brand_lower in tl:
                    free_hits.append(f'"@{domain}" (a well-known brand would not use a free email provider)')
                    break
        # Suspicious TLD
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                tld_hits.append(f'"@{domain}" uses a high-risk TLD ({tld})')

    if free_hits:
        issues.append(("Free email provider used by claimed brand", list(dict.fromkeys(free_hits))[:3]))
    if tld_hits:
        issues.append(("High-risk country/TLD in sender domain", list(dict.fromkeys(tld_hits))[:3]))
    return issues


# ── 7. Known common misspellings in phishing mails ───────────────────────────
COMMON_PHISHING_MISSPELLINGS = [
    ("recieve", "receive"), ("occured", "occurred"), ("beleive", "believe"),
    ("seperate", "separate"), ("definately", "definitely"), ("accomodation", "accommodation"),
    ("acheive", "achieve"), ("adress", "address"), ("busines", "business"),
    ("calender", "calendar"), ("concious", "conscious"), ("occurance", "occurrence"),
    ("reccommend", "recommend"), ("succesful", "successful"), ("tommorrow", "tomorrow"),
    ("wierd", "weird"), ("writting", "writing"), ("untill", "until"),
    ("beneficary", "beneficiary"), ("kindly", "kindly revert"),  # overused formal phrasing
    ("revert back", "revert back"),  # redundant phrase common in phishing
    ("do the needful", "do the needful"),
    ("dear customer", "dear customer"), ("dear user", "dear user"),
    ("dear account holder", "dear account holder"),
]

# ── 8. Excessive punctuation / ALL CAPS patterns ─────────────────────────────
# Common legitimate ALL-CAPS tokens — org names, acronyms, countries, etc.
_CAPS_WHITELIST = {
    "URL", "FBI", "SSN", "CVV", "PIN", "OTP", "USA", "UK", "FAQ",
    "PDF", "SMS", "ID", "TV", "ATM", "UPI", "EMI", "GST", "TDS",
    "NOTE", "INDIA", "LPU", "NAAC", "UGC", "AICTE", "NIRF",
    "CEO", "CFO", "COO", "CTO", "HR", "IT", "MCA", "MBA", "BBA",
    "SUBMIT", "PAY", "BOOK", "CLICK", "READ", "VIEW", "NEW",
    # Common newsletter / institutional words
    "FRESHMEN", "INDUCTION", "WELCOME", "IMPORTANT", "NOTICE",
    "UPDATE", "ALERT", "INFO", "NEWS", "EVENT", "LIVE", "NOW",
    "SCHEDULE", "REMINDER", "INVITATION", "CONFIRM", "PORTAL",
}

def check_excessive_formatting(text):
    issues = []
    # ALL CAPS words (3+ chars) — skip whitelisted acronyms/proper nouns
    caps_words = re.findall(r'\b[A-Z]{3,}\b', text)
    caps_words = [w for w in caps_words if w not in _CAPS_WHITELIST]
    if len(caps_words) >= 4:   # raised threshold: 4+ unknown CAPS words needed
        issues.append(("Excessive CAPS words", caps_words[:8]))

    # Multiple exclamation marks
    excl = re.findall(r'!{2,}', text)
    if excl:
        issues.append(("Multiple exclamation marks", excl[:5]))

    # Multiple question marks
    quest = re.findall(r'\?{2,}', text)
    if quest:
        issues.append(("Multiple question marks", quest[:5]))

    return issues

# ── 9. Indentation / spacing anomalies ───────────────────────────────────────
def check_indentation_errors(text):
    lines = text.split('\n')
    issues = []
    random_indent_lines = []
    double_space_lines  = []
    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        indent   = len(line) - len(stripped)
        # Randomly indented lines (not typical in proper emails)
        if 1 <= indent <= 20 and stripped and not stripped.startswith(('>', '-', '*', '•')):
            random_indent_lines.append(f"Line {i}: \"{stripped[:50]}\"")
        # Double spaces inside sentence
        if re.search(r'[a-zA-Z]  +[a-zA-Z]', line):
            double_space_lines.append(f"Line {i}")
    if len(random_indent_lines) >= 2:
        issues.append(("Unusual indentation", random_indent_lines[:4]))
    if double_space_lines:
        issues.append(("Irregular spacing between words", double_space_lines[:4]))
    return issues

# ── 10. Generic / impersonal greeting ────────────────────────────────────────
def check_generic_greeting(text):
    generic = [
        "dear customer", "dear user", "dear account holder",
        "dear valued customer", "dear member", "hello user",
        "to whom it may concern", "dear sir/madam", "dear sir or madam",
        "greetings", "dear friend",
    ]
    tl = text.lower()
    found = [g for g in generic if g in tl]
    return found

# ── 11. Mismatched / suspicious URLs ─────────────────────────────────────────
def check_suspicious_urls(text):
    urls = re.findall(r'https?://[^\s<>"\']+', text)
    issues = []
    for url in urls:
        for pattern in SUSPICIOUS_LINK_PATTERNS:
            if re.search(pattern, url, re.IGNORECASE):
                issues.append(url[:80])
                break
    return list(set(issues))

# ── 12. Spelling mistake detector (simple, no external lib needed) ────────────
def check_spelling(text):
    found_errors = []
    tl = text.lower()
    for (wrong, correct) in COMMON_PHISHING_MISSPELLINGS:
        if wrong in tl:
            found_errors.append((wrong, correct))
    return found_errors

# ── 13. Check for HTML / invisible characters ─────────────────────────────────
def check_html_tricks(text):
    issues = []
    # Only flag HTML if it looks like a real injected tag with attributes or script —
    # pasted email footers often contain angle-bracket artefacts like "<engage@...>"
    # or image placeholders, so we require at least one attribute or closing slash.
    if re.search(r'<(script|iframe|object|embed|form|input|style)\b', text, re.IGNORECASE):
        issues.append("Contains dangerous HTML tags (script/iframe/form)")
    if re.search(r'[\u200b\u200c\u200d\ufeff\u00ad]', text):
        issues.append("Contains invisible/zero-width characters (obfuscation trick)")
    return issues

# ── 14. Sentence structure / grammar red flags ───────────────────────────────
def check_grammar_flags(text):
    issues = []
    tl = text.lower()
    # Missing space after punctuation — require 3+ occurrences to avoid
    # flagging HTML-stripped emails where "Note:Text" appears once or twice.
    no_space_hits = re.findall(r'[.!?,][A-Za-z]', text)
    # Filter out common false positives: URLs (e.g. "www.lpu.in"), "5:00 PM", decimals
    no_space_hits = [h for h in no_space_hits if not re.search(r'\d', h)]
    if len(no_space_hits) >= 3:
        issues.append("Missing spaces after punctuation (multiple instances)")
    # Repeated words
    repeated = re.findall(r'\b(\w+)\s+\1\b', tl)
    if repeated:
        issues.append(f"Repeated words: {', '.join(set(repeated[:5]))}")
    # Very long single paragraph (no line breaks) — common in phishing
    paragraphs = [p for p in text.split('\n\n') if p.strip()]
    for p in paragraphs:
        if len(p.split()) > 120 and '\n' not in p:
            issues.append("Very long unbroken paragraph (common in template phishing emails)")
            break
    return issues

# ═══════════════════════════════════════════════════════════════════════════════
#  MASTER SCORER
# ═══════════════════════════════════════════════════════════════════════════════
def analyse_email(text):
    findings = []   # list of dicts: {category, severity (1-3), detail, examples}
    score    = 0    # raw score — will be normalised to 0-100

    tl = text.lower()

    # ── Urgency ───────────────────────────────────────────────────────────────
    urgency_hits = [w for w in URGENCY_WORDS if w in tl]
    if urgency_hits:
        w = min(len(urgency_hits) * 8, 24)
        score += w
        findings.append({
            "category": "Urgency / Pressure Language",
            "severity": 2,
            "detail": "Phishing emails create artificial urgency to make you act without thinking.",
            "examples": urgency_hits[:6],
        })

    # ── Threats ───────────────────────────────────────────────────────────────
    threat_hits = [w for w in THREAT_WORDS if w in tl]
    if threat_hits:
        w = min(len(threat_hits) * 9, 27)
        score += w
        findings.append({
            "category": "Threat / Fear Tactics",
            "severity": min(len(threat_hits), 3),
            "detail": "Uses fear-based language to panic the recipient into clicking or disclosing info.",
            "examples": threat_hits[:6],
        })

    # ── Reward bait ───────────────────────────────────────────────────────────
    reward_hits = [w for w in REWARD_WORDS if w in tl]
    if reward_hits:
        w = min(len(reward_hits) * 10, 25)
        score += w
        findings.append({
            "category": "Reward / Greed Bait",
            "severity": min(len(reward_hits), 3),
            "detail": "Lures the recipient with fake prizes, money, or rewards.",
            "examples": reward_hits[:6],
        })

    # ── Credential harvesting ─────────────────────────────────────────────────
    cred_hits = [w for w in CREDENTIAL_WORDS if w in tl]
    if cred_hits:
        w = min(len(cred_hits) * 12, 30)
        score += w
        findings.append({
            "category": "Credential / Personal Data Harvesting",
            "severity": 3,
            "detail": "Requests sensitive information like passwords, card numbers, or personal data.",
            "examples": cred_hits[:6],
        })

    # ── Suspicious URLs ───────────────────────────────────────────────────────
    url_issues = check_suspicious_urls(text)
    if url_issues:
        score += min(len(url_issues) * 15, 30)
        findings.append({
            "category": "Suspicious / Malicious URLs",
            "severity": 3,
            "detail": "Contains links with IP addresses, URL shorteners, or spoofed brand domains.",
            "examples": url_issues[:4],
        })

    # ── Spelling mistakes ─────────────────────────────────────────────────────
    spell_errors = check_spelling(text)
    if spell_errors:
        score += min(len(spell_errors) * 5, 15)
        findings.append({
            "category": "Spelling Mistakes",
            "severity": min(len(spell_errors), 3),
            "detail": "Contains common spelling errors frequently seen in phishing templates.",
            "examples": [f'"{w}" (should be "{c}")' for w, c in spell_errors[:6]],
        })

    # ── Indentation / spacing errors ──────────────────────────────────────────
    indent_issues = check_indentation_errors(text)
    if indent_issues:
        score += min(len(indent_issues) * 5, 10)
        for label, examples in indent_issues:
            findings.append({
                "category": f"Formatting Error: {label}",
                "severity": 1,
                "detail": "Irregular formatting is common in phishing emails copied from templates.",
                "examples": examples[:4],
            })

    # ── Excessive formatting ───────────────────────────────────────────────────
    fmt_issues = check_excessive_formatting(text)
    if fmt_issues:
        score += min(len(fmt_issues) * 5, 10)
        for label, examples in fmt_issues:
            findings.append({
                "category": f"Aggressive Formatting: {label}",
                "severity": 1,
                "detail": "Overuse of CAPS or punctuation is a pressure tactic.",
                "examples": [str(e) for e in examples[:6]],
            })

    # ── Generic greeting ──────────────────────────────────────────────────────
    greetings = check_generic_greeting(text)
    if greetings:
        score += min(len(greetings) * 6, 12)
        findings.append({
            "category": "Generic / Impersonal Greeting",
            "severity": 2,
            "detail": "Legitimate companies usually address you by name. Generic greetings are a red flag.",
            "examples": greetings[:4],
        })

    # ── HTML tricks ───────────────────────────────────────────────────────────
    html_issues = check_html_tricks(text)
    if html_issues:
        score += 20
        findings.append({
            "category": "HTML Obfuscation Tricks",
            "severity": 3,
            "detail": "Uses hidden HTML or invisible characters to bypass spam filters.",
            "examples": html_issues,
        })

    # ── Grammar flags ─────────────────────────────────────────────────────────
    grammar_issues = check_grammar_flags(text)
    if grammar_issues:
        score += min(len(grammar_issues) * 4, 10)
        findings.append({
            "category": "Grammar / Structure Issues",
            "severity": 1,
            "detail": "Poor grammar and sentence structure are classic phishing indicators.",
            "examples": grammar_issues[:4],
        })

    # ── Brand spoofing (typo variants + fuzzy domains + mismatch) ────────────
    brand_issues = check_brand_spoofing(text)
    for issue in brand_issues:
        check_type = issue["check"]
        if check_type == "typo_variant":
            score += min(len(issue["hits"]) * 18, 36)
            findings.append({
                "category": "Brand Name Typo / Lookalike",
                "severity": 3,
                "detail": issue["detail"],
                "examples": issue["hits"],
            })
        elif check_type == "fuzzy_domain":
            score += min(len(issue["hits"]) * 20, 40)
            findings.append({
                "category": "Typosquatted Domain (Fuzzy Match)",
                "severity": 3,
                "detail": issue["detail"],
                "examples": issue["hits"],
            })
        elif check_type == "brand_mismatch":
            score += min(len(issue["hits"]) * 15, 30)
            findings.append({
                "category": "Brand Name / Sender Domain Mismatch",
                "severity": 3,
                "detail": issue["detail"],
                "examples": issue["hits"],
            })

    # ── Suspicious sender domain / TLD ────────────────────────────────────────
    sender_issues = check_sender_flags(text)
    if sender_issues:
        score += min(len(sender_issues) * 10, 20)
        for label, examples in sender_issues:
            findings.append({
                "category": f"Suspicious Sender: {label}",
                "severity": 2,
                "detail": "The sender's email domain raises serious red flags.",
                "examples": examples[:4],
            })

    # ── Financial fraud / invoice scam ───────────────────────────────────────
    fraud_hits = [w for w in FINANCIAL_FRAUD_WORDS if w in tl]
    if fraud_hits:
        score += min(len(fraud_hits) * 10, 30)
        findings.append({
            "category": "Financial Fraud / Invoice Scam",
            "severity": 3,
            "detail": "Contains language typical of fake invoice or billing scam emails designed "
                      "to pressure victims into making fraudulent payments.",
            "examples": fraud_hits[:6],
        })

    # ── Homoglyph characters in sender display name ───────────────────────────
    # Only scan the DISPLAY NAME (text before <email@domain>) — never the email
    # address itself, to avoid flagging legitimate domains like microsoft.com.
    homoglyph_sender_hits = []

    # Collect all "Display Name <email>" display-name portions from the text
    display_name_candidates = re.findall(
        r'([A-Za-z][A-Za-z0-9\s\-_\.]{2,50}?)\s*<[\w.+\-]+@[\w.\-]+>',
        text
    )
    # Also try From: header with display name
    for line in text.splitlines():
        m = re.match(r'From\s*:\s*([^<\n]+?)\s*<', line, re.IGNORECASE)
        if m:
            display_name_candidates.append(m.group(1))

    for name in display_name_candidates:
        name_stripped = name.strip()
        if not name_stripped or len(name_stripped) < 3:
            continue
        # Check word by word — skip if it's an all-caps acronym (len <= 4, all caps)
        words_with_homoglyphs = []
        for word in name_stripped.split():
            if len(word) <= 2:
                continue
            # All-caps acronyms (IBM, LPU, DHL) are legitimate — skip them
            if word.isupper() and len(word) <= 5:
                continue
            norm_word = _normalise(word)
            # The word changes after normalisation AND contains a mid-word capital I or digit
            if norm_word != word.lower():
                # Verify change is not just standard capitalisation of first letter
                if norm_word != word[0].lower() + word[1:].lower():
                    words_with_homoglyphs.append(word)

        if words_with_homoglyphs:
            homoglyph_sender_hits.append(
                f'"{name_stripped}" — suspicious lookalike characters detected '
                f'in: {words_with_homoglyphs}'
            )

    if homoglyph_sender_hits:
        score += 25
        findings.append({
            "category": "Homoglyph Characters in Sender Name",
            "severity": 3,
            "detail": "The sender's display name uses visually identical characters to disguise "
                      "itself — a deliberate trick to impersonate a legitimate organisation.",
            "examples": homoglyph_sender_hits[:3],
        })

    # ── Normalise score to 0–100 ──────────────────────────────────────────────
    percent = min(score, 100)

    return percent, findings


# ═══════════════════════════════════════════════════════════════════════════════
#  EMAIL PRE-PROCESSOR
#  Strips email-client UI chrome (timestamps, labels, "Unsubscribe" buttons,
#  social-footer lines) so the detector only sees real email content.
# ═══════════════════════════════════════════════════════════════════════════════

# Lines that are purely email-client UI artefacts — remove them entirely
_UI_LINE_PATTERNS = [
    re.compile(r'^\s*(inbox|sent|drafts|spam|trash)\s*$', re.IGNORECASE),
    re.compile(r'^\s*unsubscribe\s*$', re.IGNORECASE),
    re.compile(r'^\s*click here to unsubscribe\s*$', re.IGNORECASE),
    re.compile(r'^\s*(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+\d{1,2}\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)', re.IGNORECASE),
    re.compile(r'^\s*to\s*:\s*me\s*$', re.IGNORECASE),
    re.compile(r'^\s*to\s+me\s*$', re.IGNORECASE),
    re.compile(r'^\s*\d+\s+(attachment|image|file)s?\b', re.IGNORECASE),
    re.compile(r'^\s*(show\s+details?|hide\s+details?|view\s+original)\s*$', re.IGNORECASE),
    re.compile(r'^\s*(reply|reply all|forward|more)\s*$', re.IGNORECASE),
    re.compile(r'^\s*\[image\s*:.*?\]\s*$', re.IGNORECASE),   # [image: logo.png]
    re.compile(r'^\s*\[logo\s*.*?\]\s*$', re.IGNORECASE),
]

# Lines that are social-media footer icons (only text icons, no URLs)
_SOCIAL_FOOTER_RE = re.compile(
    r'^\s*(facebook|instagram|twitter|linkedin|youtube|pinterest'
    r'|tiktok|snapchat|whatsapp|telegram)\s*'
    r'(\t|\s{2,}|facebook|instagram|twitter|linkedin|youtube|pinterest'
    r'|tiktok|snapchat|whatsapp|telegram)*\s*$',
    re.IGNORECASE
)

def preprocess_email(raw: str) -> tuple:
    """
    Clean pasted email text and extract structured fields.
    Returns (cleaned_text, parsed_fields_dict).

    cleaned_text  — text with UI chrome stripped, ready for analysis
    parsed_fields — dict with keys: from_addr, to_addr, subject, body_preview
    """
    lines = raw.splitlines()
    cleaned_lines = []
    parsed = {"from": "", "to": "", "subject": "", "reply_to": ""}

    # ── Pass 1: extract headers and strip UI lines ────────────────────────────
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        # Skip blank lines at top
        if not stripped and not cleaned_lines:
            i += 1
            continue

        # Extract structured headers (From: / To: / Subject: / Reply-To:)
        hdr = re.match(r'^(From|To|Subject|Reply-To|Sender)\s*:\s*(.+)', stripped, re.IGNORECASE)
        if hdr:
            key   = hdr.group(1).lower().replace('-', '_')
            value = hdr.group(2).strip()
            parsed[key] = value
            cleaned_lines.append(line)
            i += 1
            continue

        # Gmail-style "Name <email> Unsubscribe" header line
        gmail_hdr = re.match(r'^(.+?)\s*<([\w.+\-]+@[\w.\-]+)>\s*(Unsubscribe)?', stripped)
        if gmail_hdr and not parsed["from"]:
            parsed["from"] = f'{gmail_hdr.group(1).strip()} <{gmail_hdr.group(2)}>'
            cleaned_lines.append(f'From: {parsed["from"]}')
            i += 1
            continue

        # Drop pure UI lines
        is_ui = any(p.match(stripped) for p in _UI_LINE_PATTERNS)
        if is_ui:
            i += 1
            continue

        # Drop social-footer-only lines
        if _SOCIAL_FOOTER_RE.match(stripped):
            i += 1
            continue

        # Drop lines that are ONLY image/logo placeholder tokens
        if re.match(r'^(\s*(logo|naac|image|banner|photo|img)\s*)+$', stripped, re.IGNORECASE):
            i += 1
            continue

        cleaned_lines.append(line)
        i += 1

    cleaned = '\n'.join(cleaned_lines).strip()

    # ── Pass 2: if no From header was found, try to infer from angle brackets ─
    if not parsed["from"]:
        m = re.search(r'[\w.+\-]+@[\w.\-]+', cleaned)
        if m:
            parsed["from"] = m.group(0)

    # ── Pass 3: infer subject from first non-blank, non-header line if missing ─
    if not parsed["subject"]:
        for ln in cleaned_lines:
            s = ln.strip()
            if s and not re.match(r'^(From|To|Subject|Reply-To):', s, re.IGNORECASE):
                parsed["subject"] = s[:120]
                break

    return cleaned, parsed


# ═══════════════════════════════════════════════════════════════════════════════
#  UI
# ═══════════════════════════════════════════════════════════════════════════════

# Header
st.markdown("""
<div class="header-card">
    <h1>Phishing Shield</h1>
    <p>Advanced phishing email detector.<br>
    Paste any email below — we will analyse spelling, formatting, urgency tactics, links, and more.</p>
</div>
""", unsafe_allow_html=True)

# Input
email_text = st.text_area(
    label="Enter the email contents here :",
    placeholder="Paste the full email text here — subject, headers, body, links, everything…",
    height=240,
)

analyse_clicked = st.button("Analyse Email")

# ── Results ───────────────────────────────────────────────────────────────────
if analyse_clicked:
    if not email_text.strip():
        st.warning("Please paste some email content before analysing.")
    else:
        # Pre-process: strip email-client UI chrome, extract fields
        cleaned_text, parsed = preprocess_email(email_text)
        percent, findings = analyse_email(cleaned_text)

        # ── Parsed fields panel ───────────────────────────────────────────────
        from_val    = parsed.get("from", "")    or "Not detected"
        subject_val = parsed.get("subject", "") or "Not detected"
        to_val      = parsed.get("to", "")      or ""
        field_rows  = f'<tr><td>From</td><td>{from_val}</td></tr>'
        if to_val:
            field_rows += f'<tr><td>To</td><td>{to_val}</td></tr>'
        field_rows += f'<tr><td>Subject</td><td>{subject_val}</td></tr>'
        st.markdown(f"""
        <table style="width:100%;border-collapse:collapse;background:#161b22;
                      border:1px solid #30363d;border-radius:8px;
                      font-size:0.88rem;margin-bottom:16px;overflow:hidden;">
          <tbody>
            {''.join(f'<tr><td style="padding:7px 14px;color:#8b949e;width:90px;border-bottom:1px solid #30363d;white-space:nowrap;">{k}</td><td style="padding:7px 14px;color:#e6edf3;border-bottom:1px solid #30363d;word-break:break-all;">{v}</td></tr>' for k,v in [('From', from_val), ('To', to_val), ('Subject', subject_val)] if v and v != 'Not detected' or k == 'From')}
          </tbody>
        </table>
        """, unsafe_allow_html=True)

        # ── Verdict card ──────────────────────────────────────────────────────
        if percent >= 65:
            verdict_class = "result-danger"
            color_class   = "danger-color"
            verdict_text  = "HIGH RISK — Very Likely Phishing"
        elif percent >= 30:
            verdict_class = "result-warning"
            color_class   = "warn-color"
            verdict_text  = "MODERATE RISK — Suspicious Email"
        else:
            verdict_class = "result-safe"
            color_class   = "safe-color"
            verdict_text  = "LOW RISK — Looks Legitimate"

        st.markdown(f"""
        <div class="{verdict_class}">
            <div class="percent-label {color_class}">{percent}%</div>
            <div class="{color_class}" style="font-size:1.2rem; font-weight:600; margin-top:4px;">{verdict_text}</div>
            <div style="color:#8b949e; font-size:0.9rem; margin-top:6px;">
                Phishing probability based on {len(findings)} detected signal(s)
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ── Quick metrics ──────────────────────────────────────────────────────
        word_count  = len(cleaned_text.split())
        line_count  = len(cleaned_text.strip().split('\n'))
        url_count   = len(re.findall(r'https?://[^\s]+', cleaned_text))
        signal_count = len(findings)

        st.markdown(f"""
        <div class="metric-row">
            <div class="metric-box"><div class="metric-val">{word_count}</div><div class="metric-lbl">Words</div></div>
            <div class="metric-box"><div class="metric-val">{line_count}</div><div class="metric-lbl">Lines</div></div>
            <div class="metric-box"><div class="metric-val">{url_count}</div><div class="metric-lbl">URLs Found</div></div>
            <div class="metric-box"><div class="metric-val">{signal_count}</div><div class="metric-lbl">Risk Signals</div></div>
        </div>
        """, unsafe_allow_html=True)

        # ── Detailed findings ─────────────────────────────────────────────────
        if findings:
            st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
            st.markdown("### Detailed Analysis")

            severity_colours = {1: "#d29922", 2: "#e3692e", 3: "#f85149"}
            severity_label   = {1: "Low", 2: "Medium", 3: "High"}

            for f in findings:
                sev_colour = severity_colours.get(f["severity"], "#8b949e")
                sev_text   = severity_label.get(f["severity"], "Info")
                examples_html = " ".join(
                    f'<span class="highlight-red">{e}</span>' for e in f["examples"]
                )
                st.markdown(f"""
                <div class="reason-card">
                    <div class="reason-title">
                        {f["category"]}
                        &nbsp;|&nbsp;
                        <span style="color:{sev_colour};">Severity: {sev_text}</span>
                    </div>
                    <div class="reason-body">{f["detail"]}</div>
                    <div style="margin-top:8px;">{examples_html}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.markdown("""
            <div class="result-safe" style="margin-top:16px;">
                No phishing signals were detected. The email appears legitimate.<br>
                <span style="color:#8b949e; font-size:0.88rem;">
                Always stay cautious — no automated tool is 100% accurate.
                </span>
            </div>
            """, unsafe_allow_html=True)

        # ── Risk Bar Chart ────────────────────────────────────────────────────
        st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
        st.markdown("### Risk Signal Breakdown")

        if findings:
            # Build parallel label + count + colour lists from findings
            bar_labels  = [f["category"] for f in findings]
            bar_counts  = [len(f["examples"]) for f in findings]
            sev_colours = {1: "#d29922", 2: "#e3692e", 3: "#f85149"}
            bar_colours = [sev_colours.get(f["severity"], "#8b949e") for f in findings]

            # Shorten long labels for the chart axis
            short_labels = []
            for lbl in bar_labels:
                short_labels.append(lbl[:28] + "..." if len(lbl) > 28 else lbl)

            # Render as a native Streamlit bar chart using st.markdown + inline SVG
            # so no extra library is needed — pure HTML/SVG embedded via markdown
            max_count   = max(bar_counts) if bar_counts else 1
            chart_h     = 260
            bar_area_w  = 620
            n           = len(bar_labels)
            bar_w       = max(18, min(54, (bar_area_w - (n + 1) * 8) // n))
            spacing     = (bar_area_w - n * bar_w) // (n + 1)
            label_h     = 72    # space below bars for rotated labels

            bars_svg = ""
            for i, (count, colour, slabel) in enumerate(zip(bar_counts, bar_colours, short_labels)):
                bar_height = int((count / max_count) * (chart_h - 40))
                x          = spacing + i * (bar_w + spacing)
                y          = chart_h - 30 - bar_height

                # Bar rectangle
                bars_svg += (
                    f'<rect x="{x}" y="{y}" width="{bar_w}" height="{bar_height}" '
                    f'rx="4" fill="{colour}" opacity="0.9"/>'
                )
                # Count label on top of bar
                bars_svg += (
                    f'<text x="{x + bar_w//2}" y="{y - 5}" '
                    f'text-anchor="middle" fill="#e6edf3" font-size="12" font-weight="bold">'
                    f'{count}</text>'
                )
                # Rotated x-axis label
                tx = x + bar_w // 2
                ty = chart_h - 25
                bars_svg += (
                    f'<text x="{tx}" y="{ty}" '
                    f'text-anchor="end" fill="#8b949e" font-size="10" '
                    f'transform="rotate(-38 {tx} {ty})">'
                    f'{slabel}</text>'
                )

            # Y-axis gridlines
            grid_svg = ""
            for step in range(0, max_count + 1):
                gy = chart_h - 30 - int((step / max_count) * (chart_h - 40))
                grid_svg += (
                    f'<line x1="0" y1="{gy}" x2="{bar_area_w}" y2="{gy}" '
                    f'stroke="#30363d" stroke-width="1" stroke-dasharray="3,3"/>'
                    f'<text x="-6" y="{gy + 4}" text-anchor="end" fill="#8b949e" font-size="10">'
                    f'{step}</text>'
                )

            total_h = chart_h + label_h
            svg = f"""
            <svg xmlns="http://www.w3.org/2000/svg"
                 viewBox="0 0 {bar_area_w + 40} {total_h + 10}"
                 style="width:100%;background:#161b22;border:1px solid #30363d;
                        border-radius:10px;padding:12px;box-sizing:border-box;">
              <g transform="translate(36,10)">
                {grid_svg}
                {bars_svg}
                <!-- X axis line -->
                <line x1="0" y1="{chart_h - 30}" x2="{bar_area_w}" y2="{chart_h - 30}"
                      stroke="#30363d" stroke-width="1"/>
                <!-- Y axis label -->
                <text x="-28" y="{(chart_h - 30)//2}"
                      text-anchor="middle" fill="#8b949e" font-size="11"
                      transform="rotate(-90 -28 {(chart_h - 30)//2})">Evidence count</text>
              </g>
            </svg>
            """
            st.markdown(svg, unsafe_allow_html=True)

            # Legend row — severity colours (text-coloured, no emoji)
            st.markdown("""
            <div style="display:flex;gap:20px;margin-top:10px;font-size:0.82rem;">
                <span style="color:#f85149;font-weight:600;">High severity</span>
                <span style="color:#e3692e;font-weight:600;">Medium severity</span>
                <span style="color:#d29922;font-weight:600;">Low severity</span>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.markdown(
                '<p style="color:#8b949e;font-size:0.9rem;">No risk signals to chart — email appears clean.</p>',
                unsafe_allow_html=True,
            )
