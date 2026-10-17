# IBM SkillsBuild Project

> **An advanced phishing email detection system built with Python & Streamlit.**  
> Paste any email — get an instant phishing probability score, detailed signal breakdown, and a risk bar chart.

---

## Table of Contents

- [About the Project](#about-the-project)
- [Features](#features)
- [Detection Checks](#detection-checks)
- [Brand Database](#brand-database)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Running the App](#running-the-app)
- [How to Use](#how-to-use)
- [Sample Results](#sample-results)
- [Project Structure](#project-structure)
- [Known Limitations](#known-limitations)
- [Future Scope](#future-scope)
- [Author](#author)

---

## About the Project

**Phishing Shield** is a cyber security dashboard that analyses pasted email content and determines the probability that it is a phishing attempt. It uses **14 independent heuristic checks** running in parallel — from urgency language and brand impersonation to homoglyph character detection and Levenshtein fuzzy domain matching.

The system is built entirely in a **single Python file** with no external ML libraries, making it beginner-friendly while remaining capable of detecting sophisticated real-world attacks such as:

- `PayPaI` (capital I instead of lowercase l)
- `amaz0n-secure.xyz` (leet-speak + shady TLD)
- `invoicing-service-portal.com` (generic billing scam domain)
- Emails claiming to be from `Apple` but sent from `@gmail.com`

---

## Features

- **Phishing probability score** from 0% to 100%
- **3-band verdict** — High Risk / Moderate Risk / Low Risk with colour coding
- **14 parallel detection checks** with per-signal severity (High / Medium / Low)
- **40-brand impersonation database** covering banking, tech, delivery, telecom & government
- **Homoglyph normalisation** — detects lookalike characters (I→l, 0→o, 1→l, 3→e …)
- **Levenshtein fuzzy domain matching** — catches novel typosquats not in any list
- **Financial fraud / invoice scam** detection
- **Email pre-processor** — strips email-client UI noise (Gmail / Outlook / Apple Mail copy-paste)
- **Parsed fields panel** — shows detected From / Subject after cleaning
- **Risk bar chart** — inline SVG chart, no extra library needed
- **Zero false positives** on tested legitimate emails (newsletters, receipts, office emails)

---

## Detection Checks

| # | Check | Severity | What It Catches |
|---|-------|----------|-----------------|
| 1 | Urgency / Pressure Language | Medium | "immediately", "within 24 hours", "past due", "verify now" |
| 2 | Threat / Fear Tactics | High | Account suspension, legal action, collections department |
| 3 | Reward / Greed Bait | High | Lottery wins, prize claims, wire transfer requests |
| 4 | Credential Harvesting | High | Password/card/CVV/SSN/PIN requests |
| 5 | Suspicious / Malicious URLs | High | IP links, URL shorteners, shady TLDs, fake portal domains |
| 6 | Financial Fraud / Invoice Scam | High | Overdue invoices, billing portals, "final notice", legal proceedings |
| 7 | Brand Name Typo / Lookalike | High | 200+ curated variants — paypa1, g00gle, netfliix, microsofft |
| 8 | Typosquatted Domain (Fuzzy) | High | Levenshtein edit-distance ≤1 on each domain token |
| 9 | Brand / Domain Mismatch | High | Brand name in body but sender domain doesn't match |
| 10 | Homoglyph in Sender Name | High | "InvoIcing", "PayPaI" — mid-word lookalike characters |
| 11 | Generic / Impersonal Greeting | Medium | "Dear Customer", "Dear User", "Dear Account Holder" |
| 12 | Spelling Mistakes | Low–Med | 20+ common phishing template misspellings |
| 13 | Aggressive Formatting | Low | Excessive ALL-CAPS, repeated `!!`, `??` |
| 14 | Grammar / Structure Issues | Low | Missing spaces after punctuation, repeated words |

---

## Brand Database

The system monitors **40 major brands** most frequently impersonated in phishing:

| Category | Brands |
|----------|--------|
| Finance & Banking | PayPal, Chase, Bank of America, Wells Fargo, Citibank, American Express, Barclays, HSBC, SBI, HDFC, ICICI |
| Technology | Apple, Google, Microsoft, Amazon, Netflix, Facebook, Instagram, Twitter, LinkedIn, Dropbox, Adobe |
| E-Commerce & Delivery | eBay, Walmart, DHL, FedEx, UPS |
| Government | IRS, HMRC, Social Security Administration |
| Telecom | AT&T, Verizon, Airtel, Jio |
| Streaming & Software | Spotify, YouTube, Steam, Zoom, WhatsApp |

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Python 3.10+ |
| Web Framework | Streamlit |
| Pattern Matching | Python `re` (standard library) |
| Edit Distance | Custom Levenshtein (pure Python) |
| Homoglyph Detection | `str.maketrans` normalisation table |
| Visualisation | Inline SVG (no charting library) |
| Deployment | Streamlit local server (`localhost:8501`) |

---

## Getting Started

### Prerequisites

- **Python 3.10 or higher** — [Download Python](https://www.python.org/downloads/)
- **pip** — comes bundled with Python
- **Git** (optional, for cloning)

Verify your Python installation:

```bash
python --version
```

---

### Installation

**1. Clone the repository**

```bash
git clone https://github.com/awasthi-sankalp/IBM-SkillsBuild-Project
cd IBM-SkillsBuild-Project
```

Or download the ZIP and extract it, then open a terminal in the project folder.

---

**2. (Recommended) Create a virtual environment**

```bash
python -m venv venv
```

Activate it:

- **Windows:**
  ```bash
  venv\Scripts\activate
  ```
- **macOS / Linux:**
  ```bash
  source venv/bin/activate
  ```

---

**3. Install all dependencies**

```bash
pip install -r requirements.txt
```

This installs everything in one step. No manual installs needed.

---

### Running the App

```bash
python -m streamlit run app.py
```

> **Note:** Use `python -m streamlit` instead of just `streamlit` if you get a  
> `'streamlit' is not recognized` error on Windows. Both commands run identically.

The first time you run it, Streamlit may ask for your email — just press **Enter** to skip.

Your browser will open automatically at:

```
http://localhost:8501
```

If it doesn't open automatically, copy that URL and paste it into any browser.

---

## How to Use

1. **Open the app** at `http://localhost:8501`
2. **Paste any email** into the input field — include the full text: sender line, subject, body, links, everything
3. Click **Analyse Email**
4. The app will show:
   - A **phishing score** (0–100%) with a colour-coded verdict
   - **Quick metrics** — word count, line count, URL count, signal count
   - **Parsed fields** — detected From address and Subject line
   - **Detailed findings** — one card per risk signal with severity and examples
   - **Risk bar chart** — all signals plotted with evidence count

### Tips

- You can paste emails copied directly from **Gmail**, **Outlook**, or **Apple Mail** — the pre-processor cleans up client UI noise automatically
- Paste the **raw email source** (headers + body) for the most accurate results
- The tool works best when the full email including the `From:` line is included

---

## Sample Results

| Email | Score | Verdict |
|-------|-------|---------|
| `PayPaI Support <service@paypaI-security-alert.com>` | **100%** | High Risk |
| `InvoIcing Department` — overdue invoice scam | **100%** | High Risk |
| Amazon phish — `amaz0n-secure.xyz` | **100%** | High Risk |
| Fake Apple ID — `apple-id-verify.net` | **100%** | High Risk |
| SBI bank India — `.ru` TLD + PIN/CVV request | **84%** | High Risk |
| LPU Freshmen Induction 2026 (real university newsletter) | **9%** | Low Risk |
| PayPal receipt from `service@paypal.com` | **4%** | Low Risk |
| Office meeting reminder | **0%** | Low Risk |
| Microsoft invoice from `billing@microsoft.com` | **0%** | Low Risk |

---

## Project Structure

```
IBM-SkillsBuild-Project/
│
├── app.py               # Entire application — detection engine + UI (single file)
├── requirements.txt     # Python dependencies
└── README.md            # This file
```

---

## Known Limitations

- **Rule-based only** — cannot automatically learn from new phishing patterns; requires manual updates to keyword lists
- **Text analysis only** — image-based phishing emails (where all text is embedded in an image) require OCR and are not supported
- **No live URL scanning** — suspicious URLs are detected by pattern matching, not by checking if the link is actually live and malicious
- **40-brand database** — impersonation of brands not in the database is only caught by generic checks (fuzzy matching, generic greetings, etc.)
- **English language** — keyword lists are currently in English only

---

## Future Scope

- [ ] Machine learning classifier trained on labelled phishing datasets (CEAS-08, SpamAssassin)
- [ ] Live URL reputation check via Google Safe Browsing API or VirusTotal
- [ ] Browser extension for Gmail and Outlook Web App
- [ ] Email attachment analysis (malicious file extension detection)
- [ ] DKIM / SPF header verification
- [ ] Multi-language support (Hindi, French, Spanish)
- [ ] Cloud deployment on Streamlit Community Cloud

---

## Author

**Sankalp Awasthi**  
B.Tech Computer Science & Engineering  
Lovely Professional University

---

> **Disclaimer:** Phishing Shield is an academic project built for educational purposes.  
> It is a heuristic tool and does not guarantee 100% detection accuracy.  
> Always exercise caution with unexpected emails regardless of the tool's output.
