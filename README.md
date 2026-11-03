# SWYNEX – Intelligent Feature

## Task 3: PII Guard v3 — Indian PII + Resume Anonymizer

An upgrade to the Task 2 PII Guard prototype, built with **Microsoft Presidio**. Version 3 adds Indian-specific PII detection, a resume-anonymization mode, risk-aware adaptive redaction, error handling, and a full evaluation suite.

## 🧠 The Intelligent Feature

Version 1 redacted every detection the same way. Version 3 makes decisions:

- **Risk Scoring:** each detection is scored as `confidence × entity_weight` (Aadhaar, PAN and credit cards weigh 1.0; names weigh 0.5). Scores are blended into an overall risk level: LOW / MEDIUM / HIGH.
- **Adaptive Policies:** credit cards and phones keep only their **last 4** characters visible; Aadhaar, PAN, emails, names, URLs, locations, organisations and dates are replaced with descriptive tags.
- **Confidence Threshold + Review Queue:** detections between 0.25 and 0.4 confidence are not silently redacted — they are flagged for human review.
- **Allow List:** company and tool names (SWYNEX, Presidio, Python, GitHub, …) are never redacted.

## 🇮🇳 Indian PII Support

- **Indian mobile numbers:** `9995388012`, `+91 9995388012`, `99953 88012`, `+91 99953 88012`, and the `0`-trunk form.
- **Aadhaar:** 12-digit numbers in `XXXX XXXX XXXX`, `XXXXXXXXXXXX`, or `XXXX-XXXX-XXXX` form (starting 2–9).
- **PAN:** standard `ABCDE1234F` format.
- **PIN codes** (resume mode): 6-digit Indian PINs.
- **Indian States & Cities:** Custom DenyList ensures locations like Maharashtra, Mumbai, Karnataka, etc., are caught even if the base AI model misses them.
- **LinkedIn / GitHub URLs** (resume mode).

## 📄 Resume Mode

Pass `resume_mode=True`, or call the convenience wrapper. Resume mode additionally redacts URLs (LinkedIn/GitHub), locations, organisations, dates, and PIN codes — every field that identifies a candidate or proxies their age, gender, or background.

## 🛡️ Error Handling

- Empty, non-string, and over-5000-character inputs return a clear error instead of crashing.
- If the AI analyzer or anonymizer ever fails, the system falls back to a regex-only redactor.
- Optional **fail-closed** mode: pass `on_failure="block"` to refuse processing instead of degrading.

## 📊 Evaluation Suite

`evaluate.py` runs 14 labeled cases covering Indian phone formats, Aadhaar, PAN, URLs, PIN codes, clean text, error handling, and a documented failure case.

## 🚀 How to Run Locally (VS Code / Antigravity)

Follow these steps to clone and run the project on your local machine.

### 1. Clone the Repository

Open your terminal and run:
    git clone https://github.com/Anandaprian/SWYNEX-Intelligent-Feature.git
    cd SWYNEX-Intelligent-Feature

### 2. Set up a Virtual Environment (Recommended)

    python -m venv venv

Activate it (Windows):
    venv\Scripts\activate

Activate it (Mac/Linux):
    source venv/bin/activate

### 3. Install Dependencies

    pip install -r requirements.txt
    python -m spacy download en_core_web_lg

### 4. Run the Standard Demo

    python pii_guard.py

### 5. Run the Evaluation Suite

    python evaluate.py

### 6. Test With Your Own Data

Open `custom_demo.py` in VS Code or Antigravity, edit the `my_resume` variable with your own text, and run:

    python custom_demo.py

## ⚠️ Documented Failure Cases

- Spelled-out digits are not detected.
- Aadhaar is not Verhoeff-checksum validated — random 12-digit numbers can false-positive.
- PAN regex assumes uppercase.
- Regional names outside the DenyList may be missed.
- Only the English model is loaded.
- Obfuscated emails are not normalized.
- Inputs over 5000 characters are rejected, not chunked.
- Organisation/location detection depends on the spaCy model.
- Landline numbers with STD codes are not matched.
- Presidio's built-in UrlRecognizer is disabled — only LinkedIn and GitHub profile URLs are matched; generic web URLs are not redacted.

## 🔧 What is Presidio-native vs custom

| Feature | Source |
|---|---|
| Detection engine, operators, `allow_list`, `score_threshold`, `PatternRecognizer`, `deny_list` | Native Presidio |
| Risk scoring, review queue, regex fallback, resume mode, evaluation suite | Custom |
| Indian phone / Aadhaar / PAN / URL / PIN / DOB patterns | Custom recognizers on top of Presidio |

---
**Technologies Used:** Python · Microsoft Presidio · spaCy · Regular Expressions (Regex)
