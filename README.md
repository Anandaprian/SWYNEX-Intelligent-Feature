# SWYNEX – Intelligent Feature

## Task 3: PII Guard v3 – Indian PII + Resume Anonymizer

An upgrade to the Task 2 PII Guard prototype, built with **Microsoft Presidio**. Version 3 adds Indian-specific PII detection, a resume-anonymization mode, risk-aware adaptive redaction, error handling, and a full evaluation suite.

## 🧠 The Intelligent Feature

Version 1 redacted every detection the same way. Version 3 makes decisions:

- **Risk Scoring:** Each detection is scored as `confidence × entity_weight` (Aadhaar, PAN, and credit cards weigh 1.0; names weigh 0.5). Scores are blended into an overall risk level: LOW / MEDIUM / HIGH.
- **Adaptive Policies:** Credit cards and phone numbers keep only their **last 4 characters** visible. Aadhaar, PAN, emails, names, URLs, locations, organisations, and dates are replaced with descriptive tags.
- **Confidence Threshold + Review Queue:** Detections between 0.25 and 0.4 confidence are not silently redacted. Instead, they are flagged for human review.
- **Allow List:** Company and tool names (SWYNEX, Presidio, Python, GitHub, etc.) are never redacted.

## 🇮🇳 Indian PII Support

- **Indian Mobile Numbers:** Supports the following formats:
  - `9995388012`
  - `+91 9995388012`
  - `99953 88012`
  - `+91 99953 88012`
  - `0`-trunk format.
- **Aadhaar:** 12-digit numbers in the following formats (starting with 2–9):
  - `XXXX XXXX XXXX`
  - `XXXXXXXXXXXX`
  - `XXXX-XXXX-XXXX`
- **PAN:** Standard `ABCDE1234F` format.
- **PIN Codes (Resume Mode):** Six-digit Indian PIN codes.
- **LinkedIn / GitHub URLs (Resume Mode):** Detects LinkedIn and GitHub profile URLs.

## 📄 Resume Mode

Pass `resume_mode=True`, or use the convenience wrapper:

```python
from pii_guard import redact_resume

print(redact_resume(resume_text))
```

Resume mode additionally redacts URLs (LinkedIn/GitHub), locations, organisations, dates, and PIN codes. This helps anonymize fields that identify a candidate or may reveal their age, gender, or background.

## 🛡️ Error Handling

- Empty, non-string, and over-5000-character inputs return a clear error instead of crashing.
- If the AI analyzer or anonymizer fails, the system falls back to a regex-only redactor.
- **Optional Fail-Closed Mode:** Pass `on_failure="block"` to refuse processing instead of degrading to regex-only redaction.

## 📊 Evaluation Suite

`evaluate.py` runs **14 labeled test cases** covering:

- Indian phone number formats
- Aadhaar
- PAN
- URLs
- PIN codes
- Clean text
- Error handling
- A documented failure case

Run the evaluation:

```bash
python evaluate.py
```

## ⚠️ Documented Failure Cases

- Spelled-out digits are not detected.
- Aadhaar numbers are not Verhoeff-checksum validated. Random 12-digit numbers may therefore produce false positives.
- PAN regex assumes uppercase characters.
- Regional names outside the DenyList may be missed.
- Only the English model is loaded.
- Obfuscated emails are not normalized.
- Inputs exceeding 5000 characters are rejected rather than processed in chunks.
- Organisation and location detection depends on the spaCy model.
- Landline numbers with STD codes are not matched.
- Presidio's built-in `UrlRecognizer` is disabled. Only LinkedIn and GitHub profile URLs are matched; generic web URLs are not redacted.

## 🔧 What Is Presidio-Native vs. Custom?

| Feature | Source |
|---|---|
| Detection engine, operators, `allow_list`, `score_threshold`, `PatternRecognizer`, `deny_list` | Native Presidio |
| Risk scoring, review queue, regex fallback, resume mode, evaluation suite | Custom |
| Indian phone, Aadhaar, PAN, URL, PIN, and DOB patterns | Custom recognizers built on top of Presidio |

## 🚀 How to Run

### 1. Install Dependencies

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### 2. Run the Demo

```bash
python pii_guard.py
```

### 3. Run the Evaluation

```bash
python evaluate.py
```

### 4. Interactive Mode

```python
from pii_guard import interactive_demo

interactive_demo()
```
