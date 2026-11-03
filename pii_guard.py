"""
PII Guard v3 — Indian PII + Resume Anonymizer
SWYNEX Internship · Task 3 (Intelligent Feature)

v3.2 fix: Added Indian States DenyList to catch regional locations,
and disabled the default UrlRecognizer to prevent "B.Tech" from being
mistagged as a URL.
"""
import logging
import re

logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)

from presidio_analyzer import (
    AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult,
)
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig
from presidio_anonymizer.operators import Operator

try:
    from presidio_anonymizer.operators import OperatorType
    _ANON_TYPE = OperatorType.Anonymize
except ImportError:
    _ANON_TYPE = "Anonymize"


INDIAN_PHONE_REGEX = r"(?<!\d)(?:\+91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)"
AADHAAR_REGEX = r"(?<!\d)[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}(?![\s-]?\d)"
PAN_REGEX = r"(?<![A-Z0-9])[A-Z]{5}\d{4}[A-Z](?![A-Z0-9])"
CARD_REGEX = r"\b(?:\d[ -]?){13,19}\b"
EMAIL_REGEX = r"[\w.+-]+@[\w-]+\.[\w.]+"
URL_REGEX = r"(?:https?://)?(?:www\.)?(?:linkedin\.com/in/|github\.com/)[\w\-]+/?"
PIN_REGEX = r"(?<!\d)[1-9]\d{5}(?!\d)"
DOB_REGEX = r"(?i)(?:DOB|Date\s+of\s+Birth|D\.O\.B\.?)\s*[:\-]?\s*\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}"


class MaskKeepLast(Operator):
    def operate(self, text, params=None):
        keep = 4
        if params and "keep" in params:
            keep = int(params["keep"])
        if len(text) <= keep:
            return "*" * len(text)
        return "*" * (len(text) - keep) + text[-keep:]

    def operator_name(self):
        return "mask_keep_last"

    def operator_type(self):
        return _ANON_TYPE

    def validate(self, params=None):
        pass


print("Loading AI models...\n")
analyzer = AnalyzerEngine()
anonymizer = AnonymizerEngine()
try:
    anonymizer.add_anonymizer(MaskKeepLast)
except AttributeError as exc:
    raise RuntimeError(
        "This build requires presidio-anonymizer >= 0.0.40 for custom operators. "
        "Run: pip install -U presidio-anonymizer presidio-analyzer"
    ) from exc

# FIX 1: Remove default UrlRecognizer so it doesn't flag "B.Tech"
try:
    analyzer.registry.remove_recognizer("UrlRecognizer")
except Exception:
    pass

def _add(entity, pattern):
    analyzer.registry.add_recognizer(
        PatternRecognizer(supported_entity=entity, patterns=[pattern])
    )

_add("PHONE_NUMBER", Pattern(name="indian_phone", regex=INDIAN_PHONE_REGEX, score=0.85))
_add("AADHAAR", Pattern(name="aadhaar", regex=AADHAAR_REGEX, score=0.8))
_add("PAN", Pattern(name="pan", regex=PAN_REGEX, score=0.85))
_add("URL", Pattern(name="url", regex=URL_REGEX, score=0.9))
_add("IN_PIN", Pattern(name="in_pin", regex=PIN_REGEX, score=0.6))
_add("DATE_TIME", Pattern(name="dob", regex=DOB_REGEX, score=0.9))

# FIX 2: Add DenyLists to force the AI to catch regional names and states.
DENY_NAMES = ["Ananda", "Rahul", "Sharma", "Priya", "Arjun", "Sneha"]
INDIAN_STATES = [
    "Maharashtra", "Karnataka", "Tamil Nadu", "Delhi", "Uttar Pradesh", 
    "Gujarat", "West Bengal", "Rajasthan", "Kerala", "Telangana", 
    "Andhra Pradesh", "Madhya Pradesh", "Punjab", "Haryana", "Bihar", 
    "Odisha", "Assam", "Uttarakhand", "Himachal Pradesh", "Goa", 
    "Jharkhand", "Chhattisgarh", "Mumbai", "Bengaluru", "Bangalore", 
    "Chennai", "Kolkata", "Hyderabad", "Pune", "Ahmedabad", "Jaipur"
]

analyzer.registry.add_recognizer(
    PatternRecognizer(supported_entity="PERSON", deny_list=DENY_NAMES)
)
analyzer.registry.add_recognizer(
    PatternRecognizer(supported_entity="LOCATION", deny_list=INDIAN_STATES)
)


ENTITY_RISK_WEIGHTS = {
    "CREDIT_CARD": 1.0, "AADHAAR": 1.0, "PAN": 1.0,
    "PHONE_NUMBER": 0.8, "EMAIL_ADDRESS": 0.7, "URL": 0.6,
    "PERSON": 0.5, "IN_PIN": 0.5, "LOCATION": 0.4,
    "ORGANIZATION": 0.4, "DATE_TIME": 0.3,
}
DEFAULT_WEIGHT = 0.5
REVIEW_FLOOR = 0.25
REDACT_THRESHOLD = 0.4

ALLOW_LIST = ["SWYNEX", "Technologies", "Presidio", "Python", "GitHub", "Google Colab"]

DEFAULT_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON",
                    "CREDIT_CARD", "AADHAAR", "PAN"]
RESUME_ENTITIES = DEFAULT_ENTITIES + ["URL", "LOCATION", "ORGANIZATION",
                                      "DATE_TIME", "IN_PIN"]

OPERATORS = {
    "CREDIT_CARD": OperatorConfig("mask_keep_last", {"keep": 4}),
    "PHONE_NUMBER": OperatorConfig("mask_keep_last", {"keep": 4}),
    "AADHAAR": OperatorConfig("replace", {"new_value": "<AADHAAR>"}),
    "PAN": OperatorConfig("replace", {"new_value": "<PAN>"}),
    "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
    "PERSON": OperatorConfig("replace", {"new_value": "<PERSON>"}),
    "URL": OperatorConfig("replace", {"new_value": "<URL>"}),
    "LOCATION": OperatorConfig("replace", {"new_value": "<LOCATION>"}),
    "ORGANIZATION": OperatorConfig("replace", {"new_value": "<ORG>"}),
    "DATE_TIME": OperatorConfig("replace", {"new_value": "<DATE>"}),
    "IN_PIN": OperatorConfig("replace", {"new_value": "<PIN>"}),
    "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"}),
}


FALLBACK_RULES = [
    (re.compile(EMAIL_REGEX), "<EMAIL>"),
    (re.compile(CARD_REGEX), "<CARD>"),
    (re.compile(AADHAAR_REGEX), "<AADHAAR>"),
    (re.compile(PAN_REGEX), "<PAN>"),
    (re.compile(INDIAN_PHONE_REGEX), "<PHONE>"),
]
RESUME_FALLBACK_RULES = [
    (re.compile(URL_REGEX), "<URL>"),
    (re.compile(DOB_REGEX), "<DATE>"),
    (re.compile(PIN_REGEX), "<PIN>"),
]


def regex_fallback(text, resume_mode=False):
    safe = text
    for pattern, replacement in FALLBACK_RULES:
        safe = pattern.sub(replacement, safe)
    if resume_mode:
        for pattern, replacement in RESUME_FALLBACK_RULES:
            safe = pattern.sub(replacement, safe)
    return safe


# FIX 3: Trim PERSON spans that cross a newline (prevents eating "Email:")
def _trim_person_spans(text, results):
    cleaned = []
    for r in results:
        if r.entity_type == "PERSON":
            snippet = text[r.start:r.end]
            if "\n" in snippet:
                first_line = snippet.split("\n", 1)[0]
                if first_line.strip():
                    cleaned.append(RecognizerResult(
                        entity_type=r.entity_type,
                        start=r.start,
                        end=r.start + len(first_line),
                        score=r.score,
                    ))
                continue
        cleaned.append(r)
    return cleaned


def compute_risk(results):
    if not results:
        return 0.0, "LOW"
    scores = [r.score * ENTITY_RISK_WEIGHTS.get(r.entity_type, DEFAULT_WEIGHT)
              for r in results]
    blended = 0.7 * max(scores) + 0.3 * min(sum(scores), 1.0)
    blended = round(min(blended, 1.0), 2)
    if blended >= 0.7:
        level = "HIGH"
    elif blended >= 0.4:
        level = "MEDIUM"
    else:
        level = "LOW"
    return blended, level


def protect_pii(text, verbose=True, resume_mode=False, on_failure="degraded"):
    report = {
        "input": text, "output": None, "entities": [],
        "risk_score": 0.0, "risk_level": "LOW",
        "review": [], "error": None, "resume_mode": resume_mode,
    }

    if not isinstance(text, str):
        report["error"] = "Input must be a string."
        if verbose: print(f"[ERROR] {report['error']}\n")
        return report
    if not text.strip():
        report["error"] = "Input is empty — nothing to scan."
        if verbose: print(f"[ERROR] {report['error']}\n")
        return report
    if len(text) > 5000:
        report["error"] = "Input too long (max 5000 characters for this demo)."
        if verbose: print(f"[ERROR] {report['error']}\n")
        return report

    entities = RESUME_ENTITIES if resume_mode else DEFAULT_ENTITIES

    try:
        raw = analyzer.analyze(
            text=text, language="en", entities=entities,
            score_threshold=REVIEW_FLOOR, allow_list=ALLOW_LIST,
        )
    except Exception as exc:
        if on_failure == "block":
            report["error"] = f"Analyzer failed ({exc}); refusing to process (fail-closed)."
            report["risk_level"] = "UNKNOWN"
            if verbose: print(f"[BLOCKED] {report['error']}\n")
            return report
        report["error"] = f"Analyzer failed ({exc}); regex fallback used."
        report["output"] = regex_fallback(text, resume_mode)
        report["risk_level"] = "UNKNOWN"
        if verbose:
            print(f"[FALLBACK] {report['error']}")
            print(f"Safe output: {report['output']}\n")
        return report

    raw = _trim_person_spans(text, raw)

    kept, review = [], []
    for r in raw:
        snippet = text[r.start:r.end]
        if r.score >= REDACT_THRESHOLD:
            kept.append(r)
        else:
            review.append(f"{r.entity_type} ('{snippet}', {r.score:.2f})")

    report["entities"] = sorted({r.entity_type for r in kept})
    report["review"] = review
    report["risk_score"], report["risk_level"] = compute_risk(kept)

    try:
        anonymized = anonymizer.anonymize(
            text=text, analyzer_results=kept, operators=OPERATORS,
        )
        report["output"] = anonymized.text
    except Exception as exc:
        if on_failure == "block":
            report["error"] = f"Anonymizer failed ({exc}); refusing to process (fail-closed)."
            report["output"] = None
            if verbose: print(f"[BLOCKED] {report['error']}\n")
            return report
        report["error"] = f"Anonymizer failed ({exc}); regex fallback used."
        report["output"] = regex_fallback(text, resume_mode)

    if verbose:
        print("--- Original Input ---")
        print(text)
        print("--- Safe Output (Redacted) ---")
        print(report["output"])
        print(f"Detected: {report['entities'] or 'none'}")
        print(f"Risk: {report['risk_level']} ({report['risk_score']})")
        if report["review"]:
            print(f"Needs human review: {report['review']}")
        if report["error"]:
            print(f"[WARN] {report['error']}")
        print("-" * 60 + "\n")

    return report


def redact_resume(text):
    return protect_pii(text, verbose=False, resume_mode=True)


SAMPLE_TEXTS = [
    "Hi, my name is Ananda and my email is ananda@example.com.",
    "Call me at +91 99953 88012 or 9995388012.",
    "Aadhaar: 2345 6789 0123 | PAN: ABCDE1234F",
    "Please charge my card: 4111 1111 1111 1111.",
    "I work at SWYNEX Technologies and I love Python.",
]

RESUME_SAMPLE = """Rahul Sharma
Email: rahul.sharma@example.com | Phone: +91 98765 43210
LinkedIn: linkedin.com/in/rahulsharma | GitHub: github.com/rahulsharma
Location: Bengaluru, Karnataka - 560001
DOB: 15/08/1998 | Aadhaar: 2345 6789 0123 | PAN: ABCDE1234F
Education: B.Tech, IIT Madras (2016-2020)
Experience: Software Engineer at Infosys (2020-2023)"""


def run_samples():
    print("=" * 60)
    print("STANDARD MODE SAMPLES")
    print("=" * 60)
    for text in SAMPLE_TEXTS:
        protect_pii(text)
    print("=" * 60)
    print("RESUME MODE SAMPLE")
    print("=" * 60)
    protect_pii(RESUME_SAMPLE, resume_mode=True)


def interactive_demo():
    print("=== PII Guard v3 ===")
    print("1. Scan your own text")
    print("2. Run built-in samples")
    print("3. Toggle resume mode")
    print("4. Exit")
    resume_mode = False
    while True:
        try:
            choice = input("Choose 1/2/3/4: ").strip()
        except EOFError:
            break
        if choice == "1":
            try:
                user_text = input("Paste your text: ")
            except EOFError:
                break
            protect_pii(user_text, resume_mode=resume_mode)
        elif choice == "2":
            run_samples()
        elif choice == "3":
            resume_mode = not resume_mode
            print(f"Resume mode is now {'ON' if resume_mode else 'OFF'}.")
        elif choice == "4":
            print("Bye!")
            break
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    run_samples()
