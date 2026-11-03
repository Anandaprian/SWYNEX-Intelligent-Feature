"""
Evaluation suite for PII Guard v3.
"""
from pii_guard import protect_pii

TEST_CASES = [
    {"name": "Email", "text": "Contact me at test.user@example.com",
     "expected": {"EMAIL_ADDRESS"}},
    {"name": "Regional name (DenyList)", "text": "Hi, my name is Ananda.",
     "expected": {"PERSON"}},
    {"name": "Indian phone (plain)", "text": "Call 9995388012 now.",
     "expected": {"PHONE_NUMBER"}},
    {"name": "Indian phone (+91)", "text": "Call +91 9995388012 now.",
     "expected": {"PHONE_NUMBER"}},
    {"name": "Indian phone (grouped)", "text": "Call 99953 88012 now.",
     "expected": {"PHONE_NUMBER"}},
    {"name": "Indian phone (+91 grouped)", "text": "Call +91 99953 88012 now.",
     "expected": {"PHONE_NUMBER"}},
    {"name": "Aadhaar", "text": "Aadhaar: 2345 6789 0123",
     "expected": {"AADHAAR"}},
    {"name": "PAN", "text": "PAN: ABCDE1234F",
     "expected": {"PAN"}},
    {"name": "Credit card", "text": "Card: 4111 1111 1111 1111",
     "expected": {"CREDIT_CARD"}},
    {"name": "LinkedIn URL (resume mode)",
     "text": "Profile: https://linkedin.com/in/abc123def",
     "expected": {"URL"}, "resume_mode": True, "subset": True},
    {"name": "Indian PIN (resume mode)", "text": "PIN: 560001",
     "expected": {"IN_PIN"}, "resume_mode": True},
    {"name": "Clean text", "text": "Machine learning is fascinating.",
     "expected": set()},
    {"name": "Empty input (error handling)", "text": "",
     "expected": set(), "expect_error": True},
    {"name": "Spelled-out phone (known limitation)",
     "text": "Call me at nine nine nine five three eight eight zero one two.",
     "expected": {"PHONE_NUMBER"}, "xfail": True},
]

FAILURE_CASES = [
    "Spelled-out digits are not detected by any recognizer.",
    "Aadhaar is NOT Verhoeff-checksum validated — a random 12-digit number starting 2-9 can false-positive.",
    "PAN regex assumes uppercase; lowercase PANs are missed.",
    "Regional names outside DENY_NAMES may be missed by the English model.",
    "Only the English language model is loaded.",
    "Obfuscated emails ('name [at] domain dot com') are not normalized.",
    "Inputs over 5000 characters are rejected, not chunked.",
    "Organisation/location detection depends on spaCy and varies by model version.",
    "Indian landlines with STD codes are not matched — mobile formats only.",
]

def fmt(entity_set):
    if not entity_set: return "-"
    if isinstance(entity_set, str): return entity_set
    return ", ".join(sorted(entity_set))

def run_evaluation():
    print("=" * 100)
    print("PII GUARD v3 — EVALUATION SUITE")
    print("=" * 100)
    print(f"{'Case':<36}{'Expected':<24}{'Detected':<24}{'Result'}")
    print("-" * 100)

    tp = fp = fn = 0
    passed = 0
    total = len(TEST_CASES)

    for case in TEST_CASES:
        result = protect_pii(case["text"], verbose=False,
                             resume_mode=case.get("resume_mode", False))

        if case.get("expect_error"):
            detected = "ERROR" if result["error"] else "no error"
            ok = result["error"] is not None
        elif case.get("xfail"):
            detected = set(result["entities"])
            ok = detected != case["expected"]
        elif case.get("subset"):
            detected = set(result["entities"])
            ok = case["expected"].issubset(detected)
        else:
            detected = set(result["entities"])
            ok = detected == case["expected"]
            tp += len(detected & case["expected"])
            fp += len(detected - case["expected"])
            fn += len(case["expected"] - detected)

        passed += ok
        label = "PASS" if ok else "FAIL"
        if case.get("xfail"): label += " (known limitation)"
        if case.get("subset"): label += " (subset)"
        print(f"{case['name']:<36}{fmt(case['expected']):<24}{fmt(detected):<24}{label}")

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0

    print("-" * 100)
    print(f"Cases passed (incl. documented xfail/subset): {passed}/{total}")
    print(f"Entity-level precision: {precision:.2f}")
    print(f"Entity-level recall:    {recall:.2f}")
    print("\n--- Documented Failure Cases / Limitations ---")
    for line in FAILURE_CASES:
        print(f"- {line}")

if __name__ == "__main__":
    run_evaluation()
