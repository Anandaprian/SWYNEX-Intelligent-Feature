"""
Custom Demo — PII Guard v3
Edit the `my_resume` variable below with your own text to test the redaction!
"""
from pii_guard import redact_resume

# ==========================================
# EDIT THIS TEXT WITH YOUR OWN DATA:
# ==========================================
my_resume = """
Priya Sharma
Email: priya@example.com | Phone: +91 98765 43210
LinkedIn: linkedin.com/in/priyasharma | GitHub: github.com/priyasharma
Location: Mumbai, Maharashtra - 400001
DOB: 01/01/1995 | Aadhaar: 2345 6789 0123 | PAN: ABCDE1234F
Education: B.Tech, IIT Bombay
"""

# ==========================================
# DO NOT EDIT BELOW THIS LINE:
# ==========================================
if __name__ == "__main__":
    print("--- Original Input ---")
    print(my_resume.strip())
    print("\n--- Safe Output (Redacted) ---")
    
    result = redact_resume(my_resume)
    
    print(result["output"])
    print("\n--- Analysis ---")
    print(f"Entities Found: {result['entities']}")
    print(f"Risk Level: {result['risk_level']} ({result['risk_score']})")
