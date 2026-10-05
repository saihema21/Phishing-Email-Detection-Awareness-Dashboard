import re
from urllib.parse import urlparse


# -----------------------------
# Keyword Categories
# -----------------------------

URGENCY_KEYWORDS = [
    "urgent",
    "immediately",
    "asap",
    "right now",
    "action required",
    "act now",
    "expires today",
    "final warning",
    "within 24 hours",
    "suspended",
    "suspension",
]

CREDENTIAL_KEYWORDS = [
    "password",
    "credential",
    "login",
    "log in",
    "username",
    "verify your account",
    "verify your identity",
    "security code",
    "otp",
    "authentication",
]

FINANCIAL_KEYWORDS = [
    "payment",
    "invoice",
    "bank",
    "credit card",
    "debit card",
    "transaction",
    "refund",
    "money",
    "billing",
    "account details",
]

THREAT_KEYWORDS = [
    "suspended",
    "blocked",
    "terminated",
    "legal action",
    "penalty",
    "locked",
    "disable",
    "deactivate",
]

GENERIC_GREETINGS = [
    "dear user",
    "dear customer",
    "hello user",
    "dear account holder",
    "valued customer",
]


# -----------------------------
# Sender Analysis
# -----------------------------

def analyze_sender(sender):
    indicators = []
    score = 0

    sender = sender.strip().lower()

    if "@" not in sender:
        indicators.append("Invalid sender email format")
        score += 15
        return score, indicators

    local_part, domain = sender.split("@", 1)

    suspicious_domain_patterns = [
        ".invalid.test",
        "account-check",
        "payment-check",
        "reward-center",
        "account-security",
        "parcel-check",
        "employee-check",
        "management-check",
    ]

    for pattern in suspicious_domain_patterns:
        if pattern in domain:
            indicators.append(
                f"Suspicious sender domain pattern detected: {domain}"
            )
            score += 20
            break

    if len(domain) > 30:
        indicators.append("Unusually long sender domain")
        score += 5

    if domain.count(".") >= 3:
        indicators.append("Multiple subdomains detected")
        score += 5

    if any(char.isdigit() for char in domain):
        indicators.append("Sender domain contains numeric characters")
        score += 3

    return score, indicators


# -----------------------------
# URL Analysis
# -----------------------------

def analyze_url(url):
    indicators = []
    score = 0

    url = url.strip()

    if not url:
        return score, indicators

    try:
        parsed = urlparse(url)
    except Exception:
        indicators.append("Unable to parse URL")
        return 10, indicators

    if parsed.scheme.lower() != "https":
        indicators.append("URL does not use HTTPS")
        score += 10

    hostname = parsed.hostname or ""

    # Raw IP address detection
    if re.fullmatch(
        r"(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
        r"(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}",
        hostname
    ):
        indicators.append("URL uses a raw IP address")
        score += 20

    # URL shortener patterns
    shortener_domains = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly",
    ]

    if hostname.lower() in shortener_domains:
        indicators.append("URL uses a shortened URL service")
        score += 15

    # Suspicious URL keywords
    suspicious_terms = [
        "login",
        "verify",
        "verification",
        "password",
        "urgent",
        "payment",
        "account",
        "security",
    ]

    if any(term in url.lower() for term in suspicious_terms):
        indicators.append("URL contains suspicious security or action-related terms")
        score += 10

    if "@" in url:
        indicators.append("URL contains an @ symbol")
        score += 15

    if len(url) > 100:
        indicators.append("Unusually long URL")
        score += 5

    return score, indicators


# -----------------------------
# Email Content Analysis
# -----------------------------

def analyze_email_content(subject, body):
    indicators = []
    score = 0

    subject = subject.strip()
    body = body.strip()

    text = f"{subject} {body}".lower()

    urgency_count = sum(
        text.count(keyword.lower())
        for keyword in URGENCY_KEYWORDS
    )

    credential_count = sum(
        text.count(keyword.lower())
        for keyword in CREDENTIAL_KEYWORDS
    )

    financial_count = sum(
        text.count(keyword.lower())
        for keyword in FINANCIAL_KEYWORDS
    )

    threat_count = sum(
        text.count(keyword.lower())
        for keyword in THREAT_KEYWORDS
    )

    # Urgency
    if urgency_count > 0:
        indicators.append(
            f"Urgency/manipulation language detected ({urgency_count})"
        )
        score += min(urgency_count * 5, 20)

    # Credentials
    if credential_count > 0:
        indicators.append(
            f"Credential-related language detected ({credential_count})"
        )
        score += min(credential_count * 8, 25)

    # Financial
    if financial_count > 0:
        indicators.append(
            f"Financial/payment language detected ({financial_count})"
        )
        score += min(financial_count * 5, 20)

    # Threats
    if threat_count > 0:
        indicators.append(
            f"Threat language detected ({threat_count})"
        )
        score += min(threat_count * 5, 20)

    # Generic greeting
    if any(greeting in text for greeting in GENERIC_GREETINGS):
        indicators.append("Generic greeting detected")
        score += 5

    # Password request
    password_request_patterns = [
        "send your password",
        "provide your password",
        "confirm your password",
        "enter your password",
        "verify your password",
    ]

    if any(pattern in text for pattern in password_request_patterns):
        indicators.append("Password request detected")
        score += 15

    # Personal information
    personal_info_patterns = [
        "personal information",
        "personal details",
        "identity information",
        "date of birth",
        "social security",
        "account information",
    ]

    if any(pattern in text for pattern in personal_info_patterns):
        indicators.append("Personal information request detected")
        score += 10

    # Excessive exclamation marks
    exclamation_count = text.count("!")

    if exclamation_count >= 3:
        indicators.append("Excessive exclamation marks detected")
        score += 5

    # Uppercase ratio
    letters = [char for char in subject + " " + body if char.isalpha()]

    if letters:
        uppercase_ratio = sum(
            char.isupper() for char in subject + " " + body
            if char.isalpha()
        ) / len(letters)

        if uppercase_ratio > 0.35:
            indicators.append("High uppercase character ratio detected")
            score += 5

    return score, indicators


# -----------------------------
# Attachment Analysis
# -----------------------------

def analyze_attachment(attachment_name):
    indicators = []
    score = 0

    if not attachment_name:
        return score, indicators

    attachment_name = attachment_name.strip().lower()

    dangerous_extensions = [
        ".exe",
        ".scr",
        ".js",
        ".bat",
        ".cmd",
        ".vbs",
        ".ps1",
        ".jar",
    ]

    if any(
        attachment_name.endswith(extension)
        for extension in dangerous_extensions
    ):
        indicators.append(
            f"Potentially dangerous attachment type detected: {attachment_name}"
        )
        score += 25

    # Double extension detection
    double_extensions = [
        ".pdf.exe",
        ".doc.exe",
        ".docx.exe",
        ".jpg.exe",
        ".png.exe",
    ]

    if any(
        attachment_name.endswith(extension)
        for extension in double_extensions
    ):
        indicators.append("Double file extension detected")
        score += 20

    return score, indicators


# -----------------------------
# Risk Classification
# -----------------------------

def classify_risk(score):
    if score >= 70:
        return "HIGH RISK / LIKELY PHISHING"

    elif score >= 50:
        return "SUSPICIOUS"

    elif score >= 25:
        return "LOW RISK"

    else:
        return "SAFE"


# -----------------------------
# Recommendation Engine
# -----------------------------

def generate_recommendations(classification, indicators):
    recommendations = []

    if classification == "HIGH RISK / LIKELY PHISHING":
        recommendations.extend([
            "Do not click suspicious links.",
            "Do not provide passwords, OTPs, or personal information.",
            "Do not open suspicious attachments.",
            "Verify the sender through an independent trusted channel.",
            "Report the email to your security or IT team.",
        ])

    elif classification == "SUSPICIOUS":
        recommendations.extend([
            "Verify the sender before taking action.",
            "Inspect URLs carefully before clicking.",
            "Avoid sharing credentials or sensitive information.",
            "Check whether the request matches the expected context.",
        ])

    elif classification == "LOW RISK":
        recommendations.extend([
            "Review the sender and context before responding.",
            "Verify unusual requests independently.",
        ])

    else:
        recommendations.extend([
            "No major phishing indicators were detected.",
            "Continue following normal email security practices.",
        ])

    return recommendations


# -----------------------------
# Main Phishing Risk Engine
# -----------------------------

def calculate_phishing_score(
    sender,
    subject,
    body,
    urls=None,
    attachment_name=""
):
    if urls is None:
        urls = []

    total_score = 0
    indicators = []

    # Sender
    sender_score, sender_indicators = analyze_sender(sender)
    total_score += sender_score
    indicators.extend(sender_indicators)

    # Content
    content_score, content_indicators = analyze_email_content(
        subject,
        body
    )
    total_score += content_score
    indicators.extend(content_indicators)

    # URLs
    suspicious_url_count = 0

    for url in urls:
        url_score, url_indicators = analyze_url(url)

        if url_score > 0:
            suspicious_url_count += 1

        total_score += url_score
        indicators.extend(url_indicators)

    # Attachment
    attachment_score, attachment_indicators = analyze_attachment(
        attachment_name
    )

    total_score += attachment_score
    indicators.extend(attachment_indicators)

    # URL count indicator
    if len(urls) > 2:
        indicators.append("Multiple URLs detected")
        total_score += 5

    # Cap score
    total_score = min(total_score, 100)

    classification = classify_risk(total_score)

    recommendations = generate_recommendations(
        classification,
        indicators
    )

    return {
        "risk_score": total_score,
        "classification": classification,
        "indicators": indicators,
        "recommendations": recommendations,
        "suspicious_url_count": suspicious_url_count,
    }


# -----------------------------
# URL Extraction
# -----------------------------

def extract_urls(text):
    if not text:
        return []

    url_pattern = r"https?://[^\s]+"

    urls = re.findall(url_pattern, text)

    cleaned_urls = []

    for url in urls:
        url = url.rstrip(".,!?;:)")

        if url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls