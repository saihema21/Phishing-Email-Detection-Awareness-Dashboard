from utils.analyzer import (
    analyze_sender,
    analyze_url,
    analyze_email_content,
    analyze_attachment,
    calculate_phishing_score,
    classify_risk,
    extract_urls
)


def test_suspicious_sender():
    score, indicators = analyze_sender(
        "security-alert@account-check.invalid.test"
    )

    assert score > 0
    assert len(indicators) > 0


def test_normal_sender():
    score, indicators = analyze_sender(
        "training@example.org"
    )

    assert score >= 0


def test_suspicious_url():
    score, indicators = analyze_url(
        "http://198.51.100.10/verify-account"
    )

    assert score > 0
    assert len(indicators) > 0


def test_https_url():
    score, indicators = analyze_url(
        "https://example.org/workshop"
    )

    assert score >= 0


def test_phishing_content():
    score, indicators = analyze_email_content(
        "URGENT: Verify Your Account",
        "Verify your password and personal information immediately."
    )

    assert score > 0
    assert len(indicators) > 0


def test_normal_content():
    score, indicators = analyze_email_content(
        "Cybersecurity Workshop Reminder",
        "Please attend the scheduled cybersecurity workshop."
    )

    assert score >= 0


def test_dangerous_attachment():
    score, indicators = analyze_attachment(
        "document.pdf.exe"
    )

    assert score > 0
    assert len(indicators) > 0


def test_normal_attachment():
    score, indicators = analyze_attachment(
        "document.pdf"
    )

    assert score >= 0


def test_high_risk_classification():
    assert classify_risk(80) == "HIGH RISK / LIKELY PHISHING"


def test_suspicious_classification():
    assert classify_risk(60) == "SUSPICIOUS"


def test_low_risk_classification():
    assert classify_risk(30) == "LOW RISK"


def test_safe_classification():
    assert classify_risk(10) == "SAFE"


def test_complete_phishing_analysis():

    result = calculate_phishing_score(
        sender="security-alert@account-check.invalid.test",
        subject="URGENT: Verify Your Account Immediately",
        body=(
            "Your account will be suspended. "
            "Verify your password and personal information immediately."
        ),
        urls=[
            "http://198.51.100.10/verify-account"
        ],
        attachment_name="document.pdf.exe"
    )

    assert result["risk_score"] >= 70
    assert result["classification"] == "HIGH RISK / LIKELY PHISHING"
    assert len(result["indicators"]) > 0
    assert len(result["recommendations"]) > 0


def test_safe_email_analysis():

    result = calculate_phishing_score(
        sender="training@example.org",
        subject="Cybersecurity Workshop Reminder",
        body=(
            "Please attend the scheduled cybersecurity workshop."
        ),
        urls=[
            "https://example.org/workshop"
        ],
        attachment_name=""
    )

    assert result["risk_score"] < 50


def test_url_extraction():

    text = """
    Please visit https://example.org/workshop
    or https://example.com/information
    """

    urls = extract_urls(text)

    assert len(urls) == 2
    assert "https://example.org/workshop" in urls
    assert "https://example.com/information" in urls


def test_empty_url_extraction():

    urls = extract_urls("No links are present.")

    assert urls == []


def test_multiple_urls():

    result = calculate_phishing_score(
        sender="security-alert@account-check.invalid.test",
        subject="Urgent Account Verification",
        body="Verify your account immediately.",
        urls=[
            "http://198.51.100.10/verify-account",
            "http://example.invalid.test/login",
            "http://example.invalid.test/payment"
        ],
        attachment_name=""
    )

    assert result["suspicious_url_count"] > 0
    assert result["risk_score"] > 0