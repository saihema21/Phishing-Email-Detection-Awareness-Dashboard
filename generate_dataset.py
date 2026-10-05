import random
import pandas as pd

random.seed(42)

legitimate_templates = [
    {
        "category": "University Notice",
        "sender": "training@example.org",
        "subject": "Cybersecurity Workshop Reminder",
        "body": "Hello Student, this is a reminder about the upcoming cybersecurity workshop. Please attend the scheduled session.",
    },
    {
        "category": "HR Update",
        "sender": "hr@example.com",
        "subject": "Monthly HR Update",
        "body": "Hello Team, please review the latest HR updates and announcements available through the official employee portal.",
    },
    {
        "category": "Project Update",
        "sender": "project@example.org",
        "subject": "Project Status Update",
        "body": "Hello Team, the project status meeting is scheduled for tomorrow. Please review the latest project progress.",
    },
    {
        "category": "Meeting Reminder",
        "sender": "meetings@example.com",
        "subject": "Meeting Reminder",
        "body": "This is a reminder for the scheduled team meeting. Please join at the planned time.",
    },
    {
        "category": "Shopping Confirmation",
        "sender": "orders@example.net",
        "subject": "Order Confirmation",
        "body": "Thank you for your order. Your fictional order has been successfully confirmed.",
    },
    {
        "category": "Newsletter",
        "sender": "newsletter@example.org",
        "subject": "Weekly Technology Newsletter",
        "body": "Here are this week's technology articles and educational resources.",
    },
    {
        "category": "Password Confirmation",
        "sender": "accounts@example.com",
        "subject": "Password Change Confirmation",
        "body": "Your password was successfully changed. If you made this change, no further action is required.",
    },
]

phishing_templates = [
    {
        "category": "Fake Verification",
        "sender": "security-alert@account-check.invalid.test",
        "subject": "URGENT: Verify Your Account Immediately",
        "body": "Your account will be suspended. Verify your password and personal information immediately.",
    },
    {
        "category": "Fake Invoice",
        "sender": "billing-alert@payment-check.invalid.test",
        "subject": "URGENT PAYMENT REQUIRED",
        "body": "Your outstanding payment is overdue. Confirm your payment details immediately to avoid account suspension.",
    },
    {
        "category": "Fake Prize",
        "sender": "winner@reward-center.invalid.test",
        "subject": "Congratulations! You Have Won",
        "body": "You have won a reward. Confirm your personal details immediately to claim your prize.",
    },
    {
        "category": "Fake Password Expiration",
        "sender": "password@account-security.invalid.test",
        "subject": "Your Password Expires Today",
        "body": "Your password will expire today. Verify your credentials immediately to prevent account suspension.",
    },
    {
        "category": "Fake Delivery",
        "sender": "delivery@parcel-check.invalid.test",
        "subject": "Urgent Delivery Verification",
        "body": "Your delivery is waiting for verification. Confirm your personal information immediately.",
    },
    {
        "category": "Fake HR Request",
        "sender": "hr-request@employee-check.invalid.test",
        "subject": "Urgent Employee Verification",
        "body": "Please verify your employee information and password immediately.",
    },
    {
        "category": "Fake Executive Request",
        "sender": "executive@management-check.invalid.test",
        "subject": "Urgent Confidential Request",
        "body": "This request requires immediate action. Confirm your account information and payment details.",
    },
]

safe_urls = [
    "https://example.com/information",
    "https://example.org/workshop",
    "https://example.net/confirmation",
]

phishing_urls = [
    "http://198.51.100.10/verify-account",
    "http://example.invalid.test/login",
    "http://example.invalid.test/urgent-payment",
]

records = []

for i in range(600):

    if i % 2 == 0:
        template = random.choice(legitimate_templates)

        records.append({
            "email_id": f"EMAIL-{i+1:04d}",
            "sender": template["sender"],
            "sender_domain": template["sender"].split("@")[1],
            "subject": template["subject"],
            "body": template["body"],
            "urls": random.choice(safe_urls),
            "attachment_name": "",
            "label": "LEGITIMATE",
            "category": template["category"]
        })

    else:
        template = random.choice(phishing_templates)

        attachment = random.choice([
            "",
            "",
            "document.pdf.exe",
            "invoice.js",
            "account_verification.scr"
        ])

        records.append({
            "email_id": f"EMAIL-{i+1:04d}",
            "sender": template["sender"],
            "sender_domain": template["sender"].split("@")[1],
            "subject": template["subject"],
            "body": template["body"],
            "urls": random.choice(phishing_urls),
            "attachment_name": attachment,
            "label": "PHISHING",
            "category": template["category"]
        })

df = pd.DataFrame(records)

df.to_csv(
    "data/phishing_email_dataset.csv",
    index=False
)

print("Dataset generated successfully!")
print(f"Total records: {len(df)}")
print("\nClass distribution:")
print(df["label"].value_counts())