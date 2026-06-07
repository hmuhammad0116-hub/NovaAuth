import os
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
OWNER_EMAIL = os.getenv("OWNER_EMAIL", SMTP_USER)


def send_email(to_email: str, subject: str, body: str):
    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        print("SMTP not configured, email skipped:", subject)
        return False

    msg = MIMEText(body, "html")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_FROM, [to_email], msg.as_string())

    return True


def send_verification_code(email: str, code: str):
    return send_email(
        email,
        "NovaAuth Email Verification Code",
        f"""
        <h2>NovaAuth Verification</h2>
        <p>Your verification code is:</p>
        <h1>{code}</h1>
        <p>If you did not request this, ignore this email.</p>
        """
    )


def send_staff_request_email(username: str, email: str, requested_role: str):
    return send_email(
        OWNER_EMAIL,
        "NovaAuth Staff Request",
        f"""
        <h2>New Staff Request</h2>
        <p><b>User:</b> {username}</p>
        <p><b>Email:</b> {email}</p>
        <p><b>Requested Role:</b> {requested_role}</p>
        <p>Open NovaAuth Admin Panel to approve or reject.</p>
        """
    )