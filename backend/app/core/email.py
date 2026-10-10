import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from dotenv import load_dotenv

# Explicitly load .env from backend folder
BASE_DIR = Path(__file__).resolve().parents[2]
env_path = BASE_DIR / ".env"
load_dotenv(dotenv_path=env_path)

SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 465))
SMTP_USER = os.getenv("SMTP_USER", "").strip()
# Remove whitespace from app password
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").replace(" ", "").strip()
EMAIL_FROM = os.getenv("EMAIL_FROM", SMTP_USER).strip()


def send_otp_email(target_email: str, otp_code: str) -> bool:
    print(f"[*] Preparing OTP email for {target_email} using user {SMTP_USER} on port {SMTP_PORT}")

    if not SMTP_USER or not SMTP_PASSWORD:
        print(f"[DEV MODE] Missing SMTP credentials. OTP code for {target_email} is: {otp_code}")
        return True

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"PentestAI - Password Reset Code: {otp_code}"
    msg["From"] = EMAIL_FROM
    msg["To"] = target_email

    html_content = f"""
    <div style="font-family: Arial, sans-serif; background-color: #0b1120; color: #e2e8f0; padding: 24px; border-radius: 8px;">
      <h2 style="color: #10b981;">PentestAI Security Verification</h2>
      <p>You requested to reset your password. Use the verification code below:</p>
      <div style="font-size: 30px; font-weight: bold; letter-spacing: 6px; color: #38bdf8; padding: 14px 0;">
        {otp_code}
      </div>
      <p style="color: #94a3b8; font-size: 12px;">This code will expire in 10 minutes. If you did not request this, ignore this email.</p>
    </div>
    """
    msg.attach(MIMEText(html_content, "html"))

    try:
        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(EMAIL_FROM, target_email, msg.as_string())
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(EMAIL_FROM, target_email, msg.as_string())

        print(f"[+] OTP email delivered to {target_email}")
        return True

    except Exception as exc:
        print(f"[!] Email delivery failed: {exc}")
        print(f"[FALLBACK CODE] OTP for {target_email} is: {otp_code}")
        raise exc