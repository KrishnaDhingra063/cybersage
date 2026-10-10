import os
import logging
import httpx

logger = logging.getLogger(__name__)

def notify_approval_needed(engagement_id: str, tool: str, target: str, reasoning: str = ""):
    """Fire-and-forget webhook/email when a high-risk tool needs Lead approval. Never blocks."""
    webhook = os.getenv("NOTIFY_WEBHOOK_URL") or os.getenv("SLACK_WEBHOOK_URL")
    # 1. Webhook (Slack/Teams generic)
    if webhook:
        try:
            payload = {
                "text": f"🛡️ PentestAI approval needed: `{tool}` on `{target}` (engagement {engagement_id})",
                "engagement_id": engagement_id,
                "tool": tool,
                "target": target,
                "reasoning": (reasoning or "")[:500],
            }
            with httpx.Client(timeout=5.0) as client:
                client.post(webhook, json=payload)
        except Exception as e:
            logger.warning(f"Webhook notify failed: {e}")

    # 2. Email to leads if SMTP configured (best-effort)
    try:
        smtp_user = os.getenv("SMTP_USER")
        if smtp_user:
            # Defer import to avoid circular
            from app.models.database import SessionLocal
            from app.models.models import User

            db = SessionLocal()
            try:
                leads = db.query(User).filter(User.role == "lead", User.email.isnot(None)).all()
                if leads:
                    from app.core.email import send_otp_email  # reuse email infra, but we need generic
                    # Use raw smtplib for custom subject to avoid OTP template
                    import smtplib
                    from email.mime.text import MIMEText

                    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
                    smtp_port = int(os.getenv("SMTP_PORT", "587"))
                    smtp_pwd = os.getenv("SMTP_PASSWORD", "").replace(" ", "")
                    email_from = os.getenv("EMAIL_FROM", smtp_user)
                    subject = f"[PentestAI] Approval needed: {tool} on {target}"
                    body = f"Engagement {engagement_id} requires Lead approval to run {tool} on {target}.\n\nReasoning: {reasoning[:1000]}\n\nOpen /alerts to approve."
                    for lead in leads[:5]:  # cap to 5 to avoid spam
                        try:
                            msg = MIMEText(body)
                            msg["Subject"] = subject
                            msg["From"] = email_from
                            msg["To"] = lead.email
                            if smtp_port == 465:
                                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=10) as s:
                                    s.login(smtp_user, smtp_pwd)
                                    s.sendmail(email_from, lead.email, msg.as_string())
                            else:
                                with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as s:
                                    s.starttls()
                                    s.login(smtp_user, smtp_pwd)
                                    s.sendmail(email_from, lead.email, msg.as_string())
                        except Exception as e:
                            logger.warning(f"Lead email notify failed for {lead.email}: {e}")
            finally:
                db.close()
    except Exception as e:
        logger.debug(f"Email notify skipped: {e}")
