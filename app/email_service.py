"""
StorageOS Email Service
Robust SMTP email delivery with secure environment configuration and safe dev mode fallback.
"""

import os
import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any

logger = logging.getLogger("storageos.email")


def is_smtp_configured() -> bool:
    """Check whether SMTP credentials and host are configured."""
    return bool(os.environ.get("SMTP_HOST", "").strip())


def get_smtp_config() -> Dict[str, Any]:
    """Retrieve SMTP settings from environment variables."""
    host = os.environ.get("SMTP_HOST", "").strip()
    port_str = os.environ.get("SMTP_PORT", "").strip()
    username = os.environ.get("SMTP_USERNAME", "").strip()
    password = os.environ.get("SMTP_PASSWORD", "").strip()
    from_addr = os.environ.get("SMTP_FROM", "").strip() or "StorageOS <noreply@storageos.local>"
    use_tls = os.environ.get("SMTP_USE_TLS", "True").lower() in ("true", "1", "yes")
    use_ssl = os.environ.get("SMTP_USE_SSL", "False").lower() in ("true", "1", "yes")

    port = 587
    if port_str:
        try:
            port = int(port_str)
        except ValueError:
            port = 465 if use_ssl else 587
    elif use_ssl:
        port = 465

    return {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "from_addr": from_addr,
        "use_tls": use_tls,
        "use_ssl": use_ssl,
        "configured": bool(host),
    }


def send_password_reset_email(to_email: str, reset_url: str, username: str = None) -> Dict[str, Any]:
    """
    Send a password reset email using SMTP if configured.
    If SMTP is not configured, provides a safe development fallback
    without exposing passwords or compromising security.
    """
    if not to_email or "@" not in to_email:
        return {"success": False, "dev_mode": False, "error": "Invalid recipient email."}

    user_display = username or "StorageOS User"
    config = get_smtp_config()

    if not config["configured"]:
        # Safe development mechanism: log reset URL to server output for developer/testing use
        logger.info("[StorageOS DEV MODE] Password reset requested for: %s | URL: %s", to_email, reset_url)
        return {
            "success": True,
            "dev_mode": True,
            "reset_url": reset_url,
            "message": "Development mode: SMTP is not configured. Reset link logged to server console.",
        }

    # Production SMTP delivery
    try:
        subject = "StorageOS — Password Reset Request"
        text_body = f"""Hello {user_display},

We received a request to reset the password for your StorageOS account ({to_email}).

To reset your password, open the link below in your browser:
{reset_url}

This password reset link is single-use and will expire in 30 minutes.

If you did not request a password reset, please ignore this email. Your account remains secure and no changes have been made.

Sincerely,
The StorageOS Security Team
"""

        html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{subject}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f7f7f8; color: #1c1d21; margin: 0; padding: 24px; }}
    .container {{ max-width: 520px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e4e9; border-radius: 8px; padding: 32px; }}
    .logo {{ font-size: 20px; font-weight: 700; color: #1c1d21; margin-bottom: 24px; letter-spacing: -0.5px; }}
    .logo span {{ color: #e53935; }}
    .btn {{ display: inline-block; background-color: #1c1d21; color: #ffffff !important; text-decoration: none; padding: 12px 24px; border-radius: 6px; font-weight: 600; margin: 20px 0; }}
    .muted {{ color: #6e717c; font-size: 13px; line-height: 1.5; }}
    .footer {{ margin-top: 32px; border-top: 1px solid #e2e4e9; padding-top: 16px; font-size: 12px; color: #8e929f; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">Storage<span>OS</span></div>
    <h2 style="margin-top: 0; font-size: 18px; color: #1c1d21;">Password Reset Request</h2>
    <p>Hello {user_display},</p>
    <p>We received a request to reset the password associated with your account (<strong>{to_email}</strong>).</p>
    <p><a href="{reset_url}" class="btn" target="_blank">Reset Your Password</a></p>
    <p class="muted">Or copy and paste this link into your browser:<br><a href="{reset_url}" style="color: #e53935; word-break: break-all;">{reset_url}</a></p>
    <p class="muted">This link is single-use and will expire in <strong>30 minutes</strong>.</p>
    <p class="muted">If you did not request this, please disregard this email. Your account is completely secure.</p>
    <div class="footer">
      StorageOS Secure Cloud Storage &bull; Automated Security Notification
    </div>
  </div>
</body>
</html>
"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = config["from_addr"]
        msg["To"] = to_email

        part1 = MIMEText(text_body, "plain", "utf-8")
        part2 = MIMEText(html_body, "html", "utf-8")
        msg.attach(part1)
        msg.attach(part2)

        if config["use_ssl"]:
            with smtplib.SMTP_SSL(config["host"], config["port"], timeout=15) as server:
                if config["username"] and config["password"]:
                    server.login(config["username"], config["password"])
                server.send_message(msg)
        else:
            with smtplib.SMTP(config["host"], config["port"], timeout=15) as server:
                if config["use_tls"]:
                    server.starttls()
                if config["username"] and config["password"]:
                    server.login(config["username"], config["password"])
                server.send_message(msg)

        logger.info("Successfully sent password reset email to %s", to_email)
        return {"success": True, "dev_mode": False, "message": "Password reset email sent."}

    except Exception as e:
        logger.error("Failed to send password reset email via SMTP: %s", str(e))
        return {
            "success": False,
            "dev_mode": False,
            "error": f"Failed to send email via SMTP server: {str(e)}",
        }
