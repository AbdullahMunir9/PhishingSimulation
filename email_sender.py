# email_sender.py
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER')     # e.g. your Gmail address
SMTP_PASS = os.environ.get('SMTP_PASS')     # app password or SMTP pass
FROM_NAME = os.environ.get('FROM_NAME', 'Security Team')
FROM_EMAIL = os.environ.get('FROM_EMAIL', SMTP_USER)

def send_email(to_email, subject, body_html):
    if not SMTP_USER or not SMTP_PASS:
        raise RuntimeError("SMTP credentials are not configured in environment variables")

    msg = MIMEMultipart('alternative')
    msg['From'] = f"{FROM_NAME} <{FROM_EMAIL}>"
    msg['To'] = to_email
    msg['Subject'] = subject

    # attach HTML body
    msg.attach(MIMEText(body_html, 'html'))

    # connect and send
    try:
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20)
        server.ehlo()
        if SMTP_PORT == 587:
            server.starttls()
            server.ehlo()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(FROM_EMAIL, [to_email], msg.as_string())
        server.quit()
        print(f"Email sent to {to_email}")
    except Exception as e:
        # bubble up exceptions so the caller can handle/log
        print(f"Failed to send email to {to_email}: {e}")
        raise
