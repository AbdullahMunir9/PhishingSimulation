# email_sender.py
import os
import smtplib
import socket
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Email service configuration
EMAIL_SERVICE = os.environ.get('EMAIL_SERVICE', 'smtp').lower()  # 'smtp' or 'sendgrid'

# SMTP Configuration
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER')     # e.g. your Gmail address
SMTP_PASS = os.environ.get('SMTP_PASS')     # app password or SMTP pass

# SendGrid Configuration
SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
SENDGRID_FROM_EMAIL = os.environ.get('SENDGRID_FROM_EMAIL')

# Common configuration
FROM_NAME = os.environ.get('FROM_NAME', 'Security Team')
FROM_EMAIL = os.environ.get('FROM_EMAIL', SMTP_USER or SENDGRID_FROM_EMAIL)

def send_email_via_sendgrid(to_email, subject, body_html):
    """Send email using SendGrid API (recommended for cloud deployments)"""
    if not SENDGRID_API_KEY:
        raise RuntimeError(
            "SendGrid API key is not configured. "
            "Please set SENDGRID_API_KEY environment variable. "
            "Get your API key from https://app.sendgrid.com/settings/api_keys"
        )
    
    if not SENDGRID_FROM_EMAIL:
        raise RuntimeError(
            "SendGrid from email is not configured. "
            "Please set SENDGRID_FROM_EMAIL environment variable."
        )
    
    url = "https://api.sendgrid.com/v3/mail/send"
    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "personalizations": [{
            "to": [{"email": to_email}],
            "subject": subject
        }],
        "from": {
            "email": SENDGRID_FROM_EMAIL,
            "name": FROM_NAME
        },
        "content": [{
            "type": "text/html",
            "value": body_html
        }]
    }
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        if response.status_code == 202:
            print(f"Email sent successfully via SendGrid to {to_email}")
            return
        else:
            error_msg = f"SendGrid API error: {response.status_code} - {response.text}"
            print(f"SendGrid error: {error_msg}")
            raise RuntimeError(error_msg)
    except requests.exceptions.RequestException as e:
        error_msg = f"Failed to send email via SendGrid: {str(e)}"
        print(f"SendGrid request error: {error_msg}")
        raise ConnectionError(error_msg) from e


def send_email_via_smtp(to_email, subject, body_html):
    """Send email using SMTP (may not work in all cloud environments)"""
    if not SMTP_USER or not SMTP_PASS:
        raise RuntimeError(
            "SMTP credentials are not configured. "
            "Please set SMTP_USER and SMTP_PASS environment variables. "
            "For Railway deployment, ensure these are set in your Railway project environment variables."
        )

    msg = MIMEMultipart('alternative')
    msg['From'] = f"{FROM_NAME} <{FROM_EMAIL}>"
    msg['To'] = to_email
    msg['Subject'] = subject

    # attach HTML body
    msg.attach(MIMEText(body_html, 'html'))

    # connect and send
    try:
        # Test network connectivity first
        try:
            socket.create_connection((SMTP_HOST, SMTP_PORT), timeout=10)
        except (socket.gaierror, socket.timeout, OSError) as e:
            error_msg = (
                f"Cannot reach SMTP server {SMTP_HOST}:{SMTP_PORT}. "
                f"This is common in cloud deployments where outbound SMTP is blocked. "
                f"Error: {str(e)}. "
                f"Consider using SendGrid by setting EMAIL_SERVICE=sendgrid and SENDGRID_API_KEY."
            )
            print(f"Network error: {error_msg}")
            raise ConnectionError(error_msg) from e
        
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=30)
        server.set_debuglevel(0)  # Set to 1 for debug output
        
        try:
            server.ehlo()
            if SMTP_PORT == 587:
                server.starttls()
                server.ehlo()
            
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(FROM_EMAIL, [to_email], msg.as_string())
            print(f"Email sent successfully to {to_email}")
        except smtplib.SMTPAuthenticationError as e:
            error_msg = (
                f"SMTP authentication failed. "
                f"Please check your SMTP_USER and SMTP_PASS credentials. "
                f"For Gmail, ensure you're using an App Password, not your regular password."
            )
            print(f"Authentication error: {error_msg}")
            raise RuntimeError(error_msg) from e
        except smtplib.SMTPException as e:
            error_msg = f"SMTP error occurred: {str(e)}"
            print(f"SMTP error: {error_msg}")
            raise RuntimeError(error_msg) from e
        finally:
            try:
                server.quit()
            except:
                pass
                
    except ConnectionError:
        # Re-raise connection errors with our custom message
        raise
    except socket.error as e:
        error_msg = (
            f"Network error connecting to SMTP server: {str(e)}. "
            f"Railway and other cloud platforms often block outbound SMTP connections. "
            f"Please use SendGrid by setting EMAIL_SERVICE=sendgrid and SENDGRID_API_KEY, "
            f"or configure SMTP credentials if using a service that allows it."
        )
        print(f"Socket error: {error_msg}")
        raise ConnectionError(error_msg) from e
    except Exception as e:
        error_msg = f"Failed to send email: {str(e)}"
        print(f"Unexpected error: {error_msg}")
        raise RuntimeError(error_msg) from e


def send_email(to_email, subject, body_html):
    """Main email sending function that routes to the appropriate service"""
    # If EMAIL_SERVICE is explicitly set to 'sendgrid', use SendGrid
    if EMAIL_SERVICE == 'sendgrid':
        return send_email_via_sendgrid(to_email, subject, body_html)
    
    # If SendGrid credentials are available and EMAIL_SERVICE is not explicitly 'smtp', prefer SendGrid
    if SENDGRID_API_KEY and SENDGRID_FROM_EMAIL and EMAIL_SERVICE != 'smtp':
        try:
            return send_email_via_sendgrid(to_email, subject, body_html)
        except Exception as e:
            # If SendGrid fails and SMTP is available, fall back to SMTP
            if SMTP_USER and SMTP_PASS:
                print(f"SendGrid failed, falling back to SMTP: {e}")
                return send_email_via_smtp(to_email, subject, body_html)
            else:
                raise
    
    # Default to SMTP
    return send_email_via_smtp(to_email, subject, body_html)
