import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import render_template

# ইমেইল কনফিগারেশন
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "your-email@gmail.com"
SENDER_PASSWORD = "your-app-password"

def send_email(to_email, subject, template_name, **kwargs):
    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        
        # HTML টেমপ্লেট রেন্ডার
        html_content = render_template(f'emails/{template_name}', **kwargs)
        msg.attach(MIMEText(html_content, 'html'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def send_order_confirmation(order):
    user = order.customer
    subject = f"অর্ডার কনফার্মেশন - {order.order_number}"
    return send_email(user.email, subject, 'order_confirmation.html', order=order)

def send_payment_verification(order):
    user = order.customer
    subject = f"পেমেন্ট ভেরিফিকেশন - {order.order_number}"
    return send_email(user.email, subject, 'payment_verification.html', order=order)

def send_2fa_code(user, code):
    subject = "২-ফ্যাক্টর অথেনটিকেশন কোড"
    return send_email(user.email, subject, '2fa_code.html', code=code)