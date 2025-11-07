import random, os, string, datetime, requests
from flask_mail import Message
from app import mail, db
from app.models import User

def generate_otp(length=6):
    """Generate a numeric OTP of given length."""
    return ''.join(random.choices(string.digits, k=length))

def send_by_email(user, otp):
    """Send OTP to user via email. Returns True on success, False on failure."""
    if not user or not user.email:
        print('send_by_email: no user or email provided')
        return False

    recipient = user.email
    name = user.first_name or user.username or recipient
    subject = "OTP verification code for hunchØ.clothing"
    body = (
        f"Good day {name}, \n\n"
        f"Your verification code is: {otp}\n\n"
        "Thanks for signing up with hunchØ.clothing, happy shopping"
    )

    msg = Message(subject=subject, recipients=[recipient], body=body)
    try:
        mail.send(msg)
        return True
    except Exception as e:
        # Log and return False so caller can decide how to handle
        print(f"Failed to send email to {recipient}: {e}")
        return False

def send_by_sms(user, otp):
    """Send OTP to user via SMS using a third-party Service."""
    ARKESEL_API_KEY = os.getenv('ARKESEL_API_KEY')
    ARKESEL_SENDER_ID = os.getenv('ARKESEL_SENDER_ID', 'HClothing')
    message = f"Your hunchØ.clothing verification code is: {otp}. This code expires in 10 minutes."
    
    url = "https://sms.arkesel.com/api/v2/sms/send"
    headers = {
        "api-key": ARKESEL_API_KEY,
        "Authorization": f"Bearer {ARKESEL_API_KEY}",
        "Content-Type": "application/json",
    }
    
    recipient_number = None
    try:
        recipient_number = user.phone_number
    except Exception:
        recipient_number = None

    payload = {
        "sender": ARKESEL_SENDER_ID,
        "message": message,
        "recipients": [recipient_number],
    }
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        # Network error / timeout / DNS issue
        print(f"Network error while sending SMS to {User.phone_number}: {e}")
        return False

    # Detailed response logging to help debugging
    status = response.status_code
    body = None
    try:
        body = response.json()
    except ValueError:
        body = response.text

    if 200 <= status < 300:
        print(f"SMS sent successfully to {recipient_number}: status={status}, body={body}")
        return True

    # Non-successful response
    print(f"Error sending SMS to {recipient_number}: status={status}, body={body}")
    return False


def create_and_send_otp(user, send_sms=False):
    """Generate OTP, save to DB, send via email and optional SMS."""
    otp = generate_otp()
    expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
    # Use the fields defined on the User model: verification_code and verification_expiry
    user.verification_code = otp
    user.verification_expiry = expiry
    db.session.commit()

    # send email (raise on failure so caller can mark otp_sent False)
    email_ok = send_by_email(user, otp)
    if not email_ok:
        # Raise so caller (routes) can catch and handle otp_sent=False
        raise Exception('Failed to send OTP email')

    if send_sms and user.phone_number:
        sms_ok = send_by_sms(user, otp)
        if not sms_ok:
            # don't fail the whole registration for SMS failure; just log
            print('Failed to send OTP SMS')
