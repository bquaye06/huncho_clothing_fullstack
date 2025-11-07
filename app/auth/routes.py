from flask import Blueprint, request, jsonify, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from app.models import db, User
from datetime import datetime
from app.utils.validators import validate_json
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from app.utils.auth_utils import create_and_send_otp
import os
import requests
from app import oauth
from flask import url_for, current_app
import uuid
from flask import redirect
from flask import session

auth_bp = Blueprint('auth_bp', __name__)

limiter = Limiter(
    key_func=get_remote_address,
)

@auth_bp.route('/register', methods=['GET'])
def register_page():
    # Serve the HTML registration page for browser GET requests
    return render_template('register.html')


@auth_bp.route('/register', methods=['POST'])
@validate_json(['username', 'email', 'password', 'phone_number'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    username = data.get('username').strip()
    email = data.get('email').lower().strip()
    password = data.get('password')
    phone_number = data.get('phone_number').strip()
    first_name = data.get('first_name')
    middle_name = data.get('middle_name')
    last_name = data.get('last_name')
    date_of_birth = data.get('date_of_birth')
    country = data.get('country')

    # Check required fields
    if not all([username, email, password, phone_number]):
        return jsonify({'error': 'Username, email, password, and phone number are required.'}), 400

    # Prevent duplicate accounts
    if User.query.filter((User.email == email) | (User.username == username)).first():
        return jsonify({'error': 'User already exists'}), 400

    try:
        password_hash = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email,
            phone_number=phone_number,
            first_name=first_name,
            middle_name=middle_name,
            last_name=last_name,
            date_of_birth=datetime.strptime(date_of_birth, "%Y-%m-%d") if date_of_birth else None,
            country=country,
            password_hash=password_hash,
            is_verified=False,
            verification_code=None
        )
        db.session.add(new_user)
        # Commit the user to the database first. Failures sending OTP should not mark registration as failed.
        try:
            db.session.commit()
        except Exception as db_err:
            db.session.rollback()
            # If commit fails due to uniqueness/constraint, return a clear message
            return jsonify({'error': 'Registration failed', 'details': str(db_err)}), 500

        # Try sending OTP but don't roll back user creation if it fails.
        try:
            create_and_send_otp(new_user, send_sms=True)
            otp_sent = True
        except Exception as send_err:
            # Log sending error server-side (print for now) and continue
            print('Failed to send OTP:', send_err)
            otp_sent = False

        return jsonify({
            'message': 'User registered successfully. Please verify your email and phone number to activate your account.',
            'user_id': new_user.user_id,
            'otp_sent': otp_sent
        }), 201

    except Exception as e:
        # Any other unexpected exception
        try:
            db.session.rollback()
        except:
            pass
        return jsonify({'error': 'Registration failed', 'details': str(e)}), 500



# --- VERIFY OTP ---


@auth_bp.route('/verify-otp', methods=['POST'])
@validate_json(['otp'])
@limiter.limit("10 per minute")
def verify_otp():
    data = request.get_json()
    otp = data.get('otp')

    # Support verifying by email+otp (old flow) or by otp only (new flow).
    email = data.get('email')
    user = None
    if email:
        user = User.query.filter_by(email=email).first()
    else:
        # find the user having this verification_code
        user = User.query.filter_by(verification_code=otp).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    # verification fields stored on the model as verification_code / verification_expiry
    if user.verification_code != otp:
        return jsonify({'error': 'Invalid OTP'}), 400

    if not user.verification_expiry or datetime.utcnow() > user.verification_expiry:
        return jsonify({'error': 'OTP expired'}), 400

    user.is_verified = True
    user.verification_code = None
    user.verification_expiry = None
    db.session.commit()

    return jsonify({'message': 'Account verified successfully'}), 200


@auth_bp.route('/verify-otp', methods=['GET'])
def verify_otp_page():
    # Serve the HTML verify OTP page for browser GET requests
    return render_template('verify-otp.html')


@auth_bp.route('/verify-login', methods=['POST'])
@limiter.limit("10 per minute")
def verify_login_otp():
    """Verify OTP submitted during login and issue JWT tokens on success."""
    data = request.get_json() or {}
    otp = data.get('otp')
    if not otp:
        return jsonify({'error': 'OTP required'}), 400

    user = User.query.filter_by(verification_code=otp).first()
    if not user:
        return jsonify({'error': 'Invalid OTP'}), 400

    if not user.verification_expiry or datetime.utcnow() > user.verification_expiry:
        return jsonify({'error': 'OTP expired'}), 400

    # Clear verification fields now that OTP matched
    user.verification_code = None
    user.verification_expiry = None
    db.session.commit()

    # Issue JWT tokens
    access_token = create_access_token(identity=str(user.user_id))
    refresh_token = create_refresh_token(identity=str(user.user_id))

    admin_email = os.getenv('ADMIN_EMAIL') or os.environ.get('ADMIN_EMAIL')
    is_admin = False
    try:
        if admin_email and isinstance(admin_email, str):
            is_admin = (user.email.lower() == admin_email.lower()) and bool(user.is_verified)
    except Exception:
        is_admin = False

    payload = {
        'message': 'Login verified',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'is_admin': is_admin
    }

    response = jsonify(payload)
    try:
        if is_admin:
            response.set_cookie('admin_token', access_token, samesite='Lax')
    except Exception:
        pass

    return response, 200



@auth_bp.route('/login', methods=['GET'])
def login_page():
    # Serve the HTML login page for browser GET requests
    return render_template('login.html')

@auth_bp.route('/login', methods=['POST'])
@validate_json(['email', 'password'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    email = data.get('email').lower().strip()
    password = data.get('password')
    
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401

    if not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid password'}), 401
    
    # For additional security require a one-time OTP on every login attempt.
    # Generate and send an OTP to the user's email/phone and require they verify it
    # before issuing JWT tokens. This prevents automated/bot logins.
    try:
        create_and_send_otp(user, send_sms=True)
        return jsonify({'message': 'OTP sent to registered email/phone', 'otp_required': True}), 200
    except Exception as e:
        # If sending OTP fails, return error so client can surface message
        return jsonify({'error': 'Failed to send OTP for login', 'details': str(e)}), 500


# --- GOOGLE OAUTH ---
@auth_bp.route('/google/login')
def google_login():
    # Start Google OAuth2 login
    # Prefer an explicit redirect URI from config, otherwise use our callback route
    redirect_uri = url_for('auth_bp.google_callback', _external=True)
    try:
        override = current_app.config.get('GOOGLE_OAUTH_REDIRECT_URI')
        if override:
            redirect_uri = override
    except Exception:
        pass
    # Set a short-lived session marker so we can detect whether the session persists across the redirect.
    try:
        marker = str(uuid.uuid4())
        session['oauth_marker'] = marker
        # Make session permanent for a short while to help keep cookies alive during dev redirects
        session.permanent = True
    except Exception:
        marker = None

    # Debug diagnostics: log cookie/session state before redirect if enabled
    try:
        if current_app.config.get('OAUTH_DEBUG'):
            current_app.logger.debug('Starting Google OAuth login')
            current_app.logger.debug('Callback redirect_uri=%s', redirect_uri)
            current_app.logger.debug('Request cookie keys: %s', list(request.cookies.keys()))
            try:
                current_app.logger.debug('Session keys pre-redirect: %s', list(session.keys()))
                current_app.logger.debug('oauth_marker set to: %s', session.get('oauth_marker'))
            except Exception:
                current_app.logger.debug('Could not read session keys')
    except Exception:
        pass
    return oauth.google.authorize_redirect(redirect_uri)


@auth_bp.route('/google/callback')
def google_callback():
    # Handle Google's callback, fetch user info and issue JWT tokens
    token = None
    userinfo = None
    # Try the normal Authlib flow first
    try:
        token = oauth.google.authorize_access_token()
    except Exception as e:
        msg = str(e)
        # Diagnostic logging when enabled
        if current_app.config.get('OAUTH_DEBUG'):
            try:
                current_app.logger.debug('Authlib authorize_access_token failed: %s', msg)
                current_app.logger.debug('Callback args: %s', dict(request.args))
                current_app.logger.debug('Cookie keys: %s', list(request.cookies.keys()))
                from flask import session
                current_app.logger.debug('Session keys: %s', list(session.keys()))
            except Exception:
                current_app.logger.debug('Could not dump debug info for OAuth callback')

        # If state/CSRF mismatch and fallback allowed, try manual code exchange
        if ('mismatching_state' in msg or 'State not equal' in msg or 'CSRF' in msg) and current_app.config.get('OAUTH_ALLOW_FALLBACK'):
            try:
                code = request.args.get('code')
                if not code:
                    raise ValueError('No authorization code present')
                redirect_uri = url_for('auth_bp.google_callback', _external=True)
                override = current_app.config.get('GOOGLE_OAUTH_REDIRECT_URI')
                if override:
                    redirect_uri = override

                token_url = 'https://oauth2.googleapis.com/token'
                payload = {
                    'code': code,
                    'client_id': current_app.config.get('GOOGLE_CLIENT_ID'),
                    'client_secret': current_app.config.get('GOOGLE_CLIENT_SECRET'),
                    'redirect_uri': redirect_uri,
                    'grant_type': 'authorization_code'
                }
                r = requests.post(token_url, data=payload, timeout=10)
                r.raise_for_status()
                token = r.json()
                if current_app.config.get('OAUTH_DEBUG'):
                    current_app.logger.debug('Manual token exchange result keys: %s', list(token.keys()))
            except Exception as ex:
                return jsonify({'error': 'OAuth authorization failed', 'details': f'{msg}; fallback failed: {ex}'}), 400
        else:
            # Not allowed to fallback — return diagnostic info when in debug mode
            diag = {'error': 'OAuth authorization failed', 'details': msg}
            if current_app.config.get('OAUTH_DEBUG'):
                diag['query_args'] = dict(request.args)
                diag['cookie_keys'] = list(request.cookies.keys())
            return jsonify(diag), 400

    # At this point we should have an access token in `token`
    try:
        access_token = None
        if isinstance(token, dict):
            access_token = token.get('access_token')
        else:
            # Authlib may return a Token object supporting mapping interface
            try:
                access_token = token['access_token']
            except Exception:
                access_token = None

        if not access_token:
            return jsonify({'error': 'Failed to obtain access token from provider'}), 400

        # Use the OpenID Connect userinfo endpoint for robust results
        userinfo_url = 'https://openidconnect.googleapis.com/v1/userinfo'
        resp = requests.get(userinfo_url, headers={'Authorization': f'Bearer {access_token}'}, timeout=10)
        resp.raise_for_status()
        userinfo = resp.json()
    except Exception as e:
        return jsonify({'error': 'Failed to fetch user info from Google', 'details': str(e)}), 400

    email = userinfo.get('email')
    if not email:
        return jsonify({'error': 'Google account did not provide an email address'}), 400

    # Find or create user
    user = User.query.filter_by(email=email.lower()).first()
    created = False
    if not user:
        # Auto-create user for Google sign-ins
        username = email.split('@')[0]
        user = User(
            username=username,
            email=email.lower(),
            first_name=userinfo.get('given_name'),
            last_name=userinfo.get('family_name'),
            is_verified=True,
            verification_code=None
        )
        try:
            db.session.add(user)
            db.session.commit()
            created = True
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': 'Failed to create user', 'details': str(e)}), 500
    else:
        # Ensure user is marked verified
        if not user.is_verified:
            user.is_verified = True
            db.session.commit()

    # Issue JWT tokens
    access_token = create_access_token(identity=str(user.user_id))
    refresh_token = create_refresh_token(identity=str(user.user_id))

    admin_email = os.getenv('ADMIN_EMAIL') or os.environ.get('ADMIN_EMAIL')
    is_admin = False
    try:
        if admin_email and isinstance(admin_email, str):
            is_admin = (user.email.lower() == admin_email.lower()) and bool(user.is_verified)
    except Exception:
        is_admin = False

    # Render a short page that stores tokens in localStorage and redirects the user
    return render_template('oauth_callback.html', access_token=access_token, refresh_token=refresh_token, is_admin=is_admin)


# Compatibility redirect: some Google setups register the redirect as /auth/callback/google
# Accept that form and forward to our canonical callback while preserving query params.
@auth_bp.route('/callback/google')
def google_callback_alias():
    # Rebuild destination URL for the canonical callback
    qs = request.query_string.decode('utf-8')
    dest = url_for('auth_bp.google_callback')
    if qs:
        dest = f"{dest}?{qs}"
    return redirect(dest, code=302)
    
# --- RESEND OTP ---
@auth_bp.route('/resend-otp', methods=['POST'])
def resend_otp():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    create_and_send_otp(user, send_sms=True)
    return jsonify({'message': 'New OTP sent to email and SMS.'}), 200


    
# --- PASSWORD RESET REQUEST ---
@auth_bp.route('/password-reset-request', methods=['POST'])
@validate_json(['email'])
@limiter.limit("5 per minute")
def password_reset_request():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Email not found'}), 404

    create_and_send_otp(user, send_sms=True)
    return jsonify({'message': 'Password reset OTP sent to email and SMS.'}), 200




@auth_bp.route('/password-reset-request', methods=['GET'])
def password_reset_request_page():
    # Serve the HTML password reset request page for browser GET requests
    return render_template('password_reset_request.html')


# --- PASSWORD RESET ---
@auth_bp.route('/password-reset', methods=['POST'])
@validate_json(['email', 'otp', 'new_password'])
@limiter.limit("5 per minute")
def password_reset():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'User not found'}), 404

    # Use verification_code / verification_expiry fields
    if user.verification_code != otp or not user.verification_expiry or datetime.utcnow() > user.verification_expiry:
        return jsonify({'error': 'Invalid or expired OTP'}), 400

    user.password_hash = generate_password_hash(new_password)
    user.verification_code = None
    user.verification_expiry = None
    db.session.commit()
    return jsonify({'message': 'Password reset successful'}), 200

@auth_bp.route('/password-reset', methods=['GET'])
def password_reset_page():
    # Serve the HTML password reset page for browser GET requests
    return render_template('password_reset.html')
