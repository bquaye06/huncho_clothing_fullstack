from functools import wraps 
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request, decode_token
from app.models import User
import os

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user_id = None
        try:
            # try standard Authorization header first
            verify_jwt_in_request()
            user_id = get_jwt_identity()
        except Exception:
            # If no Authorization header, attempt to read token from admin_token cookie
            token = None
            try:
                token = request.cookies.get('admin_token')
            except Exception:
                token = None
            if token:
                try:
                    decoded = decode_token(token)
                    # Flask-JWT-Extended stores identity in 'sub'
                    user_id = decoded.get('sub') or decoded.get('identity')
                except Exception:
                    user_id = None
        user = User.query.get(user_id)

        # Allow access if user.is_admin is True OR the user's email matches the configured ADMIN_EMAIL
        admin_email = os.getenv('ADMIN_EMAIL') or os.environ.get('ADMIN_EMAIL')
        is_admin_email = False
        try:
            if admin_email and user and hasattr(user, 'email'):
                is_admin_email = (user.email or '').lower() == admin_email.lower()
        except Exception:
            is_admin_email = False

        if not user or (not user.is_admin and not is_admin_email):
            return jsonify({'error': 'Admins only!'}), 403

        return fn(*args, **kwargs)
    return wrapper