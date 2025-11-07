from flask import Blueprint, render_template, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import db, User
from app.models import Order, OrderItem, Product
from werkzeug.security import generate_password_hash

user_bp = Blueprint('user_bp', __name__)


@user_bp.route('/', methods=['GET'])
def account_page():
    # Serve the HTML account page for browser GET requests
    return render_template('account.html')

@user_bp.route('/user/profile', methods=['GET'])
@jwt_required()
def get_user_profile():   
    user_id = get_jwt_identity()
    try:
        user_id = int(user_id)
    except Exception:
        pass
    user = User.query.get(user_id)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'username': user.username,
        'email': user.email,
        'first_name': user.first_name,
        'middle_name': user.middle_name,
        'last_name': user.last_name,
        'phone_number': user.phone_number,
        'date_of_birth': user.date_of_birth.strftime("%Y-%m-%d") if user.date_of_birth else None,
        'country': user.country,
        'is_verified': user.is_verified
    }), 200

@user_bp.route('/user/update', methods=['PUT'])
@jwt_required()
def update_user_profile():
    """
    Updates the user's profile information.
    Accepts JSON data and updates any provided fields.
    """
    user_id = get_jwt_identity()
    try:
        user_id = int(user_id)
    except Exception:
        pass
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json() or {}
    try:
        # Update basic fields if provided
        user.username = data.get('username', user.username)
        user.phone_number = data.get('phone_number', user.phone_number)
        user.first_name = data.get('first_name', user.first_name)
        user.middle_name = data.get('middle_name', user.middle_name)
        user.last_name = data.get('last_name', user.last_name)
        user.country = data.get('country', user.country)

        # Update password (if included)
        if data.get('new_password'):
            user.password_hash = generate_password_hash(data['new_password'])

        db.session.commit()
        return jsonify({'message': 'Profile updated successfully'}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Update failed', 'details': str(e)}), 500


@user_bp.route('/orders', methods=['GET'])
@jwt_required()
def get_user_orders():
    """Return the authenticated user's orders as JSON."""
    user_id = get_jwt_identity()
    try:
        user_id = int(user_id)
    except Exception:
        pass

    orders = Order.query.filter_by(user_id=user_id).order_by(Order.created_at.desc()).all()
    results = []
    for o in orders:
        od = o.to_dict()
        # enrich items with product metadata if available
        enriched_items = []
        for it in o.items:
            prod = None
            try:
                prod = Product.query.get(it.product_id)
            except Exception:
                prod = None
            enriched_items.append({
                'item_id': it.order_items_id,
                'product_id': it.product_id,
                'product_name': prod.name if prod else None,
                'image': (prod.image_url if prod else None) or '/static/images/dress.webp',
                'quantity': it.quantity,
                'price': float(it.price)
            })
        od['items'] = enriched_items
        results.append(od)

    return jsonify({'orders': results}), 200