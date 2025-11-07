from flask import Blueprint, render_template, jsonify, request, url_for
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import db, Cart, CartItem, User, Product
from decimal import Decimal

cart_bp = Blueprint('cart_bp', __name__)


def _resolve_user_id():
    """Return JWT identity coerced to int when possible to match DB types."""
    uid = get_jwt_identity()
    try:
        return int(uid)
    except Exception:
        return uid


def _normalize_image_url(image_url):
    """Return a usable image src. If image_url is already absolute (http) or starts with '/'
    return as-is. Otherwise assume it's a filename under static/images/products and build url_for."""
    if not image_url:
        return None
    try:
        if image_url.startswith('http') or image_url.startswith('/'):
            return image_url
    except Exception:
        pass
    # assume filename stored in DB, serve from static/images/products
    try:
        return url_for('static', filename='images/products/' + image_url)
    except Exception:
        return image_url

@cart_bp.route('/', methods=['GET'])
def cart_page():
    # Serve the HTML cart page for browser GET requests
    return render_template('cart.html')

# 🟢 Get User Cart (JSON)
@cart_bp.route('/api/cart', methods=['GET'])
@jwt_required()
def get_cart():
    user_id = _resolve_user_id()
    cart = Cart.query.filter_by(user_id=user_id, is_active=True).first()
    if not cart:
        return jsonify({"cart": [], "total": 0}), 200

    items = []
    for item in cart.items:
        product = Product.query.get(item.product_id)
        img = _normalize_image_url(product.image_url) if product else None
        items.append({
            "cart_item_id": item.cart_item_id,
            "product_id": item.product_id,
            "name": product.name if product else "Deleted Product",
            "image": img,
            "price": float(item.price_at_time),
            "quantity": item.quantity,
            "subtotal": float(item.price_at_time) * item.quantity
        })

    return jsonify({"cart": items, "total": cart.total()}), 200


# 🟢 Add Item to Cart
@cart_bp.route('/api/cart/add', methods=['POST'])
@jwt_required()
def add_to_cart():
    user_id = _resolve_user_id()
    data = request.get_json()
    product_id = data.get('product_id')
    quantity = int(data.get('quantity', 1))

    product = Product.query.get(product_id)
    if not product:
        return jsonify({"error": "Product not found"}), 404

    if product.stock < quantity:
        return jsonify({"error": "Insufficient stock"}), 400

    # Get or create a cart
    cart = Cart.query.filter_by(user_id=user_id, is_active=True).first()
    if not cart:
        cart = Cart(user_id=user_id)
        db.session.add(cart)
        db.session.commit()

    # Check for existing cart item. Use user_id+product_id lookup because the DB enforces
    # a unique constraint on (user_id, product_id). It's possible an existing item belongs
    # to an older cart record (different cart_id) so we need to merge/move it into the
    # current active cart instead of blindly inserting which would violate the constraint.
    existing_item = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
    try:
        if existing_item:
            # If item exists but belongs to a different cart, move it to the current cart
            if existing_item.cart_id != cart.cart_id:
                existing_item.cart_id = cart.cart_id
            existing_item.quantity = (existing_item.quantity or 0) + quantity
            existing_item.price_at_time = product.price
        else:
            new_item = CartItem(
                cart_id=cart.cart_id,
                user_id=user_id,
                product_id=product_id,
                quantity=quantity,
                price_at_time=product.price
            )
            db.session.add(new_item)

        db.session.commit()
    except Exception as e:
        # Handle potential race/constraint errors gracefully
        db.session.rollback()
        # If duplicate key still occurs, try to update the existing row instead of failing
        try:
            existing = CartItem.query.filter_by(user_id=user_id, product_id=product_id).first()
            if existing:
                existing.quantity = (existing.quantity or 0) + quantity
                existing.price_at_time = product.price
                db.session.commit()
            else:
                # If we still can't resolve, return an error
                return jsonify({'error': 'Failed to add to cart', 'details': str(e)}), 500
        except Exception as e2:
            db.session.rollback()
            return jsonify({'error': 'Failed to add to cart', 'details': str(e2)}), 500
    # return the updated cart payload (same shape as GET /api/cart)
    cart = Cart.query.filter_by(user_id=user_id, is_active=True).first()
    items = []
    for item in (cart.items if cart else []):
        product_obj = Product.query.get(item.product_id)
        img = _normalize_image_url(product_obj.image_url) if product_obj else None
        items.append({
            "cart_item_id": item.cart_item_id,
            "product_id": item.product_id,
            "name": product_obj.name if product_obj else "Deleted Product",
            "image": img,
            "price": float(item.price_at_time),
            "quantity": item.quantity,
            "subtotal": float(item.price_at_time) * item.quantity
        })

    total = cart.total() if cart else 0
    return jsonify({"message": f"{product.name} added to cart.", "cart": items, "total": total}), 201



@cart_bp.route('/api/cart/update', methods=['PUT'])
@jwt_required()
def update_cart_item():
    user_id = _resolve_user_id()
    data = request.get_json()
    cart_item_id = data.get("cart_item_id")
    quantity = int(data.get("quantity", 1))

    item = CartItem.query.get(cart_item_id)
    if not item or item.user_id != user_id:
        return jsonify({"error": "Cart item not found"}), 404

    if quantity <= 0:
        db.session.delete(item)
    else:
        item.quantity = quantity

    db.session.commit()
    return jsonify({"message": "Cart updated successfully"}), 200



@cart_bp.route('/api/cart/remove/<int:cart_item_id>', methods=['DELETE'])
@jwt_required()
def remove_from_cart(cart_item_id):
    user_id = _resolve_user_id()
    item = CartItem.query.get(cart_item_id)

    if not item or item.user_id != user_id:
        return jsonify({"error": "Cart item not found"}), 404

    db.session.delete(item)
    db.session.commit()
    return jsonify({"message": "Item removed from cart"}), 200