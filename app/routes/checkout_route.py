from flask import Blueprint, jsonify, request, render_template
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import db, Cart, User, Order, OrderItem, Product, Payment
import requests, os

checkout_bp = Blueprint('checkout_bp', __name__)

PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY')
PAYSTACK_BASE_URL = os.getenv('PAYSTACK_BASE_URL', 'https://api.paystack.co')

# PAYSTACK_TEST_SECRET_KEY = os.getenv('PAYSTACK_TEST_SECRET_KEY')
# PAYSTACK_BASE_URL = os.getenv('PAYSTACK_BASE_URL', 'https://api.paystack.co')


# 🟢 Checkout Page (HTML)
@checkout_bp.route('/', methods=['GET'])
@jwt_required(optional=True)
def checkout_page():
    # If a JWT is present, try to load the user and pass basic details to the template
    uid = get_jwt_identity()
    user = None
    if uid:
        try:
            user = User.query.get(uid)
        except Exception:
            user = None

    user_ctx = None
    if user:
        user_ctx = {
            'first_name': user.first_name or '',
            'last_name': user.last_name or '',
            'email': user.email or '',
            'country': user.country or ''
        }

    return render_template('checkout.html', user=user_ctx)



@checkout_bp.route('/api/checkout/initiate', methods=['POST'])
@jwt_required()
def initiate_payment():
    user_id = get_jwt_identity()
    # coerce JWT identity to int when possible to avoid bigint vs varchar issues
    try:
        user_id = int(user_id)
    except Exception:
        pass

    user = User.query.get(user_id)
    cart = Cart.query.filter_by(user_id=user_id, is_active=True).first()

    if not cart or not cart.items:
        return jsonify({'error': 'Your cart is empty'}), 400

    total_amount = int(cart.total() * 100)  # Paystack expects amount in pesewas

    headers = {
        "Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "email": user.email,
        "amount": total_amount,
        "currency": "GHS",
        "callback_url": request.host_url + "checkout/verify"
    }

    res = requests.post(f"{PAYSTACK_BASE_URL}/transaction/initialize", json=payload, headers=headers)
    if res.status_code != 200:
        return jsonify({'error': 'Failed to initiate payment'}), res.status_code

    response_data = res.json()
    if not response_data.get('status'):
        return jsonify({'error': response_data.get('message', 'Payment failed')}), 400

    # Create a provisional Order with status 'Pending' so admins can see unpaid orders
    try:
        reference = response_data['data']['reference']
        order = Order(user_id=user_id, total_amount=cart.total(), status='Pending')
        db.session.add(order)
        db.session.flush()  # obtain order.order_id

        # create OrderItem rows from cart items (snapshot prices)
        for ci in cart.items:
            prod = Product.query.get(ci.product_id)
            oi = OrderItem(order_id=order.order_id, product_id=ci.product_id, quantity=ci.quantity, price=ci.price_at_time)
            db.session.add(oi)

        # create a Payment record linked to this order so we can reconcile on callback
        try:
            payment = Payment(order_id=order.order_id, amount=cart.total(), reference=reference, status='pending')
            db.session.add(payment)
            db.session.flush()
            # link back to order (order.payment_id references Payment.payment_id)
            order.payment_id = payment.payment_id

        except Exception:
            # if payment creation fails, continue — order still exists
            db.session.rollback()

        # mark cart inactive to avoid duplicate ordering (optional behavior)
        cart.is_active = False
        db.session.commit()
    except Exception:
        db.session.rollback()
        # non-fatal: continue without creating order

    return jsonify({
        "authorization_url": response_data['data']['authorization_url'],
        "reference": response_data['data']['reference']
    }), 200


# 🟢 Verify Payment after Paystack callback
@checkout_bp.route('/checkout/verify', methods=['GET'])
def verify_payment():
    reference = request.args.get('reference')
    if not reference:
        return jsonify({'error': 'Reference not found'}), 400

    headers = {"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"}
    res = requests.get(f"{PAYSTACK_BASE_URL}/transaction/verify/{reference}", headers=headers)
    data = res.json()

    if data.get('data', {}).get('status') == 'success':
        # mark payment and order as completed if we have a matching Payment record
        try:
            payment = Payment.query.filter_by(reference=reference).first()
            if payment:
                payment.status = 'success'
                # update linked order status
                if payment.order_id:
                    order = Order.query.get(payment.order_id)
                    if order:
                        order.status = 'Completed'
                db.session.commit()
        except Exception:
            db.session.rollback()

        return render_template('payment_success.html', reference=reference)
    else:
        # optionally mark payment as failed
        try:
            payment = Payment.query.filter_by(reference=reference).first()
            if payment:
                payment.status = 'failed'
                db.session.commit()
        except Exception:
            db.session.rollback()
        return render_template('payment_failed.html', reference=reference)
