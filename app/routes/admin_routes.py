from flask import Blueprint, render_template, request, jsonify, url_for
from flask_jwt_extended import create_access_token
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from app.utils.admin_decorator import admin_required
from app.models import db, User, Order, OrderItem, Product, Setting
from app.utils.admin_decorator import admin_required
from datetime import datetime, timedelta
from sqlalchemy import func, desc
import os

admin_bp = Blueprint('admin_bp', __name__, url_prefix='/admin')
# Resolve upload folder relative to the app package so saves work regardless of cwd
APP_DIR = os.path.dirname(os.path.dirname(__file__))  # path to app/
UPLOAD_FOLDER = os.path.join(APP_DIR, 'static', 'uploads', 'products')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@admin_bp.route('/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin/login.html')

    data = request.get_json() if request.is_json else request.form
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()
    if not user or not user.is_admin:
        return jsonify({'error': 'Access denied'}), 403

    if not check_password_hash(user.password_hash, password):
        return jsonify({'error': 'Invalid password'}), 401

    token = create_access_token(identity=user.user_id)
    return jsonify({'message': 'Admin login successful', 'access_token': token}), 200



@admin_bp.route('/dashboard', methods=['GET'])
@admin_required
def dashboard():
    # Compute basic metrics
    total_users = db.session.query(func.count(User.user_id)).scalar() or 0
    total_orders = db.session.query(func.count(Order.order_id)).scalar() or 0
    # Only include revenue from completed orders (payments succeeded)
    total_revenue = float(db.session.query(func.coalesce(func.sum(Order.total_amount), 0)).filter(Order.status == 'Completed').scalar() or 0.0)

    # Recent orders (latest 8)
    recent_q = Order.query.order_by(Order.created_at.desc()).limit(8).all()
    recent_orders = []
    for o in recent_q:
        recent_orders.append({
            'order_id': o.order_id,
            'user_id': o.user_id,
            'total_amount': float(o.total_amount) if o.total_amount is not None else 0.0,
            'status': o.status,
            'created_at': o.created_at.isoformat() if o.created_at else None
        })

    # Revenue by day (last 7 days)
    today = datetime.utcnow().date()
    days = []
    revenue_by_day = []
    for i in range(6, -1, -1):
        d = today - timedelta(days=i)
        start = datetime(d.year, d.month, d.day)
        end = start + timedelta(days=1)
        # Sum only completed orders for the given day
        amt = float(db.session.query(func.coalesce(func.sum(Order.total_amount), 0)).filter(
            Order.status == 'Completed', Order.created_at >= start, Order.created_at < end
        ).scalar() or 0.0)
        days.append(d.strftime('%Y-%m-%d'))
        revenue_by_day.append(amt)

    # Top products by quantity sold (last 30 days)
    since = datetime.utcnow() - timedelta(days=30)
    top_products_q = db.session.query(
        OrderItem.product_id,
        func.coalesce(func.sum(OrderItem.quantity), 0).label('qty')
    ).join(Order, Order.order_id == OrderItem.order_id).filter(Order.created_at >= since).group_by(OrderItem.product_id).order_by(desc('qty')).limit(6).all()
    top_products = []
    for pid, qty in top_products_q:
        prod = Product.query.get(pid)
        top_products.append({
            'product_id': pid,
            'name': prod.name if prod else f'#{pid}',
            'quantity_sold': int(qty or 0),
            'image_url': prod.image_url if prod else '/static/images/dress.webp'
        })

    stats = {
        'total_users': total_users,
        'total_orders': total_orders,
        'total_revenue': total_revenue,
        'recent_orders': recent_orders,
        'revenue_by_day_labels': days,
        'revenue_by_day_values': revenue_by_day,
        'top_products': top_products,
    }

    return render_template('admin/dashboard.html', stats=stats)



@admin_bp.route('/customers', methods=['GET'])
@admin_required
def admin_customers_page():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/customers.html', users=users)


@admin_bp.route('/api/customers', methods=['GET'])
@admin_required
def get_all_customers():
    users = User.query.order_by(User.created_at.desc()).all()
    return jsonify([
        {
            'user_id': u.user_id,
            'username': u.username,
            'email': u.email,
            'phone_number': u.phone_number,
            'country': u.country,
            'is_verified': u.is_verified,
            'is_admin': u.is_admin
        } for u in users
    ]), 200


@admin_bp.route('/api/customers/<int:user_id>', methods=['GET'])
@admin_required
def get_customer(user_id):
    """Return detailed information about a single user, excluding sensitive fields like password_hash."""
    u = User.query.get_or_404(user_id)
    return jsonify({
        'user_id': u.user_id,
        'username': u.username,
        'first_name': u.first_name,
        'middle_name': u.middle_name,
        'last_name': u.last_name,
        'date_of_birth': u.date_of_birth.isoformat() if u.date_of_birth else None,
        'email': u.email,
        'phone_number': u.phone_number,
        'country': u.country,
        'is_verified': u.is_verified,
        'is_admin': u.is_admin,
        'role': u.role,
        'created_at': u.created_at.isoformat() if u.created_at else None,
        'updated_at': u.updated_at.isoformat() if u.updated_at else None,
    }), 200

@admin_bp.route('/api/customers/<int:user_id>', methods=['PUT'])
@admin_required
def update_customer(user_id):
    data = request.get_json()
    user = User.query.get_or_404(user_id)

    user.username = data.get('username', user.username)
    user.email = data.get('email', user.email)
    user.phone_number = data.get('phone_number', user.phone_number)
    user.country = data.get('country', user.country)
    user.is_verified = data.get('is_verified', user.is_verified)
    user.is_admin = data.get('is_admin', user.is_admin)

    if 'password' in data and data['password']:
        user.password_hash = generate_password_hash(data['password'])

    db.session.commit()
    return jsonify({'message': 'User updated successfully'}), 200



@admin_bp.route('/api/customers/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_customer(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'User deleted successfully'}), 200


@admin_bp.route('/settings', methods=['GET'])
@admin_required
def admin_settings_page():
    settings = {s.key: s.value for s in Setting.query.all()}
    return render_template('admin/settings.html', settings=settings)


@admin_bp.route('/api/settings', methods=['POST'])
@admin_required
def save_settings():
    """Persist settings sent from the admin UI. Accepts a JSON object of key->value pairs.
    Existing keys are updated; new keys are created.
    """
    data = request.get_json() or {}
    if not isinstance(data, dict):
        return jsonify({'message': 'Invalid payload'}), 400

    # Normalize values to strings so Setting.value remains text
    for k, v in data.items():
        try:
            val = v
            # convert booleans to 'true'/'false' for compatibility with templates
            if isinstance(v, bool):
                val = 'true' if v else 'false'
            else:
                # cast None to empty string
                val = '' if v is None else str(v)

            s = Setting.query.filter_by(key=k).first()
            if s:
                s.value = val
            else:
                s = Setting(key=k, value=val)
                db.session.add(s)
        except Exception:
            # skip problematic keys but continue saving others
            continue

    db.session.commit()
    return jsonify({'message': 'Settings saved successfully'}), 200

@admin_bp.route('/products', methods=['GET'])
@admin_required
def admin_products_page():
    products = Product.query.order_by(Product.created_at.desc()).all()
    return render_template('admin/products.html', products=products)


@admin_bp.route('/api/products', methods=['POST'])
@admin_required
def create_product():
    # Accept multipart/form-data
    form = request.form
    name = form.get('name')
    description = form.get('description')
    price = form.get('price') or 0
    stock = form.get('stock') or 0
    brand = form.get('brand')
    size = form.get('size')
    color = form.get('color')

    image_url = None
    file = request.files.get('image')
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        # add timestamp to avoid collisions
        name_part, ext = os.path.splitext(filename)
        filename = f"{name_part}_{int(datetime.utcnow().timestamp())}{ext}"
        dest = os.path.join(UPLOAD_FOLDER, filename)
        file.save(dest)
        # Build a proper static URL for the uploaded file
        try:
            image_url = url_for('static', filename=f'uploads/products/{filename}')
        except Exception:
            # fallback to a simple path
            image_url = f"/static/uploads/products/{filename}"

    p = Product(
        name=name,
        description=description,
        price=float(price) if price is not None else 0.0,
        stock=int(stock) if stock is not None and stock != '' else 0,
        brand=brand,
        size=size,
        color=color,
        image_url=image_url
    )
    db.session.add(p)
    db.session.commit()
    return jsonify({'message': 'Product created', 'product_id': p.product_id}), 201


@admin_bp.route('/api/products/<int:product_id>', methods=['GET', 'PUT', 'DELETE'])
@admin_required
def product_detail(product_id):
    p = Product.query.get_or_404(product_id)

    if request.method == 'GET':
        return jsonify({
            'product_id': p.product_id,
            'name': p.name,
            'description': p.description,
            'price': float(p.price) if p.price is not None else 0.0,
            'stock': p.stock,
            'brand': p.brand,
            'size': p.size,
            'color': p.color,
            'image_url': p.image_url,
            'created_at': p.created_at.isoformat() if p.created_at else None
        }), 200

    if request.method == 'PUT':
        form = request.form
        p.name = form.get('name', p.name)
        p.description = form.get('description', p.description)
        price = form.get('price')
        if price is not None and price != '':
            try:
                p.price = float(price)
            except Exception:
                pass
        stock = form.get('stock')
        if stock is not None and stock != '':
            try:
                p.stock = int(stock)
            except Exception:
                pass
        p.brand = form.get('brand', p.brand)
        p.size = form.get('size', p.size)
        p.color = form.get('color', p.color)

        file = request.files.get('image')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            name_part, ext = os.path.splitext(filename)
            filename = f"{name_part}_{int(datetime.utcnow().timestamp())}{ext}"
            dest = os.path.join(UPLOAD_FOLDER, filename)
            file.save(dest)
            try:
                p.image_url = url_for('static', filename=f'uploads/products/{filename}')
            except Exception:
                p.image_url = f"/static/uploads/products/{filename}"

        db.session.commit()
        return jsonify({'message': 'Product updated'}), 200

    if request.method == 'DELETE':
        # Optionally remove image file
        try:
            if p.image_url:
                # image_url like /static/uploads/products/<file>
                fn = p.image_url.split('/')[-1]
                fp = os.path.join(UPLOAD_FOLDER, fn)
                if os.path.exists(fp):
                    os.remove(fp)
        except Exception:
            pass
        db.session.delete(p)
        db.session.commit()
        return jsonify({'message': 'Product deleted'}), 200

@admin_bp.route("/orders", methods=["GET"])
@admin_required
def admin_orders_page():
    orders = (
        db.session.query(Order, User)
        .join(User, Order.user_id == User.user_id)
        .order_by(Order.created_at.desc())
        .all()
    )

    orders_data = []
    for order, user in orders:
        orders_data.append({
            "order_id": order.order_id,
            "user_name": f"{user.first_name or ''} {user.last_name or ''}".strip(),
            "email": user.email,
            "phone": user.phone_number,
            "address": f"{user.address_line or ''}, {user.city or ''}, {user.region or ''}, {user.country or ''}",
            "total": float(order.total_amount),
            "status": order.status,
            "created_at": order.created_at.strftime("%Y-%m-%d %H:%M"),
        })

    return render_template("admin/orders.html", orders=orders_data)


@admin_bp.route('/api/orders/<int:order_id>', methods=['GET'])
@admin_required
def admin_get_order(order_id):
    """Return order details including items and user info for admin modal."""
    order = Order.query.get_or_404(order_id)
    user = User.query.get(order.user_id)
    items = []
    for it in order.items:
        # OrderItem.product relationship may be available
        prod = Product.query.get(it.product_id)
        items.append({
            'item_id': getattr(it, 'order_items_id', None),
            'product_id': it.product_id,
            'name': prod.name if prod else None,
            'quantity': it.quantity,
            'price': float(it.price) if getattr(it, 'price', None) is not None else None,
        })

    return jsonify({
        'order_id': order.order_id,
        'user': {
            'user_id': user.user_id if user else None,
            'name': f"{user.first_name or ''} {user.last_name or ''}".strip() if user else None,
            'email': user.email if user else None,
            'phone': user.phone_number if user else None,
            'address': f"{user.address_line or ''}, {user.city or ''}, {user.region or ''}, {user.country or ''}" if user else None,
        },
        'items': items,
        'total_amount': float(order.total_amount) if order.total_amount is not None else 0.0,
        'status': order.status,
        'created_at': order.created_at.isoformat() if order.created_at else None,
    }), 200


@admin_bp.route('/api/orders/<int:order_id>/cancel', methods=['POST'])
@admin_required
def admin_cancel_order(order_id):
    """Cancel an order by setting its status to 'Cancelled'."""
    order = Order.query.get_or_404(order_id)
    # simple guard: don't cancel if already completed or cancelled
    if order.status == 'Cancelled':
        return jsonify({'message': 'Order already cancelled'}), 400
    if order.status == 'Completed':
        return jsonify({'message': 'Cannot cancel a completed order'}), 400

    order.status = 'Cancelled'
    db.session.commit()
    return jsonify({'message': 'Order cancelled successfully', 'order_id': order.order_id}), 200