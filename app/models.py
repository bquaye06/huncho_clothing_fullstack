from app import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# -------------------------
# User Model
# -------------------------
class User(db.Model):
    __tablename__ = 'users_table'
    __table_args__ = {'schema': 'users'}

    user_id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(150), nullable=True)
    middle_name = db.Column(db.String(150), nullable=True)
    last_name = db.Column(db.String(150), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    country = db.Column(db.String(150), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)
    address_line = db.Column(db.String(255), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    region = db.Column(db.String(100), nullable=True)
    postal_code = db.Column(db.String(20), nullable=True)
    verification_code = db.Column(db.String(10), nullable=True)
    verification_expiry = db.Column(db.DateTime, nullable=True)
    password_hash = db.Column(db.Text, nullable=True)
    reset_code = db.Column(db.String(10), nullable=True)
    role = db.Column(db.String(20), default='customer')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    orders = db.relationship('Order', backref='user', lazy=True)
    # payments = db.relationship('Payment', backref='user', lazy=True)
    cart_items = db.relationship('CartItem', backref='user', lazy=True)

    # Password methods
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def user_to_dict(self):
        return {
            "username": self.username,
            "first_name" : self.first_name,
            "middle_name": self.middle_name,
            "last_name": self.last_name,
            "email": self.email,
            "phone_number": self.phone_number,
            "role": self.role,
            "created_at": self.created_at.isoformat(),
        }

# -------------------------
# Order Model
# -------------------------
class Order(db.Model):
    __tablename__ = 'order_table'
    __table_args__ = {'schema': 'orders'}

    order_id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey('users.users_table.user_id', ondelete='CASCADE'), nullable=False)
    total_amount = db.Column(db.Numeric(10, 2), nullable=False)
    status = db.Column(db.String(50), default='pending')
    payment_id = db.Column(db.BigInteger, db.ForeignKey('payment.payment_table.payment_id'), nullable=True)  # optional, maybe single payment
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Explicit foreign key to Payment.order_id
    payments = db.relationship(
        'Payment',
        backref='order',
        lazy=True,
        foreign_keys='Payment.order_id'
    )
    items = db.relationship("OrderItem", backref="order", lazy=True, cascade="all, delete")

    def to_dict(self):
        return {
            "order_id": self.order_id,
            "user_id": self.user_id,
            "total_amount": float(self.total_amount),
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "items": [item.to_dict() for item in self.items]
        }


# -------------------------
# OrderItem Model
# -------------------------
class OrderItem(db.Model):
    __tablename__ = 'order_items'
    
    order_items_id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    order_id = db.Column(db.BigInteger, db.ForeignKey('orders.order_table.order_id', ondelete='CASCADE'), nullable=False)
    product_id = db.Column(db.BigInteger, db.ForeignKey('products.products_table.product_id', ondelete='CASCADE'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    
    # relationship
    product = db.relationship('Product', backref='order_items', lazy=True)
    
    def to_dict(self):
        return{
            "item_id": self.order_items_id,
            "order_id": self.order_id,
            "product_id": self.product_id,
            "quantity": self.quantity,
            "price": float(self.price),
        }

# -------------------------
# Payment Model
# -------------------------
class Payment(db.Model):
    __tablename__ = 'payment_table'
    __table_args__ = {'schema': 'payment'}

    payment_id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    order_id = db.Column(db.BigInteger, db.ForeignKey('orders.order_table.order_id'), nullable=True)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    reference = db.Column(db.String(150), unique=True, nullable=False)
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "payment_id": self.payment_id,
            "order_id": self.order_id,
            "amount": float(self.amount),
            "reference": self.reference,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
        }

# -------------------------
# Product Model
# -------------------------
class Product(db.Model):
    __tablename__ = 'products_table'
    __table_args__ = {'schema': 'products'}

    product_id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    name = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    price = db.Column(db.Numeric(10, 2), nullable=False)
    stock = db.Column(db.Integer, default=0)
    categories_id = db.Column(db.BigInteger, db.ForeignKey('categories.categories_table.categories_id', ondelete='SET NULL'), nullable=True)
    brand = db.Column(db.String(100), nullable=True)
    size = db.Column(db.String(50), nullable=True)
    color = db.Column(db.String(50), nullable=True)
    image_url = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    category = db.relationship('Category', backref='products', lazy=True)

    cart_items = db.relationship('CartItem', backref='product', lazy=True)

    def to_dict(self):
        return {
            "product_id": self.product_id,
            "name": self.name,
            "description": self.description,
            "price": float(self.price),
            "stock": self.stock,
            "brand": self.brand,
            "size": self.size,
            "color": self.color,
            "image_url": self.image_url,
            "category_id": self.categories_id,
            "created_at": self.created_at.isoformat(),
        }

# -------------------------
# Category Model
# -------------------------
class Category(db.Model):
    __tablename__ = 'categories_table'
    __table_args__ = {'schema': 'categories'}

    categories_id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {
            "category_id": self.categories_id,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
        }

# -------------------------
# CartItem Model
# -------------------------
class CartItem(db.Model):
    __tablename__ = 'cart_items'
    __table_args__ = (
        db.UniqueConstraint('user_id', 'product_id', name='unique_user_product'),
        {'schema': 'cart'}
    )

    cart_item_id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    cart_id =  db.Column(db.BigInteger, db.ForeignKey('cart.carts.cart_id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.BigInteger, db.ForeignKey('users.users_table.user_id', ondelete='CASCADE'), nullable=False)
    product_id = db.Column(db.BigInteger, db.ForeignKey('products.products_table.product_id', ondelete='CASCADE'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    price_at_time = db.Column(db.Numeric(10, 2), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self):
        return {
            "cart_item_id": self.cart_item_id,
            "cart_id": self.cart_id,
            "product_id": self.product_id,
            "quantity": self.quantity,
            "price_at_time": float(self.price_at_time),
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# -------------------------
# Cart Model
# -------------------------
class Cart(db.Model):
    __tablename__ = 'carts'
    __table_args__={'schema':'cart'}
    
    cart_id = db.Column(db.BigInteger, primary_key=True, autoincrement=True)
    user_id = db.Column(db.BigInteger, db.ForeignKey('users.users_table.user_id', ondelete='CASCADE'), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
        # relationships
    user = db.relationship("User", backref=db.backref("cart", uselist=False))
    items = db.relationship(
        "CartItem",
        backref="cart",
        lazy=True,
        cascade="all, delete-orphan"
    )

    def to_dict(self):
        return {
            "cart_id": self.cart_id,
            "user_id": self.user_id,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "items": [item.to_dict() for item in self.items],
            "total": float(self.total() or 0.0)
        }

    def total(self):
        """Compute cart total from item price_at_time * quantity."""
        total = 0
        for item in self.items:
            # price_at_time is Decimal/Decimal-like; cast to float safely
            total += float(item.price_at_time) * item.quantity
        return round(total, 2)

# -------------------------
# Settings Model
# ------------------------- 
class Setting(db.Model):
    __tablename__ = 'settings'
    __table_args__ = {'schema': 'admin'}

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Setting {self.key}={self.value}>"


