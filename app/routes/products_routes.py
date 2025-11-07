from flask import Blueprint, render_template, jsonify, request
from sqlalchemy import or_, func
import re
from app.models import Product
from app.models import db

products_bp = Blueprint('products_bp', __name__)

@products_bp.route('/', methods=['GET'])
def products_page():
    # Serve the HTML products page for browser GET requests
    products = Product.query.all()
    return render_template('shop.html', products=products)

@products_bp.route('/products', methods=['GET'])
def get_products():
    """
    Return all products as JSON for frontend use or AJAX filtering.
    """
    products = Product.query.all()
    product_list = []
    for p in products:
        product_list.append({
            'id': p.product_id,
            'name': p.name,
            'description': p.description,
            'price': str(p.price),  # Decimal to string for JSON
            'stock': p.stock,
            'brand': p.brand,
            'size': p.size,
            'color': p.color,
            'image_url': p.image_url,
            'created_at': p.created_at.strftime("%Y-%m-%d")
        })
    return jsonify(product_list), 200

@products_bp.route('/products/<string:name>', methods=['GET'])
def product_detail_page(name):
    """
    Display a single product's full details by product name.
    """
    # Query by name (not primary key). Use first_or_404 for a friendly 404 if not found.
    product = Product.query.filter_by(name=name).first_or_404()
    return render_template('product_detail.html', product=product)


@products_bp.route('/api/product/<int:product_id>', methods=['GET'])
def get_product_json(product_id):
    product = Product.query.get_or_404(product_id)
    return jsonify({
        'id': product.product_id,
        'name': product.name,
        'description': product.description,
        'price': str(product.price),
        'stock': product.stock,
        'brand': product.brand,
        'size': product.size,
        'color': product.color,
        'image_url': product.image_url,
        'created_at': product.created_at.strftime("%Y-%m-%d")
    }), 200


# Search page (render) and API
@products_bp.route('/search', methods=['GET'])
def search_page():
    # Render a search UI that will call the API endpoint below
    return render_template('search.html')


@products_bp.route('/api/search', methods=['GET'])
def api_search():
    # Simple case-insensitive partial search on name, description, brand
    q = (request.args.get('q') or '').strip()
    if not q:
        return jsonify([]), 200

    pattern = f"%{q}%"

    # normalized query (strip non-alphanumeric) to match variants like "t-shirts" vs "tshirts"
    normalized_q = re.sub(r'[^a-z0-9]', '', q.lower()) if q else ''

    norm_like = f"%{normalized_q}%" if normalized_q else None

    # Build initial filters: plain ilike OR normalized-field ilike (uses Postgres regexp_replace)
    filters = [
        Product.name.ilike(pattern),
        Product.description.ilike(pattern),
        Product.brand.ilike(pattern),
    ]

    if normalized_q:
        # use regexp_replace to remove non-alphanumeric characters from DB values and compare
        filters.extend([
            func.regexp_replace(func.lower(Product.name), '[^a-z0-9]', '', 'g').ilike(norm_like),
            func.regexp_replace(func.lower(Product.description), '[^a-z0-9]', '', 'g').ilike(norm_like),
            func.regexp_replace(func.lower(Product.brand), '[^a-z0-9]', '', 'g').ilike(norm_like),
        ])

    results = Product.query.filter(or_(*filters)).limit(50).all()

    # If still no results, try a token-based fallback (match any token) including normalized tokens
    if not results:
        tokens = [t.strip() for t in re.split(r'\s+', q) if t.strip()]
        if tokens:
            token_filters = []
            for t in tokens:
                like_t = f"%{t}%"
                token_filters.append(Product.name.ilike(like_t))
                token_filters.append(Product.description.ilike(like_t))
                token_filters.append(Product.brand.ilike(like_t))
                # normalized token
                nt = re.sub(r'[^a-z0-9]', '', t.lower())
                if nt:
                    token_filters.append(func.regexp_replace(func.lower(Product.name), '[^a-z0-9]', '', 'g').ilike(f"%{nt}%"))
                    token_filters.append(func.regexp_replace(func.lower(Product.description), '[^a-z0-9]', '', 'g').ilike(f"%{nt}%"))
                    token_filters.append(func.regexp_replace(func.lower(Product.brand), '[^a-z0-9]', '', 'g').ilike(f"%{nt}%"))

            results = Product.query.filter(or_(*token_filters)).limit(50).all()

    out = []
    for p in results:
        img = p.image_url or '/static/images/dress.webp'
        out.append({
            'id': p.product_id,
            'name': p.name,
            'description': p.description,
            'price': str(p.price),
            'image_url': img,
        })

    return jsonify(out), 200

from werkzeug.security import generate_password_hash, check_password_hash
