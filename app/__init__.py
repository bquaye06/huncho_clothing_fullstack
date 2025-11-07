from flask import Flask
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from authlib.integrations.flask_client import OAuth
from datetime import datetime, timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
mail = Mail()
oauth = OAuth()

def create_app():
    # Ensure Flask looks for templates in the package's `templates/` directory
    templates_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
    static_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static'))
    app = Flask(__name__, template_folder=templates_path, static_folder=static_path)
    
    # Flask configuration
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
        'DATABASE_URL',
        'postgresql+pg8000://postgres:Benedicta%4022@172.29.176.1/huncho_clothing'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Mail Configuration
    app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
    app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
    app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'False').lower() == 'true'
    app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False').lower() == 'true'
    app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    
    # Payment Gateway Configuration
    app.config['PAYSTACK_SECRET_KEY'] = os.getenv('PAYSTACK_SECRET_KEY')
    app.config['PAYSTACK_PUBLIC_KEY'] = os.getenv('PAYSTACK_PUBLIC_KEY')
    app.config['PAYSTACK_BASE_URL'] = os.getenv('PAYSTACK_BASE_URL', "https://api.paystack.co")
    
    # Payment Gateway Configuration
    app.config['PAYSTACK_TEST_SECRET_KEY'] = os.getenv('PAYSTACK_TEST_SECRET_KEY')
    app.config['PAYSTACK_TEST_PUBLIC_KEY'] = os.getenv('PAYSTACK_TEST_PUBLIC_KEY')
    app.config['PAYSTACK_BASE_URL'] = os.getenv('PAYSTACK_BASE_URL', "https://api.paystack.co")
    # Google OAuth config (read from environment)
    app.config['GOOGLE_CLIENT_ID'] = os.getenv('GOOGLE_CLIENT_ID')
    app.config['GOOGLE_CLIENT_SECRET'] = os.getenv('GOOGLE_CLIENT_SECRET')
    # Optional redirect URI override; if not set we compute via url_for in routes
    app.config['GOOGLE_OAUTH_REDIRECT_URI'] = os.getenv('GOOGLE_OAUTH_REDIRECT_URI')
    # Development helpers
    app.config['OAUTH_ALLOW_FALLBACK'] = os.getenv('OAUTH_ALLOW_FALLBACK', 'False').lower() == 'true'
    app.config['OAUTH_DEBUG'] = os.getenv('OAUTH_DEBUG', 'False').lower() == 'true'
    # Session cookie behavior (helpful for OAuth state preservation)
    # Default to 'Lax' which is compatible with top-level redirects used by OAuth
    app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Lax')
    # For local development using http, keep SESSION_COOKIE_SECURE False; set to True in production with HTTPS
    app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
    
    # Rate Limiter Configuration
    # JWT configuration: increase token lifetimes (defaults: access=1 day, refresh=30 days)
    try:
        access_days = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES_DAYS', '1'))
    except Exception:
        access_days = 1
    try:
        refresh_days = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES_DAYS', '30'))
    except Exception:
        refresh_days = 30
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=access_days)
    app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=refresh_days)
    db.init_app(app)
    mail.init_app(app)
    jwt.init_app(app)
    oauth.init_app(app)
    # Register Google OIDC provider if client id/secret present
    try:
        google_client_id = app.config.get('GOOGLE_CLIENT_ID')
        google_client_secret = app.config.get('GOOGLE_CLIENT_SECRET')
        if google_client_id and google_client_secret:
            oauth.register(
                name='google',
                client_id=google_client_id,
                client_secret=google_client_secret,
                server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
                client_kwargs={'scope': 'openid email profile'}
            )
    except Exception as e:
        # If registration fails, don't break app startup; log to console for now
        print('Warning: failed to register Google OAuth provider:', e)
    migrate.init_app(app, db)

    # Template context processor (inject current year)
    @app.context_processor
    def inject_now():
        return {'current_year': datetime.utcnow().year}
    
    # Import and register  blueprint
    from app.auth.routes import auth_bp
    from app.routes.index import index_bp
    from app.routes.error import error_bp
    from app.routes.user_routes import user_bp
    from app.routes.products_routes import products_bp
    from app.routes.cart_routes import cart_bp
    from app.routes.checkout_route import checkout_bp
    from app.routes.wishlist_route import wishlist_bp
    from app.routes.admin_routes import admin_bp
    
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(index_bp, url_prefix='/')
    app.register_blueprint(error_bp, url_prefix='/404')
    app.register_blueprint(user_bp, url_prefix='/account')
    app.register_blueprint(products_bp, url_prefix='/shop')
    app.register_blueprint(cart_bp, url_prefix='/cart')
    app.register_blueprint(checkout_bp, url_prefix='/checkout')
    app.register_blueprint(wishlist_bp, url_prefix='/wishlist')
    app.register_blueprint(admin_bp, url_prefix='/admin')


    return app

# Expose oauth object for use in blueprints
# (import as `from app import oauth` in route modules)