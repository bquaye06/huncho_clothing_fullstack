from flask import Blueprint, render_template
from flask_jwt_extended import jwt_required, get_jwt_identity

wishlist_bp = Blueprint('wishlist_bp', __name__)


@wishlist_bp.route('/', methods=['GET'])
@jwt_required(optional=True)
def wishlist_page():
    # For now we render a simple wishlist page. If a user is logged in we could
    # later fetch saved items via an API. Keep template simple so it matches the
    # provided reference image when empty.
    uid = get_jwt_identity()
    user = {'user_id': uid} if uid else None
    return render_template('wishlist.html', user=user)
