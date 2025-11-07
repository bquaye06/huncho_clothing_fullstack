from flask import blueprints, render_template

error_bp = blueprints.Blueprint('404_bp', __name__)

@error_bp.route('/', methods=['GET'])
def error_404():
    return render_template('404.html'), 404