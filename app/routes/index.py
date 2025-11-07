from flask import blueprints, render_template


index_bp = blueprints.Blueprint('index_bp', __name__)
@index_bp.route('/', methods=['GET'])
def home():
    return render_template('index.html')