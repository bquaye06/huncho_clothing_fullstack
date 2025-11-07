from app import create_app, db
from dotenv import load_dotenv
from waitress import serve
import os

load_dotenv()

app = create_app()
mode = 'development'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    if mode == 'development':
        app.run(host='0.0.0.0', port=8000, debug=True)
    else:
        port = int(os.getenv("PORT", 8000))  # Render assigns a PORT dynamically
        serve(app, host='0.0.0.0', port=port, threads=4)