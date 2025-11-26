from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from database import db
from dotenv import load_dotenv
import os

# --- 1. IMPORT YOUR ROUTES ---
from routes.auth_routes import auth_bp
from routes.grc_routes import grc_bp
# MAKE SURE THIS LINE EXISTS:
from routes.log_routes import log_bp  

load_dotenv()

app = Flask(__name__)

# --- 2. ALLOW ALL SECURITY (The Nuclear Option) ---
CORS(app, resources={r"/*": {"origins": "*"}})

# --- 3. CONFIGURATION ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secusuite.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'fallback-secret')

db.init_app(app)
jwt = JWTManager(app)

# --- 4. REGISTER THE ROUTES ---
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(grc_bp, url_prefix='/api/grc')
# MAKE SURE THIS LINE EXISTS:
app.register_blueprint(log_bp,  url_prefix='/api/logs') 

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5000)