from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from database import db
from dotenv import load_dotenv
import os

# IMPORT YOUR ROUTES
from routes.auth_routes import auth_bp
from routes.grc_routes import grc_bp
from routes.log_routes import log_bp 

load_dotenv()

app = Flask(__name__)

# --- 1. ALLOW ALL SECURITY (The Nuclear Option) ---
CORS(app, resources={r"/*": {"origins": "*"}})

# --- 2. CONFIGURATION ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secusuite.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# *** HARDCODED KEY FOR STABILITY ***
app.config['JWT_SECRET_KEY'] = 'hackathon-super-secret-key-12345' 

db.init_app(app)
jwt = JWTManager(app)

# --- 3. REGISTER THE ROUTES ---
app.register_blueprint(auth_bp, url_prefix='/api/auth')
app.register_blueprint(grc_bp, url_prefix='/api/grc')
app.register_blueprint(log_bp,  url_prefix='/api/logs') 

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=5000)