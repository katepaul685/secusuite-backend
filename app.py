from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from database import db
from routes.grc_routes import grc_bp
from routes.auth_routes import auth_bp
from dotenv import load_dotenv
import os

# Load all the secret keys from the .env file
load_dotenv()

app = Flask(__name__)
CORS(app) # Allows your frontend to talk to this backend

# --- CONFIGURATION ---
# Database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secusuite.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT (Security Tokens)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY')
# --- END CONFIGURATION ---


# --- INITIALIZE TOOLS ---
db.init_app(app)
jwt = JWTManager(app)
# --- END INITIALIZE TOOLS ---


# --- REGISTER ROUTES ---
app.register_blueprint(grc_bp, url_prefix='/api/grc')
app.register_blueprint(auth_bp, url_prefix='/api/auth')
# --- END REGISTER ROUTES ---


# This command creates the database file (secusuite.db)
with app.app_context():
    db.create_all()

# This is the command to start the server
if __name__ == '__main__':
    app.run(debug=True, port=5000)