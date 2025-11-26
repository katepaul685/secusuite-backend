from flask import Blueprint, request, jsonify
import google.generativeai as genai
import os
from models import Policy
from database import db
from flask_jwt_extended import jwt_required, get_jwt

grc_bp = Blueprint('grc', __name__)

# Configure AI
try:
    genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
    model = genai.GenerativeModel("gemini-1.5-flash")
except Exception as e:
    print(f"Error configuring AI: {e}")
    model = None

# ROUTE 1: Generate a Policy (Protected for Admins)
@grc_bp.route('/generate-policy', methods=['POST'])
@jwt_required()  # User must be logged in
def generate_policy():

    # RBAC Check
   # claims = get_jwt()
   # user_role = claims.get("role")

   # if user_role != "admin":
         return jsonify({"error": "Access denied. Admin role required."}), 403

    # If they are an admin, proceed...
    data = request.json
    description = data.get('company_description')

    if not description:
        return jsonify({"error": "Description is required"}), 400
    if not model:
        return jsonify({"error": "AI Model not configured"}), 500

    prompt = f"""
    You are a GRC Expert. Write a professional cybersecurity policy 
    for this organization: "{description}".
    Format it cleanly in Markdown.
    """

    try:
        response = model.generate_content(prompt)
        policy_text = response.text

        # Save to Database
        new_policy = Policy(title="AI Generated Policy", content=policy_text)
        db.session.add(new_policy)
        db.session.commit()

        return jsonify(new_policy.to_dict()), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ROUTE 2: Get All Policies (Anyone logged in can see)
@grc_bp.route('/policies', methods=['GET'])
@jwt_required() # User must be logged in
def get_policies():
    policies = Policy.query.order_by(Policy.created_at.desc()).all()
    return jsonify([p.to_dict() for p in policies])