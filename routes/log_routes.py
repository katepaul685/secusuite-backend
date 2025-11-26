from flask import Blueprint, request, jsonify
import random

log_bp = Blueprint('logs', __name__)

# --- DUMMY ML FUNCTION ---
def analyze_log_file(filename):
    threat_count = random.randint(0, 12)
    status = "Safe" if threat_count < 5 else "Critical"
    return {"threats": threat_count, "status": status}
# -------------------------

@log_bp.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
        
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    analysis_result = analyze_log_file(file.filename)

    return jsonify({
        "message": "File processed",
        "data": analysis_result
    }), 200