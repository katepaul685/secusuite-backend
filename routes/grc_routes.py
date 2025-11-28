from flask import Blueprint, request, jsonify
import sys
import os

# --- IMPORT YOUR TEAMMATE'S AI ENGINE ---
sys.path.append(os.getcwd()) 
from policy_generator import generate_policy_response

grc_bp = Blueprint('grc', __name__)

def get_fallback_response(module, prompt):
    """
    Provides a helpful template if the local AI model doesn't know the answer.
    """
    return f"""### 🛡️ {module} Advisor
    
**Note:** My specific knowledge base is currently focused on DDoS, Phishing, Ransomware, and SQL Injection. However, here is a general guide for your request:

**Request:** "{prompt}"

**General Best Practices for {module}:**
1. **Assessment:** Identify the specific assets (servers, emails, data) involved.
2. **Containment:** If this is an attack, isolate the affected systems immediately.
3. **Recovery:** Restore from clean backups and patch the vulnerability.
4. **Compliance:** Ensure you are logging this event for GDPR/ISO standards.

*For specific technical details, please consult your organization's Security Officer.*
"""

@grc_bp.route('/generate-policy', methods=['POST'])
def generate_policy():
    data = request.json
    
    # 1. Parse the complex prompt from the frontend
    # The frontend sends: "You are acting as a [Module] Expert... User Query: [Prompt]"
    full_prompt = data.get('company_description', '')
    
    # Extract the user's actual question and the module name
    user_real_query = ""
    module_name = "General Security"
    
    if "User Query:" in full_prompt:
        parts = full_prompt.split("User Query:")
        context_part = parts[0]
        user_real_query = parts[1].split("Please provide")[0].strip()
        
        # Try to find the module name
        if "acting as a" in context_part:
            module_name = context_part.split("acting as a")[1].split("Expert")[0].strip()
    else:
        user_real_query = full_prompt

    if not user_real_query:
        return jsonify({"error": "Please describe your issue."}), 400

    try:
        # 2. Try the Teammate's AI Model first
        response_text, policy_data, response_type = generate_policy_response(user_real_query)
        
        # 3. Check if it failed (The model returns a specific "I couldn't find..." string)
        if "I couldn't find specific information" in response_text:
            # Use our fallback logic instead of showing an error
            response_text = get_fallback_response(module_name, user_real_query)
            response_type = "general_advice"

        # 4. Send back the best answer we have
        return jsonify({
            "content": response_text,
            "structured_data": policy_data,
            "type": response_type
        }), 200
        
    except Exception as e:
        print(f"AI Error: {e}")
        # Even if it crashes, give a safe fallback
        fallback = get_fallback_response(module_name, user_real_query)
        return jsonify({
            "content": fallback, 
            "type": "error_fallback"
        }), 200