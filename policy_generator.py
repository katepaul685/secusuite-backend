import time
import random
import json

def generate_policy_response(user_input):
    """
    Simulates an LLM generating a threat intelligence policy OR providing threat info.
    Returns: (response_text, data, response_type)
    """
    # Simulate network latency
    time.sleep(1.0)
    
    user_input_lower = user_input.lower()
    
    # --- Intent Classification ---
    # Check for information requests vs policy generation requests
    info_keywords = ["what is", "define", "explain", "tell me about", "info", "standard", "iso", "nist", "compliance"]
    is_info_request = any(keyword in user_input_lower for keyword in info_keywords)
    
    if is_info_request:
        return _handle_info_request(user_input_lower)
    else:
        return _handle_policy_request(user_input_lower)

def _handle_info_request(user_input):
    # 1. Threat Knowledge Base
    threat_kb = {
        "phishing": "### 🎣 Phishing\n**Definition**: Phishing is a social engineering attack where attackers deceive victims into revealing sensitive info via fraudulent messages.\n\n**Mitigation**:\n- Implement SPF, DKIM, and DMARC.\n- Conduct regular user security training.",
        "ransomware": "### 🔒 Ransomware\n**Definition**: Malware that encrypts victim data and demands payment for the decryption key.\n\n**Mitigation**:\n- Maintain offline backups.\n- Use Endpoint Detection and Response (EDR).",
        "ddos": "### 🌊 DDoS (Distributed Denial of Service)\n**Definition**: An attempt to disrupt normal traffic by overwhelming a target with a flood of internet traffic.\n\n**Mitigation**:\n- Rate limiting.\n- Web Application Firewalls (WAF).",
        "sql injection": "### 💉 SQL Injection (SQLi)\n**Definition**: Code injection that destroys or manipulates your database.\n\n**Mitigation**:\n- Use prepared statements (Parameterized Queries).\n- Validate all inputs.",
        "cloud": "### ☁️ Cloud Security\n**Definition**: The protection of data, applications, and infrastructures involved in cloud computing.\n\n**Mitigation**:\n- Enable Multi-Factor Authentication (MFA).\n- Misconfiguration monitoring."
    }

    # 2. Standards & Compliance Knowledge Base (NEW)
    standards_kb = {
        "iso": "### 📜 ISO/IEC 27001\n**Overview**: The international standard for Information Security Management Systems (ISMS).\n\n**Key Requirements**:\n- **Risk Assessment**: Identify and treat security risks.\n- **Leadership**: Management must commit to security.\n- **Annex A Controls**: Implement controls for access control, cryptography, and physical security.",
        "nist": "### 🏛️ NIST Cybersecurity Framework (CSF)\n**Overview**: A framework by the US National Institute of Standards and Technology.\n\n**5 Core Functions**:\n1. **Identify**: Understand your assets and risks.\n2. **Protect**: Implement safeguards (Identity Management, Training).\n3. **Detect**: Spot anomalies and events.\n4. **Respond**: Have a plan for incidents.\n5. **Recover**: Restore capabilities after an attack.",
        "gdpr": "### 🇪🇺 GDPR (General Data Protection Regulation)\n**Overview**: A regulation in EU law on data protection and privacy.\n\n**Key Principles**:\n- **Consent**: Must be clear and distinguishable.\n- **Right to Access**: Users can ask what data you have.\n- **Right to be Forgotten**: Users can ask to delete data.\n- **Breach Notification**: Must report breaches within 72 hours.",
        "pci": "### 💳 PCI DSS\n**Overview**: Payment Card Industry Data Security Standard.\n\n**Goal**: Secure credit card transactions.\n\n**Requirements**:\n- Install firewalls.\n- Encrypt transmission of cardholder data.\n- Use anti-virus software."
    }
    
    # Check Threat KB
    for key, content in threat_kb.items():
        if key in user_input:
            return content, None, "info"

    # Check Standards KB
    for key, content in standards_kb.items():
        if key in user_input:
            return content, None, "info"
            
    # 3. Universal Fallback for Unknown Topics
    topic = user_input.replace("what is", "").replace("define", "").replace("explain", "").strip().title()
    if not topic: topic = "General Security"
    
    fallback_content = f"""### 🛡️ {topic} Overview
**Note:** This is a general AI-generated summary for **{topic}**.

**General Security Best Practices:**
1. **Assessment:** Identify the assets and risks associated with {topic}.
2. **Defense:** Implement 'Defense in Depth' (layered security controls).
3. **Monitoring:** Ensure logs are collected for any suspicious activity related to {topic}.
4. **Compliance:** Check ISO 27001 and NIST frameworks for specific controls.

*For detailed analysis, please consult a specialized security analyst.*"""
    
    return fallback_content, None, "info"

def _handle_policy_request(user_input):
    # Simple keyword-based logic
    policy_type = "General Security"
    action = "MONITOR"
    target = "All Assets"
    
    # 1. Detect Specific Intents
    if "block" in user_input or "deny" in user_input:
        action = "DENY"
    elif "allow" in user_input:
        action = "ALLOW"
        
    if "ip" in user_input:
        target = "Specified IP Range"
        policy_type = "Network Security"
    elif "email" in user_input:
        policy_type = "Email Security"
        target = "Malicious Sender Domain"
    elif "cloud" in user_input:
        policy_type = "Cloud Security"
        target = "Cloud Storage Buckets"
    elif "password" in user_input or "login" in user_input or "identity" in user_input:
        policy_type = "Identity Access"
        target = "User Accounts"
        action = "ENFORCE MFA"
    elif "compliance" in user_input or "grc" in user_input or "iso" in user_input:
        policy_type = "GRC & Compliance"
        target = "Audit Logs"
        action = "RETAIN FOR 7 YEARS"

    # 2. Generate a Unique ID
    policy_id = f"POL-{random.randint(1000, 9999)}"
    
    # 3. Construct the Structured Policy Object
    policy_data = {
        "policy_id": policy_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "type": policy_type,
        "generated_from": user_input,
        "rules": [
            {
                "rule_id": "R-01",
                "action": action,
                "target": target,
                "severity": "HIGH",
                "description": f"Automatically generated rule to {action.lower()} {target.lower()} based on user prompt."
            }
        ],
        "metadata": {
            "confidence_score": 0.85,
            "source": "SecuSuite-AI-Engine"
        }
    }

    response_text = f"I've generated a **{policy_type}** policy to **{action}** traffic/access for **{target}**.\n\nYou can review the structured policy data below."

    return response_text, policy_data, "policy"