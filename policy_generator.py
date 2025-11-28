import time
import random
import json

def generate_policy_response(user_input):
    """
    Simulates an LLM generating threat intelligence, policies, and educational content.
    Returns: (response_text, data, response_type)
    """
    time.sleep(1.0) # Simulate latency
    user_input_lower = user_input.lower()
    
    # --- 1. Detect Intent ---
    is_report_request = any(k in user_input_lower for k in ["report", "template", "incident response", "recovery"])
    is_info_request = any(k in user_input_lower for k in ["what is", "define", "explain", "how to", "info", "learn", "tell me about"])
    
    if is_report_request:
        return _handle_report_request(user_input_lower)
    elif is_info_request:
        return _handle_education_request(user_input_lower)
    else:
        return _handle_policy_request(user_input_lower)

def _handle_education_request(user_input):
    # Knowledge Base with Attack Details, Recovery, Standards, and External Links
    kb = {
        "phishing": {
            "title": "🎣 Phishing Attack",
            "definition": "A social engineering attack where attackers deceive victims into revealing sensitive info (passwords, credit cards) via fraudulent emails.",
            "recovery": "1. Disconnect device from network.\n2. Reset all passwords immediately.\n3. Report to IT Security team.\n4. Scan device for malware.",
            "standard": "ISO 27001: A.7.2.2 (Information Security Awareness)",
            "links": "[CISA Phishing Guidance](https://www.cisa.gov/shields-up), [NIST Email Security](https://www.nist.gov/itl/applied-cybersecurity/nice/resources/online-learning-content/email-security)"
        },
        "ransomware": {
            "title": "🔒 Ransomware",
            "definition": "Malware that encrypts victim data and demands payment for the decryption key.",
            "recovery": "1. Isolate infected systems.\n2. Do NOT pay the ransom (no guarantee of data).\n3. Restore data from offline backups.\n4. Patch the vulnerability used for entry.",
            "standard": "NIST CSF: DE.AE (Anomalies and Events), RS.MI (Mitigation)",
            "links": "[CISA Ransomware Guide](https://www.cisa.gov/stopransomware), [No More Ransom Project](https://www.nomoreransom.org/)"
        },
        "ddos": {
            "title": "🌊 DDoS (Distributed Denial of Service)",
            "definition": "Flooding a server with internet traffic to disrupt normal service.",
            "recovery": "1. Contact ISP to filter traffic.\n2. Enable 'Under Attack' mode in WAF (e.g., Cloudflare).\n3. Scale up server resources temporarily.",
            "standard": "ISO 27001: A.13.1 (Network Security Management)",
            "links": "[Cloudflare DDoS Learning Center](https://www.cloudflare.com/learning/ddos/what-is-a-ddos-attack/), [AWS Shield](https://aws.amazon.com/shield/)"
        },
        "sql injection": {
            "title": "💉 SQL Injection (SQLi)",
            "definition": "Injecting malicious SQL code into a website form to manipulate the database.",
            "recovery": "1. Take the affected application offline.\n2. Identify and patch the vulnerable input field.\n3. Restore database from clean backup.",
            "standard": "OWASP Top 10: A03:2021 (Injection)",
            "links": "[OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection), [PortSwigger SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection)"
        },
        "email": {
            "title": "📧 Email Security",
            "definition": "Protection of email accounts and communication from unauthorized access, loss, or compromise.",
            "recovery": "1. Change passwords.\n2. Enable MFA.\n3. Review forwarding rules.",
            "standard": "NIST SP 800-45 (Guidelines on Electronic Mail Security)",
            "links": "[Microsoft Email Security](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/), [Google Workspace Security](https://support.google.com/a/answer/9157861?hl=en)"
        },
        "cloud": {
            "title": "☁️ Cloud Security",
            "definition": "A set of policies, controls, procedures and technologies that work together to protect cloud-based systems, data, and infrastructure.",
            "recovery": "1. Identify the scope of the breach.\n2. secure the compromised account/resource.\n3. Review logs (CloudTrail, Azure Monitor).",
            "standard": "CSA Cloud Controls Matrix (CCM)",
            "links": "[AWS Security](https://aws.amazon.com/security/), [Azure Security](https://azure.microsoft.com/en-us/explore/security/), [Cloud Security Alliance](https://cloudsecurityalliance.org/)"
        },
        "identity": {
            "title": "🆔 Identity & Access Management (IAM)",
            "definition": "A framework of policies and technologies for ensuring that the proper people in an enterprise have the appropriate access to technology resources.",
            "recovery": "1. Revoke access for compromised identities.\n2. Rotate keys and secrets.\n3. Audit access logs.",
            "standard": "NIST SP 800-63 (Digital Identity Guidelines)",
            "links": "[Okta IAM Guide](https://www.okta.com/identity-101/what-is-identity-access-management/), [Auth0 Blog](https://auth0.com/blog/)"
        },
        "network": {
            "title": "🌐 Network Security",
            "definition": "The practice of preventing and protecting against unauthorized intrusion into corporate networks.",
            "recovery": "1. Isolate affected segments.\n2. Block malicious IPs.\n3. Patch vulnerabilities.",
            "standard": "ISO/IEC 27033 (Network Security)",
            "links": "[Cisco Network Security](https://www.cisco.com/c/en/us/products/security/what-is-network-security.html), [SANS Institute](https://www.sans.org/)"
        },
         "grc": {
            "title": "📜 Governance, Risk, and Compliance (GRC)",
            "definition": "A strategy for managing an organization's overall governance, enterprise risk management and compliance with regulations.",
            "recovery": "N/A (Strategic Framework)",
            "standard": "ISO 31000 (Risk Management), COBIT",
            "links": "[OCEG GRC Capability Model](https://www.oceg.org/), [NIST Risk Management Framework](https://csrc.nist.gov/projects/risk-management/about-rmf)"
        }
    }

    # Search for a match
    for key, data in kb.items():
        if key in user_input:
            content = f"""### {data['title']}
**Definition:** {data['definition']}

**🚨 How to Recover / Best Practices:**
{data['recovery']}

**📜 Governing Standard:**
{data['standard']}

**🔗 Learn More:**
{data.get('links', 'No external links available.')}
"""
            return content, None, "info"

    # Fallback for general questions
    return """### 🛡️ General Security Advice
**Prevention:**
1. **Patching:** Keep all software up to date.
2. **MFA:** Enable Multi-Factor Authentication everywhere.
3. **Backups:** Keep offline backups of critical data.

**Standard:** NIST Cybersecurity Framework (Identify, Protect, Detect, Respond, Recover).""", None, "info"

def _handle_report_request(user_input):
    # Generates a professional Incident Response Report Template
    
    report_type = "General Incident"
    if "phishing" in user_input: report_type = "Phishing Incident"
    elif "ransomware" in user_input: report_type = "Ransomware Attack"
    
    template = f"""### 📝 Incident Response Report Template: {report_type}

**1. Incident Overview**
* **Date/Time:** [Enter Date]
* **Detected By:** [Name/System]
* **Severity:** [High/Medium/Low]

**2. Impact Analysis**
* **Affected Systems:** [List Servers/Devices]
* **Data Compromised:** [Yes/No - Describe]

**3. Containment & Eradication**
* **Actions Taken:** [e.g., Isolated host, blocked IP]
* **Root Cause:** [e.g., Malicious email attachment]

**4. Recovery**
* **Restoration:** [e.g., Restored from Backup]
* **Verification:** [System tested and confirmed clean]

**5. Lessons Learned**
* **What went wrong?**
* **How to prevent recurrence?**
"""
    return template, None, "report"

def _handle_policy_request(user_input):
    # (This is your existing policy logic - kept simple here)
    policy_type = "General Security"
    target = "All Assets"
    action = "MONITOR"
    
    if "email" in user_input: policy_type = "Email Security"; target = "Inbound Emails"; action = "FILTER"
    elif "network" in user_input: policy_type = "Network Security"; target = "Firewall"; action = "BLOCK"
    elif "cloud" in user_input: policy_type = "Cloud Security"; target = "S3 Buckets"; action = "ENCRYPT"
    
    response_text = f"### 🛡️ Generated Policy: {policy_type}\n\n**Action:** {action} traffic/access for {target}.\n\n**Compliance:** Aligns with ISO 27001 Access Control."
    
    policy_data = {
        "id": f"POL-{random.randint(1000,9999)}",
        "type": policy_type,
        "action": action,
        "target": target
    }
    
    return response_text, policy_data, "policy"