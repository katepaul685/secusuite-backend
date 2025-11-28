SecuSuite — AI-Powered Cybersecurity Platform

SecuSuite is a Python-based AI cybersecurity platform that provides unified detection, prevention, and response capabilities across email, web, network, identity, and cloud environments. 

It also includes a GRC Copilot and a Threat Intelligence Engine to help organizations strengthen security and maintain compliance.


Features

Email Security: AI phishing detection, malicious URL/attachment analysis, impersonation detection.

Web Security: Unsafe website analysis, malicious script detection, domain reputation scoring.

Network Security: Intrusion detection, anomaly detection, encrypted traffic analysis, automated response.

Identity & Cloud Security: Abnormal login detection, privilege misuse alerts, cloud workload monitoring.

GRC Copilot: Automated compliance tracking, risk scoring, policy templates, audit readiness.

Threat Intelligence Engine: Aggregates global feeds, dark web data, and local telemetry to generate predictive alerts.



Tech Stack

Core

Python 

Flask

Machine Learning Models (Python-based)

SQLite / PostgreSQL


AI/ML

NLP for phishing & content analysis

Unsupervised anomaly detection

Supervised classification models

Threat clustering & correlation

Predictive analytics


Frontend

HTML
CSS
JavaScript



Installation

1. Clone the Repository

git clone https://github.com/yourusername/secusuite.git
cd secusuite

2. Create Virtual Environment

python3 -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows

3. Install Dependencies

pip install -r requirements.txt

4. Run the Application

python app.py

API/UI will run on your configured host and port.

