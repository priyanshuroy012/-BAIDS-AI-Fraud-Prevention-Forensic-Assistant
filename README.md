VIDEO - https://drive.google.com/file/d/1QNd-s-I5FW83ohv2mP5_YFX-uQsxUvob/view?usp=sharing

🧠 **Core Capabilities**
1️⃣ Hybrid Anomaly Detection

Isolation Forest → Detects outliers in registration metadata

Autoencoder (AE) → Measures reconstruction error for abnormal behavior

2️⃣ Rule-Based Risk Engine

Deterministic rules score risk factors such as:

SIM–device mismatch

Geo-IP inconsistencies

Time-of-registration anomalies

3️⃣ Profile-Based Thresholding

Supports multiple operational profiles:

Profile	Description
Default	Balanced security & user experience
Conservative	Low false negatives, high security
Aggressive	High sensitivity for high-risk regions

Each profile adjusts:

Rule weights

ML thresholds

Risk tolerance

🧮**Hybrid Scoring Model**

Rule-Based Risk: 0–50 scale

ML Anomaly Score: Isolation Forest + AE error

OSINT Boost: ASN, IP reputation, WHOIS risk

<img width="193" height="245" alt="image" src="https://github.com/user-attachments/assets/86da89a6-dc66-454f-8a49-55a96aef6e92" />
<img width="194" height="107" alt="image" src="https://github.com/user-attachments/assets/35f93e6b-66ed-4c32-bc66-8d179ac1663f" />



📌 **Final Risk Score = Weighted Average + OSINT Boost**

🧾**Forensic Report Generation**

The system automatically generates:

Registration risk summary

Feature-level anomaly explanation

ML scores and rule triggers

OSINT enrichment details

📄 Reports are suitable for law enforcement and compliance review.

🏗️ **System Pipeline**

Registration Metadata Ingest

Rule-Based Risk Evaluation

ML Anomaly Detection (IF + AE)

OSINT Enrichment (IP / ASN / WHOIS)

**Hybrid Risk Scoring**

Decision + Forensic Report Output

🛠️ **Tech Stack
Languages**

Python 3.11

Libraries & Frameworks

scikit-learn

TensorFlow / Keras

pandas, NumPy

Streamlit (UI)

matplotlib / seaborn (visualization)

requests

ipwhois, python-whois

Tools

Google Colab (Model Training)

VS Code (Deployment)

🌍 **Use Cases**

🏦 Banking & FinTech → Detect SIM swaps, fake onboarding, device spoofing

📡 Telecom → Prevent fraud during SIM/device registration

🚔 Law Enforcement → Generate admissible forensic evidence

🔗 Cross-Industry Integration → APIs for KYC, login & fraud monitoring
