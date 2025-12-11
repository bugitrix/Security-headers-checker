# Security-headers-checker
A simple, beginner-friendly, yet beautiful **web-based Security Headers Analyzer** built using **Python (Flask)** and **HTML/CSS/JS**.

This tool allows you to enter any domain name (e.g., `bugitrix.com`) and instantly see:

- ✔ Present security headers  
- ❗ Missing or recommended security headers  
- ℹ Explanation of each header  
- ⚠ High-level impact  
- 🛠 Suggested remediation  
- 🍪 Raw Set-Cookie headers  
- 📋 Copyable report  
- 📥 Downloadable JSON & TXT report  

The app performs only a **safe HTTP GET request** — suitable for defensive analysis and learning.

---

## 🚀 Features

### 🟩 Beautiful & Modern Web UI  
Clean cards, severity badges, collapsible sections, and a polished layout.

### 🧠 Smart Security Header Analysis  
Detects presence or absence of commonly recommended headers:

- Strict-Transport-Security  
- Content-Security-Policy  
- X-Frame-Options  
- X-Content-Type-Options  
- Referrer-Policy  
- Permissions-Policy  
- COOP / COEP  
- Expect-CT  

### 📋 One-Click Report Actions  
- **Copy report** to clipboard  
- **Download JSON**  
- **Download TXT**  

### 🔌 Simple Flask Backend  
Easy to host locally or deploy online (Replit, Render, Railway, etc.).

---

## 📁 Project Structure
project-folder/
│
├── app.py # Flask server
├── sec_headers_checker.py # Header analysis logic
│
└── templates/
└── index.html # Full UI (HTML/CSS/JS)

## 🛠 Installation (Local — Windows / Mac / Linux)

### 1) Clone the repo
### 1) Clone the repo

```bash
git clone https://github.com/bugitrix/Security-headers-checker.git
cd security-headers-checker

2) Create & activate a virtual environment
python -m venv .venv
.\.venv\Scripts\activate

Mac / Linux:
python3 -m venv .venv
source .venv/bin/activate

3) Install dependencies
pip install flask requests

4) Run the app
python app.py

5) Open in browser
Navigate to:
http://127.0.0.1:5000




⭐ Support
If you like this project, consider giving it a ⭐ on GitHub!
