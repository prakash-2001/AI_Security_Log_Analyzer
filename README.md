# 🔒 AI Security Log Analyzer

🔗 Live Demo: https://aisecurity-log-analyzer.streamlit.app/

A **production-quality, free-to-run** web application that parses server logs,
detects security threats using a rule-based engine, and calls the **Groq AI API**
for intelligent threat classification and remediation advice.

---

## ✨ Features

| Feature | Details |
|---|---|
| 📄 Log Formats | Apache access logs, SSH/syslog, generic timestamped |
| 🔨 Brute Force | ≥5 failed auth attempts from same IP |
| 📤 Data Exfiltration | High request volume or large byte transfers |
| ⬆️ Privilege Escalation | Access to `/admin` and elevated paths |
| 🗂️ Path Traversal | `../`, LFI, and WordPress probe patterns |
| 🌙 Off-Hours Access | Privileged access between midnight–06:00 |
| 🔑 Credential Stuffing | Multiple SSH usernames from one IP |
| 🤖 AI Analysis | Groq LLaMA-3 threat classification + remediation |
| 📊 Charts | Threat distribution (donut) + anomaly scores (bar) |

---

## 🚀 Quick Start

### 1. Clone / open the folder

```bash
cd AI_Security_Log_Analyzer
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. (Optional) Add your Groq API key

Edit `.streamlit/secrets.toml`:
```toml
GROQ_API_KEY = "gsk_YOUR_KEY_HERE"
```
Get a **free** key at [console.groq.com](https://console.groq.com).

### 4. Run

```bash
streamlit run app.py
```

Open `http://localhost:8501` in your browser.

---

## 📁 Project Structure

```
AI_Security_Log_Analyzer/
├── app.py                      # Streamlit UI + pipeline orchestration
├── requirements.txt
├── .streamlit/
│   └── secrets.toml            # GROQ_API_KEY
│
├── core/
│   ├── log_parser.py           # Parse Apache, SSH, generic logs
│   └── anomaly_detector.py     # 6-rule threat detection engine
│
├── ai/
│   └── groq_analyzer.py        # Groq LLaMA-3 integration + fallback
│
└── utils/
    ├── constants.py            # Sample logs, thresholds, icons
    └── helpers.py              # Shared utilities
```

---

## 🌐 Deploy to Streamlit Cloud (Free)

1. Push to GitHub
2. Go to [streamlit.io/cloud](https://streamlit.io/cloud) → **New app**
3. Select your repo → `app.py`
4. Under **Advanced settings → Secrets**, add:
   ```toml
   GROQ_API_KEY = "gsk_YOUR_KEY"
   ```
5. Deploy → get a public URL instantly

---

## 💰 Cost

| Resource | Cost |
|---|---|
| Streamlit Cloud | **FREE** |
| Groq API | **FREE** (generous rate limits) |
| **Total** | **$0/month** |
