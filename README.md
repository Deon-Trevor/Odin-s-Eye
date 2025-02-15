# 🦉 Odin’s Eye: Unveil the Secrets in Your Emails  

Odin’s Eye is a **cutting-edge email analysis tool** designed for **cybersecurity professionals and researchers**. Inspired by the legendary sight of Norse god Odin, this tool provides **deep insights** into email headers, attachments, and embedded URLs, helping to detect phishing, malware, and suspicious content.  

The latest version of Odin’s Eye features a **FastAPI backend** with a **modern custom-built HTML, CSS, and JavaScript frontend**, replacing the previous Streamlit-based GUI. This ensures **better performance, flexibility, and interactivity** for analyzing email threats.  

---

## ⚡ Features  

### **📩 Email Header Analysis**  
- Extracts critical metadata (**From, To, CC, Subject, Date, etc.**)  
- Displays **detailed authentication results** (SPF, DKIM, DMARC)  
- Highlights anomalies and potential **spoofing attempts**  

### **🛠️ Advanced Traceroute Visualization**  
- Tracks the journey of an email across **mail servers**  
- **Animated step-by-step visualization** of mail hops  
- Displays **IP addresses, timestamps, and raw headers**  

### **🔍 Base64 & Encoding Analysis**  
- **Decodes Base64-encoded strings** hidden in email bodies and headers  
- Detects **obfuscated payloads** or hidden malicious content  

### **🌐 URL & Domain Extraction**  
- Extracts and lists **all URLs** found in emails  
- Runs checks on URLs using **VirusTotal, URLScan, and PhishFort (Nighthawk)**  
> **📌 NB:** While the **VirusTotal, URLScan and Nighthawk (NH)** integrations are available in the **API**, their **UI integration is coming soon**. You can still manually use the API to check URLs and attachments.

### **📎 Attachment Analysis**  
- Detects file attachments and **checks SHA-256 hashes** against **VirusTotal**  
- Offers the ability to **upload suspicious files** for scanning  

### **📧 Email Body Rendering**  
- Displays **HTML, plaintext, and raw source views** of the email body  
- Analyzes **embedded content** for hidden threats  

### **🔬 IOC (Indicators of Compromise) Extraction**  
- Extracts **IP addresses, emails, phone numbers, hashes, and social media links**  
- Flags **potential threats** using **automated threat intelligence**  

### **🛡️ Security & Authentication Checks**  
- **SPF/DKIM/DMARC validation** for sender reputation  
- **Fetches live DNS records** for SPF, DMARC, and DKIM signatures  
- Identifies **email spoofing** or unauthorized senders  

---

## 🚀 Getting Started  

### **1️⃣ Installation**  
Clone the repository:  
```bash
git clone https://github.com/your-username/odins-eye.git
cd odins-eye
```

Install dependencies:
```bash
pip install -r requirements.txt
```

### **2️⃣ Backend Setup (FastAPI)**
Run the FastAPI backend:
```bash
python3 -m uvicorn backend.main:app --host 127.0.0.1 --port 7070
```
The API docs will be available at:
📌 http://127.0.0.1:7070/docs (Swagger API Docs)

### **3️⃣ Frontend Setup**
Simply open the index.html file in a web browser, or serve it using a simple HTTP server:
```bash
python -m http.server 80
```
Then, navigate to http://127.0.0.1/ in your browser.

**🔥 Odin’s Eye - See through the lies of phishing and deception! 🔥**
