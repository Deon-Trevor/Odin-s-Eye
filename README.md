# Odin's Eye: Unveil the Secrets in Your Emails
**Odin's Eye** is a powerful email analysis tool designed for cyber security professionals and enthusiasts. Inspired by the legendary sight of Norse god Odin, this tool provides deep insights into email content, attachments, and headers. It's available in two versions: a Command Line Interface (CLI) for those who prefer the control and flexibility of command-line tools, and a Graphical User Interface (GUI) powered by Streamlit for a more visual and interactive experience.

# Features
- **Email Header Analysis**: Quickly parse and display essential email header information, including sender, recipient, subject, and date.
- **Base64 Decoding**: Detect and decode Base64 encoded strings seamlessly, revealing concealed data.
- **URL Extraction**: Extract and list all URLs found within an email, allowing for further analysis of potential threats or phishing attempts.
- **Attachment Analysis**: Scans attachments with VirusTotal API for security threats.
- **Email Body Display**: Render the email's body content, both text and HTML, for a complete view of the email's composition.
- **External Verdicts**: Get a verdict from popular platforms such as Virus Total, URLScan, PhishFort \(Nighthawk), etc  
- **Intuitive GUI**: Streamlit-based interface for more interactive analysis. All hail streamlit 🙌🏾

**RUN Locally**
```
pip3 install -r requirements.txt
```

**CLI Usage**
```
export VIRUS_TOTAL_KEY='your_api_key_here'
python odins_eye_cli.py
```
Follow the prompts to input the path to the .eml or .msg file.

**GUI Usage**

Set up your VirusTotal API key as an environment variable or within the Streamlit app.
Launch the Streamlit app:
```
streamlit run odins_eye_gui.py
```
Use the interactive interface to upload and analyze emails.

**NB**: As i am not a UI/UX person, I rely heavily on streamlit. Unfortunately, due to streamlit's limitations, some features will either take a long while or may never make it onto the GUI version
