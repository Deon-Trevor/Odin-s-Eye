import os
import re
import time
import hashlib
import spacy
import requests
import logging
import datetime
from transformers import pipeline
from email import policy
from email.parser import BytesParser
from email.header import decode_header
from extract_msg import Message
from urllib.parse import urlparse


TLD_CACHE_FILE = "icann_tlds.txt"
TLD_CACHE_EXPIRATION = 86400  # 24 hours (in seconds)
ICANN_TLD_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"

# Setup Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {"eml", "msg"}

# Load spaCy's pre-trained NER model (lightweight)
nlp = spacy.load("en_core_web_sm")

# Load Hugging Face Transformer Model for better PII recognition
pii_model = pipeline("ner", model="Jean-Baptiste/roberta-large-ner-english")


def extract_iocs(text: str):
    """Extract different types of IOCs including URLs, IPs, Domains, Emails, Crypto, and Social Handles."""

    urls = extract_urls(text)  # ✅ Extract all URLs first
    social_links = set(extract_social_media_links(urls))  # ✅ Convert to set

    # ✅ Extract domains from URLs
    url_domains = {
        urlparse(url).netloc.lower().lstrip("www.")
        for url in urls
        if urlparse(url).netloc
    }

    # ✅ Extract raw domains from text and merge with extracted URL domains
    raw_domains = set(extract_domains(text)) | url_domains

    # ✅ Separate social media domains from other domains
    social_media_domains = {
        domain for domain in raw_domains if domain in SOCIAL_MEDIA_DOMAINS
    }
    filtered_domains = (
        raw_domains - social_media_domains
    )  # ✅ Remove social domains from "Domains"

    # ✅ Merge extracted social media links with social media domains
    social_media = list(
        social_links | {f"https://{domain}" for domain in social_media_domains}
    )  # ✅ Ensure both are full URLs

    iocs = {
        "urls": list(
            set(urls) - social_links
        ),  # ✅ Remove social media links from URLs
        "ip_addresses": extract_ip_addresses(text),
        "domains": list(filtered_domains),  # ✅ Exclude social media domains
        "emails": extract_emails(text),
        "phone_numbers": extract_phone_numbers(text),
        "crypto_addresses": extract_crypto_addresses(text),
        "social_media": social_media,  # ✅ Include valid social media URLs
        "bank_accounts": extract_bank_accounts(text),
        "pii": extract_pii(text),
    }

    # ✅ Remove empty keys dynamically
    return {k: v for k, v in iocs.items() if v}


def extract_received_headers(eml_data):
    """Extract and structure Received headers from an email to create a traceroute view."""
    received_headers = eml_data.get_all("Received", [])
    parsed_hops = []

    for index, header in enumerate(
        received_headers[::-1], start=1
    ):  # Reverse for correct order
        received_from_match = re.search(r"from\s+([^\s;]+)", header)
        received_by_match = re.search(r"by\s+([^\s;]+)", header)
        ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", header)

        received_from = (
            received_from_match.group(1) if received_from_match else "Unknown"
        )
        received_by = received_by_match.group(1) if received_by_match else "Unknown"
        originating_ip = ip_match.group(1) if ip_match else "Unknown"

        timestamp_match = re.search(r";\s*(.+)", header)
        timestamp = timestamp_match.group(1).strip() if timestamp_match else "Unknown"

        parsed_hops.append(
            {
                "hop": index,
                "timestamp": timestamp,
                "received_from": received_from,
                "received_by": received_by,
                "originating_ip": originating_ip,
                "raw": header,  # Keep raw header for debugging
            }
        )

    return parsed_hops


def download_icann_tlds():
    """Download the ICANN TLD list and cache it locally."""
    try:
        response = requests.get(ICANN_TLD_URL, timeout=5)
        response.raise_for_status()  # Raise exception for failed requests

        # Save to file (convert to lowercase for case-insensitive matching)
        with open(TLD_CACHE_FILE, "w") as f:
            f.write("\n".join(response.text.lower().splitlines()[1:]))  # Skip header

        print("[INFO] ICANN TLDs updated successfully.")
    except requests.RequestException as e:
        print(f"[ERROR] Failed to update TLD list: {e}")


def load_icann_tlds():
    """Load TLDs from cached file, refreshing if expired or missing."""
    if (
        not os.path.exists(TLD_CACHE_FILE)
        or (time.time() - os.path.getmtime(TLD_CACHE_FILE)) > TLD_CACHE_EXPIRATION
    ):
        print("[INFO] Updating ICANN TLD list...")
        download_icann_tlds()

    # Read TLDs into a set for fast lookups
    with open(TLD_CACHE_FILE) as f:
        return set(f.read().splitlines())


# 🔹 Load TLDs at startup
ICANN_TLDS = load_icann_tlds()


def allowed_file(filename: str) -> bool:
    """Check if the uploaded file is an allowed email format."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def parse_eml(file_path: str):
    """Extract details from an .eml email file, including Received headers as hops."""
    if not os.path.exists(file_path):
        return {"error": "File not found"}

    with open(file_path, "rb") as eml_file:
        eml_data = BytesParser(policy=policy.default).parse(eml_file)

    headers = extract_headers(eml_data)
    body_content = extract_body(eml_data)
    iocs = extract_iocs(body_content["plaintext"] or body_content["html"] or "")
    attachments = extract_attachments(eml_data)
    received_hops = extract_received_headers(
        eml_data
    )  # ✅ Extract Received headers as hops

    return {
        "headers": headers,
        "body": body_content,
        "iocs": iocs,
        "attachments": attachments,
        "traceroute": received_hops,  # ✅ Properly structured Received headers
    }


def parse_msg(file_path: str):
    """Extract details from an .msg email file."""
    if not os.path.exists(file_path):
        return {"error": "File not found"}

    msg_data = Message(file_path)

    # Extract Headers
    headers = {
        "subject": msg_data.subject,
        "from": msg_data.sender,
        "to": (
            [recipient.email for recipient in msg_data.recipients]
            if msg_data.recipients
            else []
        ),
        "date": msg_data.date,
    }

    # Extract Body
    body = msg_data.body

    # ✅ Use `extract_iocs()` to ensure uniform IOC extraction
    iocs = extract_iocs(body)

    # Extract Attachments (Handles MSG Attachments Properly)
    attachments = []
    if msg_data.attachments:
        for attachment in msg_data.attachments:
            attachment_data = attachment.data
            if isinstance(attachment_data, str):
                attachment_data = attachment_data.encode()

            hash_object = hashlib.sha256()
            hash_object.update(attachment_data)
            hash_value = hash_object.hexdigest()

            attachments.append(
                {"filename": attachment.longFilename, "sha256": hash_value}
            )

    return {"headers": headers, "body": body, "iocs": iocs, "attachments": attachments}


def extract_pii(text: str):
    """Extracts various forms of PII using regex and NLP (BERT & spaCy)."""

    pii_data = {}

    # 🔹 Regex-Based Extraction
    ssn_pattern = r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b"
    pii_data["ssn"] = re.findall(ssn_pattern, text)

    credit_card_pattern = r"\b(?:\d[ -]*?){13,19}\b"
    pii_data["credit_cards"] = re.findall(credit_card_pattern, text)

    bank_account_pattern = r"\b\d{8,20}\b"
    pii_data["bank_accounts"] = re.findall(bank_account_pattern, text)

    passport_patterns = [r"\b[A-Z]\d{8}\b", r"\b\d{9}\b"]
    pii_data["passports"] = [
        match for pattern in passport_patterns for match in re.findall(pattern, text)
    ]

    national_id_patterns = [r"\b\d{12}\b", r"\b\d{11}\b", r"\b\d{9}\b"]
    pii_data["national_ids"] = [
        match for pattern in national_id_patterns for match in re.findall(pattern, text)
    ]

    phone_pattern = r"\b(?:\+?\d{1,3})?[-. ]?(?:\(\d{1,4}\))?[-. ]?\d{1,4}[-. ]?\d{1,4}[-. ]?\d{1,9}\b"
    pii_data["phone_numbers"] = re.findall(phone_pattern, text)

    crypto_patterns = {
        "btc": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        "eth": r"\b0x[a-fA-F0-9]{40}\b",
        "xmr": r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b",
    }
    pii_data["crypto_wallets"] = {
        key: re.findall(pattern, text) for key, pattern in crypto_patterns.items()
    }

    # 🔹 NLP-Based Extraction (Names, Locations, Organizations)
    doc = nlp(text)
    pii_data["names"] = [ent.text for ent in doc.ents if ent.label_ == "PERSON"]
    pii_data["locations"] = [
        ent.text for ent in doc.ents if ent.label_ in ["GPE", "LOC"]
    ]
    pii_data["organizations"] = [ent.text for ent in doc.ents if ent.label_ == "ORG"]

    # 🔹 Extract Emails Manually (Regex, because spaCy doesn't detect them)
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    pii_data["emails"] = re.findall(email_pattern, text)

    # 🔹 Transformer-based Entity Recognition (Better accuracy for PII)
    transformer_entities = pii_model(text)
    pii_data["bert_entities"] = [
        {"word": ent["word"], "entity": ent["entity"]}
        for ent in transformer_entities
        if "entity" in ent
    ]

    return pii_data


def extract_headers(email_data):
    """Extract key headers including all recipients."""

    def decode_mime_words(s):
        """Decode MIME-encoded words (e.g., =?UTF-8?B?...?=)."""
        decoded = decode_header(s)
        return " ".join(
            part.decode(encoding or "utf-8") if isinstance(part, bytes) else part
            for part, encoding in decoded
        )

    return {
        "from": decode_mime_words(email_data.get("From", "")),
        "to": [decode_mime_words(addr) for addr in email_data.get_all("To", [])],
        "cc": [decode_mime_words(addr) for addr in email_data.get_all("Cc", [])],
        "bcc": [decode_mime_words(addr) for addr in email_data.get_all("Bcc", [])],
        "subject": decode_mime_words(email_data.get("Subject", "Unknown Subject")),
        "date": email_data.get("Date"),
        "authentication-results": email_data.get("Authentication-Results"),
        "x-headers": {
            key: value for key, value in email_data.items() if key.startswith("X-")
        },  # ✅ Extract all X-Headers
    }


def extract_body(email_data):
    """Extract both plaintext and HTML versions of the email body."""
    plain_body = None
    html_body = None

    for part in email_data.walk():
        content_type = part.get_content_type()
        content_disposition = part.get("Content-Disposition", "")

        if "attachment" in content_disposition:
            continue  # Skip attachments

        try:
            body_content = part.get_payload(decode=True).decode(errors="ignore").strip()
        except:
            continue  # Skip decoding errors

        if content_type == "text/plain" and not plain_body:
            plain_body = body_content

        elif content_type == "text/html" and not html_body:
            html_body = body_content

    return {"plaintext": plain_body or "", "html": html_body or ""}


### **IOC Extraction Functions**
def extract_urls(text: str):
    """Extract all URLs from the email body."""
    return re.findall(r"http[s]?://[^\s<>\"']+", text)


def extract_ip_addresses(text: str):
    """Extract all IPv4 and IPv6 addresses."""
    ipv4_pattern = (
        r"\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
        r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
        r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\."
        r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b"
    )

    ipv6_pattern = (
        r"\b(?:[a-fA-F0-9]{1,4}:){7,7}[a-fA-F0-9]{1,4}|"
        r"(?:[a-fA-F0-9]{1,4}:){1,7}:|"
        r"(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|"
        r"(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|"
        r"(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|"
        r"(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|"
        r"(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|"
        r"[a-fA-F0-9]{1,4}:(?::[a-fA-F0-9]{1,4}){1,6}|"
        r":(?::[a-fA-F0-9]{1,4}){1,7}|::"
    )

    ipv4_matches = re.findall(ipv4_pattern, text)
    ipv6_matches = re.findall(ipv6_pattern, text)

    return ipv4_matches + ipv6_matches


def extract_domains(text: str):
    """Extract domains with ICANN-approved TLDs only."""
    domain_pattern = (
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,63})\b"
    )
    potential_domains = re.findall(domain_pattern, text)

    # ✅ Filter only valid domains (with approved ICANN TLDs)
    valid_domains = [d for d in potential_domains if d.rsplit(".", 1)[-1] in ICANN_TLDS]

    return valid_domains


def extract_emails(text: str):
    """Extract email addresses."""
    email_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
    return re.findall(email_pattern, text)


def extract_phone_numbers(text: str):
    """Extract phone numbers (supports multiple formats)."""
    phone_pattern = r"\+?\d{1,3}[\s.-]?\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}"
    return re.findall(phone_pattern, text)


def extract_crypto_addresses(text: str):
    """Extract cryptocurrency wallet addresses (Bitcoin, Ethereum, etc.)."""
    patterns = {
        "Bitcoin": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
        "Ethereum": r"\b0x[a-fA-F0-9]{40}\b",
        "Litecoin": r"\b[L3][a-km-zA-HJ-NP-Z1-9]{26,33}\b",
    }

    extracted = {}
    for crypto, pattern in patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            extracted[crypto] = matches

    return extracted


# ✅ Top 20 Social Media Domains
SOCIAL_MEDIA_DOMAINS = {
    "facebook.com",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "youtube.com",
    "tiktok.com",
    "snapchat.com",
    "pinterest.com",
    "reddit.com",
    "tumblr.com",
    "whatsapp.com",
    "wechat.com",
    "discord.com",
    "telegram.org",
    "medium.com",
    "twitch.tv",
    "quora.com",
    "vimeo.com",
    "threads.net",
    "clubhouse.com",
}


def extract_social_media_links(urls):
    """Filter URLs to extract only social media links."""
    social_links = set()

    for url in urls:
        domain = urlparse(url).netloc.lower()
        domain = domain.lstrip("www.")  # Remove 'www.' prefix for consistency

        if domain in SOCIAL_MEDIA_DOMAINS:
            social_links.add(url)  # ✅ Store full URL, not just the domain

    return list(social_links)  # ✅ Return unique full URLs


def extract_bank_accounts(text: str):
    """Extract potential bank account numbers & BINs (first 6 digits of CC)."""
    bank_pattern = r"\b\d{8,20}\b"
    bin_pattern = r"\b(?:\d{6})\b"
    return {
        "accounts": re.findall(bank_pattern, text),
        "bins": re.findall(bin_pattern, text),
    }


def extract_attachments(email_data):
    """Extract all attachments, including inline images."""
    attachments = []

    for part in email_data.walk():
        content_disposition = part.get("Content-Disposition", "")
        content_type = part.get_content_type()

        if "attachment" in content_disposition or "image" in content_type:
            filename = part.get_filename()
            if not filename:
                filename = (
                    f"unnamed_attachment_{len(attachments) + 1}"  # Assign default name
                )

            file_data = part.get_payload(decode=True)
            if file_data:
                hash_value = hashlib.sha256(file_data).hexdigest()
                attachments.append({"filename": filename, "sha256": hash_value})

    return attachments
