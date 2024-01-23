import streamlit as st
import os
import re
import email
import base64
import asyncio
import aiohttp
from email import policy
from email.parser import BytesParser
from email.header import decode_header


async def check_virustotal_async(file_path, filename, session):
    url = "https://www.virustotal.com/api/v3/files"
    headers = {
        "accept": "application/json",
        "x-apikey": os.environ["VIRUS_TOTAL_KEY"]
    }

    with open(file_path, "rb") as file_data:
        files = {"file": (filename, file_data, "application/octet-stream")}
        response = await session.post(url, data=files, headers=headers)

        return await response.text()

def check_virustotal(file_path, filename):
    if 'vt_session' not in st.session_state:
        st.session_state['vt_session'] = aiohttp.ClientSession()

    asyncio.create_task(check_virustotal_async(file_path, filename, st.session_state['vt_session']))
    st.experimental_rerun()

def decode_base64(data):
    if is_base64(data):
        return base64.b64decode(data).decode()
    
    return data

def is_base64(sb):
    try:
        if isinstance(sb, str):
            sb_bytes = bytes(sb, "ascii")
        elif isinstance(sb, bytes):
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")

        base64.b64decode(sb_bytes, validate=True)

        return True

    except Exception:
        return False

def extract_eml_details(file_content):
    msg = BytesParser(policy=policy.default).parsebytes(file_content)
    
    display_headers(msg)
    urls = extract_urls(msg)

    st.write("URLs found:")

    for url in urls:
        st.write(url)

    extract_attachments(msg)
    display_body(msg)

def display_headers(msg):
    headers_to_display = ["to", "from", "subject", "date", "authentication-results"]

    for header in headers_to_display:
        value = msg.get(header, "")

        if isinstance(value, bytes):
            value = value.decode("utf-8")  # decode if it"s a bytes object
        
        elif is_base64(value):
            value = decode_base64(value)  # your custom base64 decoding

        st.write(f"{header.capitalize()}: {value}")
        
        if header == "authentication-results":
            value = st.code(f"{value}")


def extract_urls(msg):
    urls = []

    for part in msg.walk():
        if part.get_content_type() == "text/html":
            content = part.get_payload(decode=True).decode()
            urls.extend(re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", content))

    return urls

def extract_attachments(msg):
    for part in msg.walk():
        if part.get_content_maintype() == "multipart" or part.get("Content-Disposition") is None:
            continue

        filename = part.get_filename()

        if filename:
            filename = decode_header(filename)[0][0]

            if isinstance(filename, bytes):
                filename = filename.decode()

            file_path = os.path.join("attachments", filename)

            with open(file_path, "wb") as f:
                f.write(part.get_payload(decode=True))

            st.write(f"Attachment saved: {file_path}")
            # Uncomment the line below after setting up check_virustotal function
            # asyncio.run(check_virustotal(file_path, filename))

def display_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                with st.chat_message("email", avatar="📩"):
                    st.write(part.get_payload(decode=True).decode())
    else:
        st.write(msg.get_payload(decode=True).decode())

def main():
    st.set_page_config(page_title="Odin's Eye", page_icon="assets/logo.png", layout="wide", initial_sidebar_state="auto")
    st.title("Odin's Eye")

    uploaded_file = st.file_uploader("Choose an EML file", type=["eml"])

    if uploaded_file is not None:
        file_content = uploaded_file.getvalue()  # Keep it as bytes
        extract_eml_details(file_content)

if __name__ == "__main__":
    main()
