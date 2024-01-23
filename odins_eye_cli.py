import os
import re
import email
import base64
import asyncio
import aiohttp
import magic  # For handling .msg files
from email import policy
from email.parser import BytesParser, Parser
from email.header import decode_header
from colorama import Fore


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

async def check_virustotal(file_path, filename):
    url = "https://www.virustotal.com/api/v3/files"

    with open(file_path, "rb") as file_data:
        files = {"file": (filename, file_data, "application/octet-stream")}
        headers = {
            "accept": "application/json",
            "x-apikey": virustotal_api_key
        }

        try:
            print("\nSubmitting attachment to VirusTotal for scanning\n")

            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=files, headers=headers) as response:
                    await asyncio.sleep(15)
    
                    print(await response.text())

        except Exception as error:
            print("\nVirusTotal Scan failed with:"+Fore.LIGHTRED_EX+f" {error}"+Fore.RESET)

def extract_eml_details(file_path):
    if file_path.endswith(".eml"):
        with open(file_path, "rb") as eml_file:
            msg = BytesParser(policy=policy.default).parse(eml_file)
            
            display_headers(msg)
            urls = extract_urls(msg)
            print(Fore.CYAN+"URLs found:")

            for url in urls:
                print(Fore.GREEN+f"{url}")

            extract_attachments(msg)
            display_body(msg)

    elif file_path.endswith(".msg"):
        # Handle .msg files if necessary using python-magic or similar library
        pass

def display_headers(msg):
    headers_to_display = ["to", "from", "subject", "date", "authentication-results"]
    print("")

    for header in headers_to_display:
        value = msg.get(header, "")
        
        if is_base64(value):
            value = decode_base64(value)

        print(Fore.CYAN+f"{header.capitalize()}"+Fore.RESET+": "+Fore.GREEN+f"{value}"+Fore.RESET)

    print("")        

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
        
            print(Fore.CYAN+"\nAttachment saved: "+Fore.GREEN+f"{file_path}")
            
            # Pass both file_path and filename to the check_virustotal function
            # asyncio.run(check_virustotal(file_path, filename))


def display_body(msg):
    if msg.is_multipart():

        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                print(Fore.CYAN+"\nBody: "+Fore.RESET, part.get_payload(decode=True).decode())
    
    else:
        print("Body: ", msg.get_payload(decode=True).decode())

if __name__ == "__main__":
    virustotal_api_key = os.environ["VIRUS_TOTAL_KEY"]

    file_path = input("\nEnter the path to the .eml or .msg file:\n> ")
    extract_eml_details(file_path)