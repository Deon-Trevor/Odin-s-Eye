import hashlib
import re
import os
from email import policy
from email.parser import BytesParser
from email.header import decode_header
from bs4 import BeautifulSoup
from colorama import Fore
from EmailParsers.utils import IsBase64
from EmailParsers.utils import virustotal
from EmailParsers.utils import nighthawk


def extract_details(email_header):
    with open(email_header, "rb") as eml_file:
        eml_data = BytesParser(policy=policy.default).parse(eml_file)
        
        os.system("clear")
        display_headers(eml_data)
        urls = extract_urls(eml_data)
        
        print(Fore.CYAN+"URLs found:")
        
        if not urls:
            print(Fore.LIGHTGREEN_EX+"None")
        
        else:
            for url in urls:
                url = clean_url(url)
                nighthawk.status(url)
                is_it_on_vt = virustotal.check_url(url)

                if is_it_on_vt is False:
                    virustotal.scan_url(url)

        print("")
        emails = extract_emails(eml_data)
        
        print(Fore.CYAN+"Emails found:")

        if not emails:
            print(Fore.LIGHTGREEN_EX+"None")
        
        else:
            for email in emails:
                print(email)

        extract_attachments(eml_data)
        display_body(eml_data)    

def extract_urls(eml_data):
    urls = []

    for part in eml_data.walk():
        if part.get_content_type() == "text/html":
            content = part.get_payload(decode=True).decode()
            urls.extend(re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", content))

    return urls

def extract_emails(eml_data):
    emails = set()  

    for part in eml_data.walk():
        content_type = part.get_content_type()
        if content_type in ["text/plain", "text/html"]:
            try:
                content = part.get_payload(decode=True).decode("utf-8")
            except UnicodeDecodeError:
                content = part.get_payload(decode=True).decode("latin-1", errors="replace")
            
            found_emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
            emails.update(found_emails)

    return list(emails) 


def clean_url(url):
    match = re.search(r"(https?://[^\s<]+)", url)
    
    if match:
        return match.group(1)
    
    return None  

def display_headers(eml_data):
    headers_to_display = ["to", "from", "subject", "date", "authentication-results"]
    print("")

    for header in headers_to_display:
        value = eml_data.get(header, "")
        
        if IsBase64.check(value):
            value = IsBase64.decode(value)

        print(Fore.CYAN+f"{header.capitalize()}"+Fore.RESET+": "+Fore.GREEN+f"{value}"+Fore.RESET)

    print("")

def extract_attachments(data):
    print(Fore.CYAN+"\nAttachments Found:")

    for part in data.walk():
        content_disposition = part.get("Content-Disposition")

        if part.get_content_maintype() == "multipart" or content_disposition is None:
            continue

        dispositions = content_disposition.split(";")
        
        if "attachment" not in dispositions:
            print(Fore.LIGHTGREEN_EX+"None")
            continue

        attachment = part.get_filename()
        
        if attachment:
            decoded_string, encoding = decode_header(attachment)[0]
            
            if encoding:
                attachment = decoded_string.decode(encoding)
            
            else:
                attachment = decoded_string

            attachment_content = part.get_payload(decode=True)
            
            hash_object = hashlib.sha256(attachment_content)
            hash = hash_object.hexdigest()

            is_it_on_vt = virustotal.check_attachment(hash, attachment)

            if is_it_on_vt is False:
                file_path = os.path.join("attachments", attachment)
            
                with open(file_path, "wb") as file:
                    file.write(part.get_payload(decode=True))
                
                file.close()                
                
                virustotal.scan_attachment(file_path)

def display_body(msg):
    did_we_print = False
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                try:
                    body_content = part.get_payload(decode=True).decode("utf-8")
                    
                except UnicodeDecodeError:
                    body_content = part.get_payload(decode=True).decode("latin-1", errors="replace")
                
                if content_type == "text/html":
                    soup = BeautifulSoup(body_content, "html.parser")
                    body_text = soup.get_text(separator="\n", strip=True)
                
                else:
                    body_text = body_content
                
                print(Fore.CYAN+"\nBody: "+Fore.RESET, body_text)
                did_we_print = True
                break

    else:
        if did_we_print is not True:    
            try:
                body_content = msg.get_payload(decode=True).decode("utf-8")
            
            except UnicodeDecodeError:
                body_content = msg.get_payload(decode=True).decode("latin-1", errors="replace")
            
            if msg.get_content_type() == "text/html":
                soup = BeautifulSoup(body_content, "html.parser")
                body_text = soup.get_text(separator="\n", strip=True)
            
            else:
                body_text = body_content
            
            print(Fore.CYAN+"\nBody: "+Fore.RESET, body_text)
            did_we_print = True
