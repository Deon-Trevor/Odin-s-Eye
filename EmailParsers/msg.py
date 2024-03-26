import os
import re
import hashlib
from colorama import Fore
from extract_msg import Message
from EmailParsers.utils import IsBase64
from EmailParsers.utils import virustotal
from EmailParsers.utils import nighthawk

def extract_details(email_header):
    msg_data = Message(email_header)
    subject = msg_data.subject
    sender = msg_data.sender
    recipients = msg_data.recipients
    body = msg_data.body
    date = msg_data.date

    subject = IsBase64.decode(subject)
    sender = IsBase64.decode(sender)
    recipients_list = [IsBase64.decode(recipient.email if recipient.email else recipient.name) for recipient in recipients]
    recipients_str = ', '.join(recipients_list)
    date = IsBase64.decode(date)
    body = IsBase64.decode(body)
    urls = extract_urls(body)
    
    os.system("clear")
    print(Fore.CYAN+"Subject: "+Fore.GREEN+f"{subject}")
    print(Fore.CYAN+"From: "+Fore.GREEN+f"{sender}")
    print(Fore.CYAN+"To: "+Fore.GREEN+f"{recipients_str}")
    print(Fore.CYAN+"Date: "+Fore.GREEN+f"{date}")
    print(Fore.CYAN+"\nURLs found:")

    for url in urls:
        url = clean_url(url)
        nighthawk.status(url)
        is_it_on_vt = virustotal.check_url(url)

        if is_it_on_vt is False:
            virustotal.scan_url(url)

    print("")
    extract_attachments(msg_data)

def extract_urls(text):
    urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)
    return urls

def clean_url(url):
    match = re.search(r'(https?://[^\s<]+)', url)
    
    if match:
        return match.group(1)
    
    return None  

def extract_attachments(msg):
    attachments_dir = "attachments"
    attachments = msg.attachments

    if not os.path.exists(attachments_dir):
        os.makedirs(attachments_dir)
    
    for attachment in attachments:
        attachment_data = attachment.data
        
        if isinstance(attachment_data, str):
            attachment_data = attachment_data.encode()

        hash_object = hashlib.sha256()
        hash_object.update(attachment_data)
        hash = hash_object.hexdigest()
        attachment = attachment.longFilename

        is_it_on_vt = virustotal.check_attachment(hash, attachment)

        if is_it_on_vt is False:
            file_path = os.path.join(attachments_dir, attachment)
        
            with open(file_path, "wb") as file:
                file.write(attachment_data)
            
            file.close()                
            
            virustotal.scan_attachment(file_path, attachment)
