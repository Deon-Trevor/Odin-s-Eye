import os
import vt
from colorama import Fore


virustotal_api_key = os.environ.get("VIRUS_TOTAL_KEY")


def check_attachment(hash, attachment):
    client = vt.Client(virustotal_api_key)
    
    if not virustotal_api_key:
        print("VirusTotal API key is not set in environment variables.")
        
        return
    
    try:
        analysis = client.get_object(f"/files/{hash}")

        reputation = analysis.reputation
        
        if reputation <= -50:
            print(Fore.LIGHTCYAN_EX+f"Virus Total Verdict for "+Fore.RESET+f"{attachment}: "+Fore.RED+f"Entirely Malicious")

        elif reputation < -50 and reputation < 0:
            print(Fore.LIGHTCYAN_EX+f"Virus Total Verdict for "+Fore.RESET+f"{attachment}: "+Fore.YELLOW+f"Has Malicious Code")        

        elif reputation < 0 and reputation < 50:
            print(Fore.LIGHTCYAN_EX+f"Virus Total Verdict for "+Fore.RESET+f"{attachment}: "+Fore.LIGHTGREEN_EX+f"Mostly CLean")

        elif reputation < 50:
            print(Fore.LIGHTCYAN_EX+f"Virus Total Verdict for "+Fore.RESET+f"{attachment}: "+Fore.BLUE+f"Completely Clean")                

    except vt.error.APIError as error:
        if error.code == "NotFoundError":
            print(Fore.RESET+f"{attachment}: "+Fore.YELLOW+"Not Found in VirusTotal's DB. Uploading file for scan ...."+Fore.RESET)
            
            return False
        
        else:
            print(Fore.RESET+f"{attachment}: "+Fore.YELLOW+"Error retrieving VirusTotal's verdict"+Fore.RED+f"{error}"+Fore.RESET)

    except Exception as error:
        print(Fore.RED+f"An unexpected error on "+Fore.RESET+f"{attachment} occurred: "+Fore.RED+f"{error}"+Fore.RESET)
    
    finally:
        client.close()

def scan_attachment(file_path, attachment):
    client = vt.Client(virustotal_api_key)
    
    with open(file_path, "rb") as file:
        try:
            analysis = client.scan_file(file, wait_for_completion=True)

            reputation = analysis.reputation
            
            if reputation <= -50:
                print(Fore.LIGHTCYAN_EX+f"Virus Total Verdict for "+Fore.RESET+f"{attachment}: "+Fore.RED+f"Entirely Malicious")

            elif reputation < -50 and reputation < 0:
                print(Fore.LIGHTCYAN_EX+f"Virus Total Verdict for "+Fore.RESET+f"{attachment}: "+Fore.YELLOW+f"Has Malicious Code")        

            elif reputation < 0 and reputation < 50:
                print(Fore.LIGHTCYAN_EX+f"Virus Total Verdict for "+Fore.RESET+f"{attachment}: "+Fore.LIGHTGREEN_EX+f"Mostly CLean")

            elif reputation < 50:
                print(Fore.LIGHTCYAN_EX+f"Virus Total Verdict for "+Fore.RESET+f"{attachment}: "+Fore.BLUE+f"Completely Clean")                


        except Exception as error:
            print(Fore.RED+f"An unexpected error on "+Fore.RESET+f"{attachment} occurred: "+Fore.RED+f"{error}"+Fore.RESET)
        
        finally:
            client.close()

def check_url(url):
    client = vt.Client(virustotal_api_key)
    url_id = vt.url_id(url)

    try:
        url_scan = client.get_object("/urls/{}", url_id)
        reputation = url_scan.reputation

        if reputation <= -50:
            print(Fore.LIGHTCYAN_EX+f"Virus Total Verdict for "+Fore.RESET+f"{url}: "+Fore.RED+f"Entirely Malicious")

        elif reputation < -50 and reputation < 0:
            print(Fore.LIGHTCYAN_EX+f"Virus Total Verdict for "+Fore.RESET+f"{url}: "+Fore.YELLOW+f"Has Malicious Code")        

        elif reputation < 0 and reputation < 50:
            print(Fore.LIGHTCYAN_EX+f"Virus Total Verdict for "+Fore.RESET+f"{url}: "+Fore.LIGHTGREEN_EX+f"Mostly CLean")

        elif reputation < 50:
            print(Fore.LIGHTCYAN_EX+f"Virus Total Verdict for "+Fore.RESET+f"{url}: "+Fore.BLUE+f"Completely Clean")                

    except vt.error.APIError as error:
        if error.code == "NotFoundError":
            print(Fore.RESET+f"{url}: "+Fore.YELLOW+"Not Found in VirusTotal's DB. Submitting scan ...."+Fore.RESET)
            
            return False
        
        else:
            print(Fore.RESET+f"{url}: "+Fore.YELLOW+"Error retrieving VirusTotal's verdict"+Fore.RED+f"{error}"+Fore.RESET)

    except Exception as error:
        print(Fore.RED+f"An unexpected error on "+Fore.RESET+f"{url} occurred: "+Fore.RED+f"{error}"+Fore.RESET)
        pass
        
    client.close()

def scan_url(url):
    client = vt.Client(virustotal_api_key)

    try:
        client.scan_url(f"{url}", wait_for_completion=True)           

    except Exception as error:
        print(Fore.RED+f"An unexpected error on "+Fore.RESET+f"{url} occurred: "+Fore.RED+f"{error}"+Fore.RESET) 
        pass
    
    client.close()
    check_url(url)