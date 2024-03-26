import requests
import json
from colorama import Fore

def status(url):
    lookup_api = f"https://lookup.phishfort.com/api/lookup?url={url}"

    try:
        siteStatus = requests.get(url=lookup_api, headers={
            "x-client-id": "odin's eye",
            "x-client-version": "1.0.0"
            })

        siteStatus = json.loads(siteStatus.content)

        if "error" in siteStatus:
            print("Error checking Nighthawk status")
            pass

        else:
            siteStatus = siteStatus["dangerous"]

            if siteStatus == True:
                print(Fore.LIGHTCYAN_EX+f"Nighthawk Verdict for "+Fore.RESET+f"{url}: "+Fore.RED+f"Entirely Malicious")

                return True

            elif siteStatus == False:
                with open("EmailParsers/utils/incidents.cache", "r") as incidents:
                    incidents = incidents.read()

                    if url in incidents:
                        print(Fore.LIGHTCYAN_EX+f"Nighthawk Verdict for "+Fore.RESET+f"{url}: "+Fore.RED+f"Entirely Malicious")
                        
                    else:
                        print(Fore.LIGHTCYAN_EX+f"Nighthawk Verdict for "+Fore.RESET+f"{url}: "+Fore.BLUE+f"Completely Clean")
                        return False

    except requests.exceptions.HTTPError as error:
        print(Fore.RED+"Error:"+Fore.RESET+f" {error}")
        pass

    except requests.exceptions.ConnectionError as error:
        print(Fore.RED+"Error:"+Fore.RESET+f" {error}")
        pass

    except TypeError as error:
        print(Fore.RED+"Error:"+Fore.RESET+f" {error}")
        pass

    except requests.exceptions.ReadTimeout as error:
        print(Fore.RED+"Error:"+Fore.RESET+f" {error}")
        pass