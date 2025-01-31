#!/usr/bin/python 

import os
import urllib.request
import json
import sys
from datetime import datetime
import time

def slowprint(s, delay=0.001):
    """ Prints text slowly for a better visual effect. """
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(delay)

def ipinfo():
    """ Retrieves information about an IP address. """
    ip = input("Enter IP Address: \033[1;32m ").strip()

    if not ip:
        print("\033[1;91m[!] Please enter a valid IP address!\033[0m")
        return ipinfo()

    url = f"http://ip-api.com/json/{ip}"
    
    try:
        response = urllib.request.urlopen(url)
        data = json.loads(response.read())
        
        if data.get("status") != "success":
            print("\033[1;91m[!] Unable to retrieve information for this IP.\033[0m")
            return
        
        os.system("clear")
        print("\033[1;32m\007\n")
        os.system("figlet IP-Info | lolcat")

        slowprint("\033[1;36m =====================================")
        slowprint("\033[1;33m|            IP Information           |")
        slowprint("\033[1;36m =====================================")
        slowprint(f"\033[1;36m IP          : \033[1;32m {data['query']}")
        slowprint(f"\033[1;36m Status      : \033[1;32m {data['status']}")
        slowprint(f"\033[1;36m Region      : \033[1;32m {data.get('regionName', 'N/A')}")
        slowprint(f"\033[1;36m Country     : \033[1;32m {data.get('country', 'N/A')}")
        slowprint(f"\033[1;36m Date & Time : \033[1;32m {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        slowprint(f"\033[1;36m City        : \033[1;32m {data.get('city', 'N/A')}")
        slowprint(f"\033[1;36m ISP         : \033[1;32m {data.get('isp', 'N/A')}")
        slowprint(f"\033[1;36m Lat,Lon     : \033[1;32m {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
        slowprint(f"\033[1;36m ZIPCODE     : \033[1;32m {data.get('zip', 'N/A')}")
        slowprint(f"\033[1;36m TimeZone    : \033[1;32m {data.get('timezone', 'N/A')}")
        slowprint(f"\033[1;36m AS          : \033[1;32m {data.get('as', 'N/A')}\n")

        slowprint("\033[1;36m =====================================")
        slowprint("\033[1;33m|        By Bobi.exe & NebulaStudioCode        |")
        slowprint("\033[1;36m =====================================")
        slowprint("\033[1;91m|  https://github.com/NebulaStudioTM/ |")
        slowprint("\033[1;36m =====================================\n")

    except Exception as e:
        print(f"\033[1;91m[!] Error: {e}\033[0m")

    input("\033[1;33m[+] Press ENTER to continue...\033[0m")
    os.system("clear")
    return main()

def about():
    """ Displays information about the tool. """
    os.system("clear")
    print("\033[1;32m\007\n")
    os.system("figlet IP-Info | lolcat")
    time.sleep(1)

    slowprint("\033[1;91m -----------------------------------------------")
    slowprint("\033[1;33m         [+] Tool Name     =>\033[1;36m IP-Info")
    slowprint("\033[1;33m         [+] Author        =>\033[1;36m Bobi.exe")
    slowprint("\033[1;33m         [+] Latest Update =>\033[1;36m 17/3/2023")
    slowprint("\033[1;33m         [+] Github        =>\033[1;36m NebulaStudioTM")
    slowprint("\033[1;91m -----------------------------------------------")
    slowprint("\033[1;95m[+] https://github.com/NebulaStudioTM/ [+]")
    slowprint("\033[1;91m -----------------------------------------------")

    input("\033[1;33m[+] Press ENTER to continue...\033[0m")
    os.system("clear")
    return main()

def ext():
    """ Displays an exit message and terminates the program. """
    slowprint("\033[1;36m ==============================================")
    slowprint("\033[1;33m|      Thank you for using IP-Information      |")
    slowprint("\033[1;36m ==============================================")
    time.sleep(1)
    exit()

def main():
    """ Main menu of the script. """
    os.system("clear")
    print("\033[1;36m")
    os.system("figlet IPInfo | lolcat")

    slowprint("\n\033[1;33m [ 1 ]\033[1;91m Scan IP Address")
    slowprint("\033[1;33m [ 2 ]\033[1;91m About this tool")
    slowprint("\033[1;33m [ 0 ]\033[1;91m Exit\n")

    option = input("\033[1;36m[+] Select an option >> \033[1;32m").strip()

    if option == "1":
        os.system("clear")
        ipinfo()
    elif option == "2":
        os.system("clear")
        about()
    elif option == "0":
        os.system("clear")
        ext()
    else:
        slowprint("\033[1;91m[!] Please enter a valid number!\033[0m")
        time.sleep(2)
        os.system("clear")
        return main()

if __name__ == "__main__":
    main()
