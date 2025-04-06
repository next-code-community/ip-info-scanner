#!/usr/bin/python 

import os
import urllib.request
import json
import sys
from datetime import datetime
import time
import argparse
import socket
import ipaddress
import platform
import webbrowser
import csv
import re
import random
import requests

# Global variables
version = "2.0"
update_date = "06/04/2025"
author = "Bobi.exe & NebulaStudioTM"
github = "https://github.com/NebulaStudioTM/"
history = []
config = {
    "slow_print": True,
    "print_delay": 0.001,
    "show_ascii_art": True,
    "color_mode": True,
    "api_provider": "ip-api",  # ip-api, ipinfo, ipgeolocation
    "export_format": "json",
    "max_history": 10,
    "timeout": 5,
    "proxy": None
}

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @staticmethod
    def disable():
        Colors.HEADER = ''
        Colors.BLUE = ''
        Colors.CYAN = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.RED = ''
        Colors.ENDC = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''

    @staticmethod
    def get_random():
        colors = [Colors.BLUE, Colors.CYAN, Colors.GREEN, Colors.YELLOW]
        return random.choice(colors)

if not config["color_mode"]:
    Colors.disable()

def slowprint(s, delay=None):
    """ Prints text slowly for a better visual effect. """
    if delay is None:
        delay = config["print_delay"]
    
    if not config["slow_print"]:
        print(s)
        return
        
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(delay)

def display_ascii_art(text="IPInfo", size="normal"):
    """ Displays ASCII art using figlet or a simple fallback. """
    if config["show_ascii_art"]:
        try:
            os.system(f"figlet {text} | lolcat")
        except:
            # Fallback if figlet or lolcat is not installed
            print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 40}")
            print(f"{' ' * (20 - len(text)//2)}{Colors.YELLOW}{text}")
            print(f"{Colors.CYAN}{'=' * 40}{Colors.ENDC}\n")
    else:
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 40}")
        print(f"{' ' * (20 - len(text)//2)}{Colors.YELLOW}{text}")
        print(f"{Colors.CYAN}{'=' * 40}{Colors.ENDC}\n")

def validate_ip(ip):
    """ Validates if the input is a valid IP address. """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def resolve_hostname(hostname):
    """ Resolves a hostname to an IP address. """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def get_ip_info(ip_or_host, provider=None):
    """ Retrieves information about an IP address from various providers. """
    if provider is None:
        provider = config["api_provider"]
    
    # Check if input is a hostname and resolve if needed
    if not validate_ip(ip_or_host):
        resolved_ip = resolve_hostname(ip_or_host)
        if resolved_ip:
            ip = resolved_ip
            hostname = ip_or_host
        else:
            return {"status": "error", "message": "Invalid IP or hostname"}
    else:
        ip = ip_or_host
        hostname = None
    
    # Use selected provider API
    if provider == "ip-api":
        url = f"http://ip-api.com/json/{ip}"
    elif provider == "ipinfo":
        url = f"https://ipinfo.io/{ip}/json"
    elif provider == "ipgeolocation":
        url = f"https://api.ipgeolocation.io/ipgeo?ip={ip}"
    else:
        # Default to ip-api
        url = f"http://ip-api.com/json/{ip}"
    
    try:
        if config["proxy"]:
            proxy_handler = urllib.request.ProxyHandler({'http': config["proxy"], 'https': config["proxy"]})
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)
            
        response = urllib.request.urlopen(url, timeout=config["timeout"])
        data = json.loads(response.read())
        
        # Add our custom fields
        data["query_time"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if hostname:
            data["hostname"] = hostname
        
        # Save to history
        if len(history) >= config["max_history"]:
            history.pop(0)
        history.append({"ip": ip, "time": data["query_time"], "data": data})
        
        return data
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

def display_ip_info(data):
    """ Displays IP information in a formatted way. """
    os.system("clear" if platform.system() != "Windows" else "cls")
    display_ascii_art("IP-Info")

    slowprint(f"{Colors.CYAN} =====================================")
    slowprint(f"{Colors.YELLOW}|            IP Information           |")
    slowprint(f"{Colors.CYAN} =====================================")
    
    if data.get("status") == "error":
        slowprint(f"{Colors.RED}[!] Error: {data.get('message', 'Unknown error')}")
        return
        
    # Handle different API response formats
    if "query" in data:  # ip-api format
        slowprint(f"{Colors.CYAN} IP          : {Colors.GREEN} {data.get('query', 'N/A')}")
        slowprint(f"{Colors.CYAN} Status      : {Colors.GREEN} {data.get('status', 'N/A')}")
        slowprint(f"{Colors.CYAN} Region      : {Colors.GREEN} {data.get('regionName', 'N/A')}")
        slowprint(f"{Colors.CYAN} Country     : {Colors.GREEN} {data.get('country', 'N/A')}")
        slowprint(f"{Colors.CYAN} Date & Time : {Colors.GREEN} {data.get('query_time', 'N/A')}")
        slowprint(f"{Colors.CYAN} City        : {Colors.GREEN} {data.get('city', 'N/A')}")
        slowprint(f"{Colors.CYAN} ISP         : {Colors.GREEN} {data.get('isp', 'N/A')}")
        slowprint(f"{Colors.CYAN} Lat,Lon     : {Colors.GREEN} {data.get('lat', 'N/A')}, {data.get('lon', 'N/A')}")
        slowprint(f"{Colors.CYAN} ZIPCODE     : {Colors.GREEN} {data.get('zip', 'N/A')}")
        slowprint(f"{Colors.CYAN} TimeZone    : {Colors.GREEN} {data.get('timezone', 'N/A')}")
        slowprint(f"{Colors.CYAN} AS          : {Colors.GREEN} {data.get('as', 'N/A')}")
        if data.get("hostname"):
            slowprint(f"{Colors.CYAN} Hostname    : {Colors.GREEN} {data.get('hostname', 'N/A')}")
    elif "ip" in data:  # ipinfo format
        slowprint(f"{Colors.CYAN} IP          : {Colors.GREEN} {data.get('ip', 'N/A')}")
        slowprint(f"{Colors.CYAN} Date & Time : {Colors.GREEN} {data.get('query_time', 'N/A')}")
        slowprint(f"{Colors.CYAN} Hostname    : {Colors.GREEN} {data.get('hostname', 'N/A')}")
        slowprint(f"{Colors.CYAN} City        : {Colors.GREEN} {data.get('city', 'N/A')}")
        slowprint(f"{Colors.CYAN} Region      : {Colors.GREEN} {data.get('region', 'N/A')}")
        slowprint(f"{Colors.CYAN} Country     : {Colors.GREEN} {data.get('country', 'N/A')}")
        slowprint(f"{Colors.CYAN} Location    : {Colors.GREEN} {data.get('loc', 'N/A')}")
        slowprint(f"{Colors.CYAN} Organization: {Colors.GREEN} {data.get('org', 'N/A')}")
        slowprint(f"{Colors.CYAN} Postal      : {Colors.GREEN} {data.get('postal', 'N/A')}")
        slowprint(f"{Colors.CYAN} TimeZone    : {Colors.GREEN} {data.get('timezone', 'N/A')}")
    
    slowprint(f"\n{Colors.CYAN} =====================================")
    slowprint(f"{Colors.YELLOW}|        By {author}        |")
    slowprint(f"{Colors.CYAN} =====================================")
    slowprint(f"{Colors.RED}|  {github} |")
    slowprint(f"{Colors.CYAN} =====================================\n")

def export_data(data, filename=None, format=None):
    """ Exports IP information to a file in the specified format. """
    if format is None:
        format = config["export_format"]
        
    if filename is None:
        ip = data.get("query", data.get("ip", "unknown"))
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"ipinfo_{ip}_{timestamp}.{format}"
    
    try:
        if format == "json":
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
        elif format == "csv":
            with open(filename, 'w', newline='') as f:
                # Get all keys for the CSV header
                keys = data.keys()
                writer = csv.DictWriter(f, fieldnames=keys)
                writer.writeheader()
                writer.writerow(data)
        elif format == "txt":
            with open(filename, 'w') as f:
                for key, value in data.items():
                    f.write(f"{key}: {value}\n")
        else:
            return {"status": "error", "message": f"Unsupported format: {format}"}
            
        return {"status": "success", "filename": filename}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def batch_process(file_path, output_format=None):
    """ Process multiple IPs from a file. """
    if not os.path.exists(file_path):
        return {"status": "error", "message": f"File not found: {file_path}"}
    
    results = []
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        for line in lines:
            ip = line.strip()
            if ip and not ip.startswith('#'):  # Skip empty lines and comments
                data = get_ip_info(ip)
                results.append(data)
                # Add a small delay to avoid API rate limits
                time.sleep(0.5)
        
        # Export results if format specified
        if output_format:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"batch_results_{timestamp}.{output_format}"
            
            if output_format == "json":
                with open(filename, 'w') as f:
                    json.dump(results, f, indent=4)
            elif output_format == "csv":
                with open(filename, 'w', newline='') as f:
                    # Get all possible keys for the CSV header
                    keys = set()
                    for result in results:
                        keys.update(result.keys())
                    writer = csv.DictWriter(f, fieldnames=sorted(keys))
                    writer.writeheader()
                    for result in results:
                        writer.writerow(result)
            elif output_format == "txt":
                with open(filename, 'w') as f:
                    for i, result in enumerate(results):
                        f.write(f"===== Result {i+1} =====\n")
                        for key, value in result.items():
                            f.write(f"{key}: {value}\n")
                        f.write("\n")
            
            return {"status": "success", "results": results, "filename": filename}
        
        return {"status": "success", "results": results}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

def view_on_map(data):
    """ Opens a browser to show the IP location on a map. """
    if "lat" in data and "lon" in data:
        lat = data.get("lat")
        lon = data.get("lon")
        if lat and lon:
            url = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
            webbrowser.open(url)
            return True
    elif "loc" in data:
        loc = data.get("loc")
        if loc and "," in loc:
            lat, lon = loc.split(",")
            url = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"
            webbrowser.open(url)
            return True
    
    return False

def ping_ip(ip, count=4):
    """ Pings an IP address and returns the result. """
    ping_param = "-n" if platform.system().lower() == "windows" else "-c"
    command = f"ping {ping_param} {count} {ip}"
    return os.popen(command).read()

def traceroute(ip):
    """ Runs a traceroute to the IP address. """
    command = "tracert" if platform.system().lower() == "windows" else "traceroute"
    return os.popen(f"{command} {ip}").read()

def whois_lookup(ip):
    """ Performs a WHOIS lookup for an IP address. """
    command = "whois" if platform.system().lower() != "windows" else "nslookup"
    return os.popen(f"{command} {ip}").read()

def scan_ports(ip, ports=[80, 443, 22, 21, 25, 3306, 8080]):
    """ Scans common ports on the target IP. """
    results = {}
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = socket.getservbyport(port, "tcp") if port < 1024 else "unknown"
                results[port] = {"status": "open", "service": service}
            else:
                results[port] = {"status": "closed", "service": "N/A"}
            sock.close()
        except:
            results[port] = {"status": "error", "service": "N/A"}
    
    return results

def ipinfo():
    """ Main IP information function. """
    os.system("clear" if platform.system() != "Windows" else "cls")
    display_ascii_art("IP-Info")
    
    ip = input(f"{Colors.CYAN}Enter IP Address or Hostname: {Colors.GREEN} ").strip()

    if not ip:
        print(f"{Colors.RED}[!] Please enter a valid IP address or hostname!{Colors.ENDC}")
        time.sleep(1)
        return ipinfo()

    # Get and display IP information
    data = get_ip_info(ip)
    display_ip_info(data)
    
    # Additional actions menu
    while True:
        slowprint(f"\n{Colors.YELLOW}What would you like to do next?")
        slowprint(f"{Colors.CYAN}[1] {Colors.YELLOW}Export data to file")
        slowprint(f"{Colors.CYAN}[2] {Colors.YELLOW}View on map")
        slowprint(f"{Colors.CYAN}[3] {Colors.YELLOW}Ping IP")
        slowprint(f"{Colors.CYAN}[4] {Colors.YELLOW}Traceroute")
        slowprint(f"{Colors.CYAN}[5] {Colors.YELLOW}WHOIS lookup")
        slowprint(f"{Colors.CYAN}[6] {Colors.YELLOW}Port scan (common ports)")
        slowprint(f"{Colors.CYAN}[7] {Colors.YELLOW}Change API provider")
        slowprint(f"{Colors.CYAN}[0] {Colors.YELLOW}Return to main menu")
        
        choice = input(f"\n{Colors.CYAN}[+] Select an option >> {Colors.GREEN}").strip()
        
        if choice == "1":
            formats = ["json", "csv", "txt"]
            slowprint(f"\n{Colors.YELLOW}Export formats:")
            for i, fmt in enumerate(formats):
                slowprint(f"{Colors.CYAN}[{i+1}] {Colors.YELLOW}{fmt}")
            
            fmt_choice = input(f"\n{Colors.CYAN}Select format [1-3] (default: json): {Colors.GREEN}").strip()
            if fmt_choice == "2":
                format = "csv"
            elif fmt_choice == "3":
                format = "txt"
            else:
                format = "json"
                
            result = export_data(data, format=format)
            if result["status"] == "success":
                slowprint(f"{Colors.GREEN}[+] Data exported to {result['filename']}")
            else:
                slowprint(f"{Colors.RED}[!] Export failed: {result.get('message', 'Unknown error')}")
            
        elif choice == "2":
            slowprint(f"{Colors.YELLOW}[+] Opening map in your browser...")
            if not view_on_map(data):
                slowprint(f"{Colors.RED}[!] Couldn't open map. Location data not available.")
                
        elif choice == "3":
            slowprint(f"{Colors.YELLOW}[+] Pinging {ip}...")
            ping_result = ping_ip(ip)
            print(f"{Colors.CYAN}{ping_result}{Colors.ENDC}")
            
        elif choice == "4":
            slowprint(f"{Colors.YELLOW}[+] Performing traceroute to {ip}...")
            traceroute_result = traceroute(ip)
            print(f"{Colors.CYAN}{traceroute_result}{Colors.ENDC}")
            
        elif choice == "5":
            slowprint(f"{Colors.YELLOW}[+] Performing WHOIS lookup for {ip}...")
            whois_result = whois_lookup(ip)
            print(f"{Colors.CYAN}{whois_result}{Colors.ENDC}")
            
        elif choice == "6":
            slowprint(f"{Colors.YELLOW}[+] Scanning common ports on {ip}...")
            port_results = scan_ports(ip)
            for port, info in port_results.items():
                status_color = Colors.GREEN if info["status"] == "open" else Colors.RED
                slowprint(f"{Colors.CYAN}Port {port}: {status_color}{info['status']}{Colors.CYAN} - Service: {info['service']}")
                
        elif choice == "7":
            providers = ["ip-api", "ipinfo", "ipgeolocation"]
            slowprint(f"\n{Colors.YELLOW}Available API providers:")
            for i, provider in enumerate(providers):
                current = " (current)" if provider == config["api_provider"] else ""
                slowprint(f"{Colors.CYAN}[{i+1}] {Colors.YELLOW}{provider}{current}")
            
            provider_choice = input(f"\n{Colors.CYAN}Select provider [1-3]: {Colors.GREEN}").strip()
            if provider_choice == "1":
                config["api_provider"] = "ip-api"
            elif provider_choice == "2":
                config["api_provider"] = "ipinfo"
            elif provider_choice == "3":
                config["api_provider"] = "ipgeolocation"
                
            slowprint(f"{Colors.GREEN}[+] API provider changed to {config['api_provider']}")
            # Refresh data with new provider
            data = get_ip_info(ip)
            display_ip_info(data)
            
        elif choice == "0":
            break
        else:
            slowprint(f"{Colors.RED}[!] Invalid option{Colors.ENDC}")
            
    input(f"\n{Colors.YELLOW}[+] Press ENTER to continue...{Colors.ENDC}")
    os.system("clear" if platform.system() != "Windows" else "cls")
    return main()

def batch_mode():
    """ Process multiple IPs from a file. """
    os.system("clear" if platform.system() != "Windows" else "cls")
    display_ascii_art("Batch Mode")
    
    file_path = input(f"{Colors.CYAN}Enter path to file with IPs (one per line): {Colors.GREEN}").strip()
    
    if not file_path or not os.path.exists(file_path):
        slowprint(f"{Colors.RED}[!] File not found: {file_path}{Colors.ENDC}")
        time.sleep(1)
        return batch_mode()
    
    formats = ["none", "json", "csv", "txt"]
    slowprint(f"\n{Colors.YELLOW}Export formats:")
    slowprint(f"{Colors.CYAN}[1] {Colors.YELLOW}Don't export (just show results)")
    slowprint(f"{Colors.CYAN}[2] {Colors.YELLOW}JSON")
    slowprint(f"{Colors.CYAN}[3] {Colors.YELLOW}CSV")
    slowprint(f"{Colors.CYAN}[4] {Colors.YELLOW}Text")
    
    fmt_choice = input(f"\n{Colors.CYAN}Select format [1-4]: {Colors.GREEN}").strip()
    format = None
    if fmt_choice == "2":
        format = "json"
    elif fmt_choice == "3":
        format = "csv"
    elif fmt_choice == "4":
        format = "txt"
    
    slowprint(f"{Colors.YELLOW}[+] Processing IPs from {file_path}...")
    result = batch_process(file_path, output_format=format)
    
    if result["status"] == "success":
        slowprint(f"{Colors.GREEN}[+] Successfully processed {len(result['results'])} IPs")
        if format:
            slowprint(f"{Colors.GREEN}[+] Results saved to {result.get('filename', 'unknown')}")
            
        # Show summary
        for i, data in enumerate(result["results"]):
            ip = data.get("query", data.get("ip", "unknown"))
            status = data.get("status", "unknown")
            country = data.get("country", "unknown")
            city = data.get("city", "unknown")
            
            status_color = Colors.GREEN if status == "success" else Colors.RED
            slowprint(f"{Colors.CYAN}[{i+1}] {Colors.YELLOW}IP: {ip} - Status: {status_color}{status}{Colors.YELLOW} - Location: {country}, {city}")
    else:
        slowprint(f"{Colors.RED}[!] Failed to process file: {result.get('message', 'Unknown error')}")
    
    input(f"\n{Colors.YELLOW}[+] Press ENTER to continue...{Colors.ENDC}")
    os.system("clear" if platform.system() != "Windows" else "cls")
    return main()

def view_history():
    """ View previously looked up IPs. """
    os.system("clear" if platform.system() != "Windows" else "cls")
    display_ascii_art("History")
    
    if not history:
        slowprint(f"{Colors.YELLOW}[!] No history available")
        input(f"\n{Colors.YELLOW}[+] Press ENTER to continue...{Colors.ENDC}")
        return main()
    
    slowprint(f"{Colors.CYAN} =====================================")
    slowprint(f"{Colors.YELLOW}|         IP Lookup History          |")
    slowprint(f"{Colors.CYAN} =====================================")
    
    for i, entry in enumerate(history):
        slowprint(f"{Colors.CYAN}[{i+1}] {Colors.YELLOW}IP: {entry['ip']} - Time: {entry['time']}")
    
    choice = input(f"\n{Colors.CYAN}Select entry to view details (0 to return): {Colors.GREEN}")
    try:
        index = int(choice) - 1
        if index == -1:
            return main()
        elif 0 <= index < len(history):
            display_ip_info(history[index]["data"])
        else:
            slowprint(f"{Colors.RED}[!] Invalid selection")
    except ValueError:
        slowprint(f"{Colors.RED}[!] Invalid input")
    
    input(f"\n{Colors.YELLOW}[+] Press ENTER to continue...{Colors.ENDC}")
    os.system("clear" if platform.system() != "Windows" else "cls")
    return main()

def settings():
    """ Configure tool settings. """
    os.system("clear" if platform.system() != "Windows" else "cls")
    display_ascii_art("Settings")
    
    while True:
        slowprint(f"{Colors.CYAN} =====================================")
        slowprint(f"{Colors.YELLOW}|              Settings              |")
        slowprint(f"{Colors.CYAN} =====================================")
        
        slowprint(f"{Colors.CYAN}[1] {Colors.YELLOW}Slow Print: {Colors.GREEN if config['slow_print'] else Colors.RED}{config['slow_print']}")
        slowprint(f"{Colors.CYAN}[2] {Colors.YELLOW}Print Delay: {Colors.GREEN}{config['print_delay']}")
        slowprint(f"{Colors.CYAN}[3] {Colors.YELLOW}Show ASCII Art: {Colors.GREEN if config['show_ascii_art'] else Colors.RED}{config['show_ascii_art']}")
        slowprint(f"{Colors.CYAN}[4] {Colors.YELLOW}Color Mode: {Colors.GREEN if config['color_mode'] else Colors.RED}{config['color_mode']}")
        slowprint(f"{Colors.CYAN}[5] {Colors.YELLOW}API Provider: {Colors.GREEN}{config['api_provider']}")
        slowprint(f"{Colors.CYAN}[6] {Colors.YELLOW}Export Format: {Colors.GREEN}{config['export_format']}")
        slowprint(f"{Colors.CYAN}[7] {Colors.YELLOW}Max History: {Colors.GREEN}{config['max_history']}")
        slowprint(f"{Colors.CYAN}[8] {Colors.YELLOW}Request Timeout: {Colors.GREEN}{config['timeout']}")
        slowprint(f"{Colors.CYAN}[9] {Colors.YELLOW}Set Proxy: {Colors.GREEN}{config['proxy'] or 'None'}")
        slowprint(f"{Colors.CYAN}[0] {Colors.YELLOW}Return to Main Menu")
        
        choice = input(f"\n{Colors.CYAN}Select setting to change: {Colors.GREEN}")
        
        if choice == "1":
            config["slow_print"] = not config["slow_print"]
        elif choice == "2":
            try:
                new_delay = float(input(f"{Colors.CYAN}Enter new delay (e.g. 0.001): {Colors.GREEN}"))
                if 0 <= new_delay <= 0.1:
                    config["print_delay"] = new_delay
                else:
                    slowprint(f"{Colors.RED}[!] Delay must be between 0 and 0.1")
            except ValueError:
                slowprint(f"{Colors.RED}[!] Invalid input")
        elif choice == "3":
            config["show_ascii_art"] = not config["show_ascii_art"]
        elif choice == "4":
            config["color_mode"] = not config["color_mode"]
            if not config["color_mode"]:
                Colors.disable()
        elif choice == "5":
            providers = ["ip-api", "ipinfo", "ipgeolocation"]
            for i, provider in enumerate(providers):
                slowprint(f"{Colors.CYAN}  [{i+1}] {Colors.YELLOW}{provider}")
            try:
                provider_choice = int(input(f"{Colors.CYAN}Select provider: {Colors.GREEN}"))
                if 1 <= provider_choice <= len(providers):
                    config["api_provider"] = providers[provider_choice - 1]
                else:
                    slowprint(f"{Colors.RED}[!] Invalid selection")
            except ValueError:
                slowprint(f"{Colors.RED}[!] Invalid input")
        elif choice == "6":
            formats = ["json", "csv", "txt"]
            for i, format in enumerate(formats):
                slowprint(f"{Colors.CYAN}  [{i+1}] {Colors.YELLOW}{format}")
            try:
                format_choice = int(input(f"{Colors.CYAN}Select format: {Colors.GREEN}"))
                if 1 <= format_choice <= len(formats):
                    config["export_format"] = formats[format_choice - 1]
                else:
                    slowprint(f"{Colors.RED}[!] Invalid selection")
            except ValueError:
                slowprint(f"{Colors.RED}[!] Invalid input")
        elif choice == "7":
            try:
                new_max = int(input(f"{Colors.CYAN}Enter new max history size: {Colors.GREEN}"))
                if 0 <= new_max <= 100:
                    config["max_history"] = new_max
                else:
                    slowprint(f"{Colors.RED}[!] Max history must be between 0 and 100")
            except ValueError:
                slowprint(f"{Colors.RED}[!] Invalid input")
        elif choice == "8":
            try:
                new_timeout = int(input(f"{Colors.CYAN}Enter new timeout in seconds: {Colors.GREEN}"))
                if 1 <= new_timeout <= 30:
                    config["timeout"] = new_timeout
                else:
                    slowprint(f"{Colors.RED}[!] Timeout must be between 1 and 30 seconds")
            except ValueError:
                slowprint(f"{Colors.RED}[!] Invalid input")
        elif choice == "9":
            proxy = input(f"{Colors.CYAN}Enter proxy (format: http://host:port) or 'none' to disable: {Colors.GREEN}")
            if proxy.lower() == 'none':
                config["proxy"] = None
            elif re.match(r'^https?://\S+:\d+, proxy):
                config["proxy"] = proxy
            else:
                slowprint(f"{Colors.RED}[!] Invalid proxy format")
        elif choice == "0":
            break
        else:
            slowprint(f"{Colors.RED}[!] Invalid option{Colors.ENDC}")
        
        # Refresh screen
        time.sleep(1)
        os.system("clear" if platform.system() != "Windows" else "cls")
        display_ascii_art("Settings")
    
    return main()
