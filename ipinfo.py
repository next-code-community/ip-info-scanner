#!/usr/bin/python3

import os
import sys
import socket
import requests
import json
import random
import re
import csv
import time
import argparse
import ipaddress
import platform
import webbrowser
from datetime import datetime
import concurrent.futures
from urllib.parse import urlparse

# Global variables
VERSION = "3.0"
UPDATE_DATE = "14/04/2025"
AUTHOR = "InfoSec Specialist"
GITHUB = "https://github.com/next-code-community/ip-info-scanner"
MAX_THREADS = 10
DEFAULT_TIMEOUT = 10

# History tracking
history = []

# Configuration
config = {
    "slow_print": True,
    "print_delay": 0.03,
    "show_ascii_art": True,
    "color_mode": True,
    "api_providers": ["ip-api", "ipinfo", "ipgeolocation", "ipdata", "abuseipdb", "shodan"],
    "primary_provider": "ip-api",
    "export_format": "json",
    "max_history": 20,
    "timeout": DEFAULT_TIMEOUT,
    "proxy": None,
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0"
    ],
    "deep_scan": True,
    "port_scan_timeout": 1.0,
    "common_ports": [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 445, 1433, 3306, 3389, 5632, 5900, 8080, 8443],
    "extended_ports": [20, 21, 22, 23, 25, 53, 80, 110, 111, 115, 135, 139, 143, 194, 389, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5632, 5900, 8080, 8443, 8888, 10000]
}

# API Keys (replace with your own)
API_KEYS = {
    "ipinfo": "",       # https://ipinfo.io/
    "ipgeolocation": "", # https://ipgeolocation.io/
    "ipdata": "",       # https://ipdata.co/
    "abuseipdb": "",    # https://www.abuseipdb.com/
    "shodan": ""        # https://www.shodan.io/
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
    MAGENTA = '\033[35m'
    BRIGHT_GREEN = '\033[92;1m'
    BRIGHT_RED = '\033[91;1m'
    BRIGHT_YELLOW = '\033[93;1m'
    BRIGHT_BLUE = '\033[94;1m'
    BRIGHT_MAGENTA = '\033[35;1m'
    BRIGHT_CYAN = '\033[96;1m'
    BG_BLACK = '\033[40m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_BLUE = '\033[44m'
    BG_MAGENTA = '\033[45m'
    BG_CYAN = '\033[46m'
    BG_WHITE = '\033[47m'

    @staticmethod
    def disable():
        for attr in dir(Colors):
            if not attr.startswith('__') and not callable(getattr(Colors, attr)):
                setattr(Colors, attr, '')

    @staticmethod
    def get_random():
        color_attrs = [attr for attr in dir(Colors) 
                     if not attr.startswith('__') and 
                        not callable(getattr(Colors, attr)) and
                        attr not in ['ENDC', 'BOLD', 'UNDERLINE', 'disable', 'get_random']]
        return getattr(Colors, random.choice(color_attrs))

if not config["color_mode"]:
    Colors.disable()

def get_random_user_agent():
    """Returns a random user agent from the configuration."""
    return random.choice(config["user_agents"])

def slowprint(s, delay=None, color=None):
    """Prints text with a delay between characters for visual effect."""
    if delay is None:
        delay = config["print_delay"]
    
    if not config["slow_print"]:
        if color:
            print(f"{color}{s}{Colors.ENDC}")
        else:
            print(s)
        return
    
    for c in s:
        if color:
            sys.stdout.write(f"{color}{c}{Colors.ENDC}")
        else:
            sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def display_ascii_art(text="Enhanced IPInfo", size="normal"):
    """Displays ASCII art banner."""
    if config["show_ascii_art"]:
        try:
            os.system(f"figlet -f slant '{text}' | lolcat")
            print()  # Add a newline after the figlet output
        except:
            # Fallback if figlet or lolcat is not installed
            banner = r"""
 _____      _                          _   _____  _____  _____        __      
| ____|_ __| |__   __ _ _ __   ___ ___| | |_   _||  __ \|_   _|      / _|     
|  _| | '_ \| '_ \ / _` | '_ \ / __/ _ \ |   | |  | |__) | | |  _ __ | |_ ___  
| |___| | | | | | | (_| | | | | (_|  __/ |   | |  |  ___/  | | | '_ \|  _/ _ \ 
|_____|_| |_|_| |_|\__,_|_| |_|\___\___|_|   |_|  |_|     |_| | | | | || (_) |
                                                           |_| |_| |_|_| \___/ 
"""
            print(f"{Colors.CYAN}{banner}{Colors.ENDC}")
    else:
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 60}")
        print(f"{' ' * ((60 - len(text)) // 2)}{Colors.YELLOW}{text}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}\n")

def clear_screen():
    """Clear the terminal screen."""
    os.system("clear" if platform.system() != "Windows" else "cls")

def validate_ip(ip):
    """Validates if the input is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def is_valid_domain(domain):
    """Validates if the input is a valid domain name."""
    domain_pattern = re.compile(
        r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*'
        r'([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    )
    return bool(domain_pattern.match(domain))

def is_valid_url(url):
    """Validates if the input is a valid URL."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def resolve_hostname(hostname):
    """Resolves a hostname to an IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

def get_domain_from_url(url):
    """Extracts domain from URL."""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':')[0]
        return domain
    except:
        return None

def get_request_with_ua(url, timeout=None):
    """Makes an HTTP request with a random user agent."""
    if timeout is None:
        timeout = config["timeout"]
        
    headers = {
        'User-Agent': get_random_user_agent(),
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
    }
    
    proxies = None
    if config["proxy"]:
        proxies = {
            'http': config["proxy"],
            'https': config["proxy"]
        }
    
    try:
        response = requests.get(url, headers=headers, proxies=proxies, timeout=timeout)
        return response
    except Exception as e:
        return None

def get_ip_info_from_provider(ip, provider):
    """Retrieves IP information from a specific provider."""
    result = {"provider": provider, "status": "error", "message": "Unknown error"}
    
    try:
        if provider == "ip-api":
            url = f"http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
            response = get_request_with_ua(url)
            if response and response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    result = {"provider": provider, "status": "success", **data}
                else:
                    result = {"provider": provider, "status": "error", "message": data.get("message", "API request failed")}
                    
        elif provider == "ipinfo":
            token_param = f"?token={API_KEYS['ipinfo']}" if API_KEYS['ipinfo'] else ""
            url = f"https://ipinfo.io/{ip}/json{token_param}"
            response = get_request_with_ua(url)
            if response and response.status_code == 200:
                data = response.json()
                result = {"provider": provider, "status": "success", **data}
                
        elif provider == "ipgeolocation":
            api_key_param = f"apiKey={API_KEYS['ipgeolocation']}" if API_KEYS['ipgeolocation'] else ""
            url = f"https://api.ipgeolocation.io/ipgeo?{api_key_param}&ip={ip}"
            response = get_request_with_ua(url)
            if response and response.status_code == 200:
                data = response.json()
                result = {"provider": provider, "status": "success", **data}
                
        elif provider == "ipdata":
            api_key = API_KEYS['ipdata']
            if api_key:
                url = f"https://api.ipdata.co/{ip}?api-key={api_key}"
                response = get_request_with_ua(url)
                if response and response.status_code == 200:
                    data = response.json()
                    result = {"provider": provider, "status": "success", **data}
                
        elif provider == "abuseipdb":
            api_key = API_KEYS['abuseipdb']
            if api_key:
                url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
                headers = {
                    'Key': api_key,
                    'Accept': 'application/json',
                    'User-Agent': get_random_user_agent()
                }
                response = requests.get(url, headers=headers)
                if response and response.status_code == 200:
                    data = response.json()
                    result = {"provider": provider, "status": "success", **data}
                
        elif provider == "shodan":
            api_key = API_KEYS['shodan']
            if api_key:
                url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
                response = get_request_with_ua(url)
                if response and response.status_code == 200:
                    data = response.json()
                    result = {"provider": provider, "status": "success", **data}
    
    except Exception as e:
        result = {"provider": provider, "status": "error", "message": str(e)}
    
    return result

def get_ip_info(ip_or_host):
    """Retrieves comprehensive information about an IP address or hostname."""
    # Determine if input is IP, domain or URL
    original_input = ip_or_host
    hostname = None
    
    if is_valid_url(ip_or_host):
        hostname = get_domain_from_url(ip_or_host)
        if hostname:
            ip_or_host = hostname
    
    if not validate_ip(ip_or_host):
        if is_valid_domain(ip_or_host):
            hostname = ip_or_host
            slowprint(f"{Colors.YELLOW}Resolving hostname {hostname}...{Colors.ENDC}")
            ip = resolve_hostname(hostname)
            if not ip:
                return {"status": "error", "message": f"Could not resolve hostname: {hostname}"}
        else:
            return {"status": "error", "message": "Invalid IP, URL or hostname provided"}
    else:
        ip = ip_or_host
    
    # Default result with basic info
    result = {
        "query": ip,
        "original_input": original_input,
        "hostname": hostname,
        "query_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "status": "success",
        "providers": {}
    }
    
    # Get primary info
    slowprint(f"{Colors.YELLOW}Fetching primary information from {config['primary_provider']}...{Colors.ENDC}")
    primary_data = get_ip_info_from_provider(ip, config['primary_provider'])
    result["providers"][config['primary_provider']] = primary_data
    
    # Copy primary data to main result if successful
    if primary_data.get("status") == "success":
        for key, value in primary_data.items():
            if key not in ["provider", "status"]:
                result[key] = value
    
    # Get additional information from other providers if deep scan is enabled
    if config["deep_scan"]:
        slowprint(f"{Colors.YELLOW}Performing deep scan with multiple providers...{Colors.ENDC}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            future_to_provider = {
                executor.submit(get_ip_info_from_provider, ip, provider): provider
                for provider in config["api_providers"]
                if provider != config['primary_provider']  # Skip primary provider as we already queried it
            }
            
            for future in concurrent.futures.as_completed(future_to_provider):
                provider = future_to_provider[future]
                try:
                    data = future.result()
                    result["providers"][provider] = data
                except Exception as exc:
                    result["providers"][provider] = {
                        "provider": provider,
                        "status": "error",
                        "message": str(exc)
                    }
    
    # Try to perform reverse DNS lookup
    try:
        if "reverse" not in result or not result["reverse"]:
            reverse_hostname = socket.getfqdn(ip)
            if reverse_hostname != ip:  # If it returns a different value
                result["reverse"] = reverse_hostname
    except:
        pass
    
    # Save to history
    if len(history) >= config["max_history"]:
        history.pop(0)
    history.append({"ip": ip, "time": result["query_time"], "data": result})
    
    return result

def scan_ports(ip, ports=None, timeout=None):
    """Scans specified ports on the target IP."""
    if ports is None:
        ports = config["common_ports" if not config["deep_scan"] else "extended_ports"]
    
    if timeout is None:
        timeout = config["port_scan_timeout"]
    
    results = {}
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_port = {executor.submit(check_port, ip, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open, service = future.result()
                status = "open" if is_open else "closed"
                results[port] = {"status": status, "service": service}
                if is_open:
                    open_ports.append(port)
            except Exception as exc:
                results[port] = {"status": "error", "service": "unknown", "message": str(exc)}
    
    return {"scan_results": results, "open_ports": sorted(open_ports), "total_open": len(open_ports)}

def check_port(ip, port, timeout):
    """Checks if a specific port is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        result = sock.connect_ex((ip, port))
        is_open = (result == 0)
        
        service = "unknown"
        if is_open:
            try:
                service = socket.getservbyport(port, "tcp")
            except:
                common_services = {
                    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 
                    80: "HTTP", 110: "POP3", 115: "SFTP", 135: "RPC", 139: "NetBIOS", 
                    143: "IMAP", 194: "IRC", 443: "HTTPS", 445: "SMB", 
                    1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5632: "PCAnywhere", 
                    5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
                }
                service = common_services.get(port, "unknown")
        
        return is_open, service
    finally:
        sock.close()

def ping_ip(ip, count=4):
    """Pings an IP address and returns the result."""
    ping_param = "-n" if platform.system().lower() == "windows" else "-c"
    command = f"ping {ping_param} {count} {ip}"
    return os.popen(command).read()

def traceroute(ip):
    """Runs a traceroute to the IP address."""
    command = "tracert" if platform.system().lower() == "windows" else "traceroute"
    return os.popen(f"{command} {ip}").read()

def whois_lookup(ip):
    """Performs a WHOIS lookup for an IP address."""
    command = "whois" if platform.system().lower() != "windows" else "nslookup"
    return os.popen(f"{command} {ip}").read()

def nslookup(domain):
    """Performs DNS lookup for a domain."""
    return os.popen(f"nslookup {domain}").read()

def display_ip_info(data):
    """Displays IP information in a formatted way."""
    clear_screen()
    display_ascii_art("IP Information")
    
    if data.get("status") == "error":
        slowprint(f"{Colors.RED}[!] Error: {data.get('message', 'Unknown error')}", color=Colors.RED)
        return
    
    # Header
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_YELLOW}{' ' * 20}IP INFORMATION REPORT{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    
    # Basic Information
    print(f"{Colors.BRIGHT_BLUE}[+] BASIC INFORMATION:{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    ip = data.get("query", data.get("ip", "N/A"))
    print(f"{Colors.YELLOW}IP Address     : {Colors.GREEN}{ip}{Colors.ENDC}")
    if data.get("original_input") and data.get("original_input") != ip:
        print(f"{Colors.YELLOW}Original Input  : {Colors.GREEN}{data.get('original_input')}{Colors.ENDC}")
    if data.get("hostname"):
        print(f"{Colors.YELLOW}Hostname       : {Colors.GREEN}{data.get('hostname')}{Colors.ENDC}")
    if data.get("reverse"):
        print(f"{Colors.YELLOW}Reverse DNS    : {Colors.GREEN}{data.get('reverse')}{Colors.ENDC}")
    print(f"{Colors.YELLOW}Query Time     : {Colors.GREEN}{data.get('query_time', 'N/A')}{Colors.ENDC}")
    
    # Location Information
    print(f"\n{Colors.BRIGHT_BLUE}[+] LOCATION INFORMATION:{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    city = data.get("city", "N/A")
    region = data.get("regionName", data.get("region", "N/A"))
    country = data.get("country", "N/A")
    print(f"{Colors.YELLOW}City           : {Colors.GREEN}{city}{Colors.ENDC}")
    print(f"{Colors.YELLOW}Region         : {Colors.GREEN}{region}{Colors.ENDC}")
    print(f"{Colors.YELLOW}Country        : {Colors.GREEN}{country}{Colors.ENDC}")
    print(f"{Colors.YELLOW}Postal/ZIP     : {Colors.GREEN}{data.get('zip', data.get('postal', 'N/A'))}{Colors.ENDC}")
    
    # Coordinates
    lat = data.get("lat", "N/A")
    lon = data.get("lon", "N/A")
    if lat != "N/A" and lon != "N/A":
        print(f"{Colors.YELLOW}Coordinates    : {Colors.GREEN}{lat}, {lon}{Colors.ENDC}")
    elif data.get("loc"):
        print(f"{Colors.YELLOW}Coordinates    : {Colors.GREEN}{data.get('loc')}{Colors.ENDC}")
    
    # Organization
    print(f"\n{Colors.BRIGHT_BLUE}[+] ORGANIZATION INFORMATION:{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.YELLOW}ISP            : {Colors.GREEN}{data.get('isp', data.get('org', 'N/A'))}{Colors.ENDC}")
    if data.get("as"):
        print(f"{Colors.YELLOW}AS Number      : {Colors.GREEN}{data.get('as')}{Colors.ENDC}")
    if data.get("asname"):
        print(f"{Colors.YELLOW}AS Name        : {Colors.GREEN}{data.get('asname')}{Colors.ENDC}")
    if data.get("org") and data.get("isp") != data.get("org"):
        print(f"{Colors.YELLOW}Organization   : {Colors.GREEN}{data.get('org')}{Colors.ENDC}")
    
    # Network Information
    print(f"\n{Colors.BRIGHT_BLUE}[+] NETWORK INFORMATION:{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.YELLOW}Timezone       : {Colors.GREEN}{data.get('timezone', 'N/A')}{Colors.ENDC}")
    if data.get("mobile") is not None:
        mobile_status = "Yes" if data.get("mobile") else "No"
        print(f"{Colors.YELLOW}Mobile Network : {Colors.GREEN}{mobile_status}{Colors.ENDC}")
    if data.get("proxy") is not None:
        proxy_status = "Yes" if data.get("proxy") else "No"
        print(f"{Colors.YELLOW}Proxy/VPN      : {Colors.GREEN}{proxy_status}{Colors.ENDC}")
    if data.get("hosting") is not None:
        hosting_status = "Yes" if data.get("hosting") else "No"
        print(f"{Colors.YELLOW}Hosting        : {Colors.GREEN}{hosting_status}{Colors.ENDC}")
    
    # Additional provider details (if deep scan)
    if config["deep_scan"] and data.get("providers"):
        print(f"\n{Colors.BRIGHT_BLUE}[+] ADDITIONAL PROVIDER DATA:{Colors.ENDC}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
        
        for provider, provider_data in data.get("providers", {}).items():
            if provider == config['primary_provider']:
                continue  # Skip primary provider as we already displayed its data
                
            status = provider_data.get("status", "error")
            status_color = Colors.GREEN if status == "success" else Colors.RED
            
            print(f"{Colors.YELLOW}Provider: {Colors.BRIGHT_MAGENTA}{provider} {Colors.YELLOW}- Status: {status_color}{status}{Colors.ENDC}")
            
            if status == "success":
                # Show a subset of interesting information from this provider
                interesting_fields = display_provider_highlights(provider, provider_data)
                
                if not interesting_fields:
                    print(f"{Colors.CYAN}  No unique additional information from this provider{Colors.ENDC}")
    
    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_YELLOW}{' ' * 15}END OF BASIC INFORMATION{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")

def display_provider_highlights(provider, data):
    """Displays interesting highlights from a specific provider."""
    displayed_fields = 0
    
    # Provider-specific interesting fields
    if provider == "abuseipdb":
        if "data" in data and isinstance(data["data"], dict):
            abuse_data = data["data"]
            if "abuseConfidenceScore" in abuse_data:
                score = abuse_data["abuseConfidenceScore"]
                score_color = Colors.GREEN if score < 30 else (Colors.YELLOW if score < 70 else Colors.RED)
                print(f"{Colors.CYAN}  Abuse Confidence Score: {score_color}{score}%{Colors.ENDC}")
                displayed_fields += 1
            if "totalReports" in abuse_data:
                reports = abuse_data["totalReports"]
                reports_color = Colors.GREEN if reports == 0 else (Colors.YELLOW if reports < 5 else Colors.RED)
                print(f"{Colors.CYAN}  Total Abuse Reports: {reports_color}{reports}{Colors.ENDC}")
                displayed_fields += 1
            if "lastReportedAt" in abuse_data and abuse_data["lastReportedAt"]:
                print(f"{Colors.CYAN}  Last Reported: {Colors.YELLOW}{abuse_data['lastReportedAt']}{Colors.ENDC}")
                displayed_fields += 1
                
    elif provider == "shodan":
        if "ports" in data and data["ports"]:
            ports_str = ", ".join(map(str, data["ports"][:10]))
            if len(data["ports"]) > 10:
                ports_str += f" and {len(data['ports']) - 10} more"
            print(f"{Colors.CYAN}  Open Ports (Shodan): {Colors.YELLOW}{ports_str}{Colors.ENDC}")
            displayed_fields += 1
        if "vulns" in data and data["vulns"]:
            vulns_count = len(data["vulns"])
            vuln_color = Colors.GREEN if vulns_count == 0 else (Colors.YELLOW if vulns_count < 3 else Colors.RED)
            print(f"{Colors.CYAN}  Vulnerabilities: {vuln_color}{vulns_count} found{Colors.ENDC}")
            displayed_fields += 1
        if "hostnames" in data and data["hostnames"]:
            hostnames_str = ", ".join(data["hostnames"][:3])
            if len(data["hostnames"]) > 3:
                hostnames_str += f" and {len(data['hostnames']) - 3} more"
            print(f"{Colors.CYAN}  Hostnames: {Colors.YELLOW}{hostnames_str}{Colors.ENDC}")
            displayed_fields += 1
        if "os" in data and data["os"]:
            print(f"{Colors.CYAN}  Operating System: {Colors.YELLOW}{data['os']}{Colors.ENDC}")
            displayed_fields += 1
            
    elif provider == "ipdata":
        if "threat" in data and isinstance(data["threat"], dict):
            threat_data = data["threat"]
            is_threat = any(threat_data.values())
            if is_threat:
                print(f"{Colors.CYAN}  Threat Intelligence: {Colors.RED}Suspicious{Colors.ENDC}")
                for key, value in threat_data.items():
                    if value and key not in ["is_threat"]:
                        print(f"{Colors.CYAN}    - {key.replace('_', ' ').title()}: {Colors.RED}Yes{Colors.ENDC}")
                        displayed_fields += 1
            else:
                print(f"{Colors.CYAN}  Threat Intelligence: {Colors.GREEN}Clean{Colors.ENDC}")
                displayed_fields += 1
        
        if "asn" in data and isinstance(data["asn"], dict):
            asn_data = data["asn"]
            if "name" in asn_data and asn_data["name"]:
                print(f"{Colors.CYAN}  ASN Name: {Colors.YELLOW}{asn_data['name']}{Colors.ENDC}")
                displayed_fields += 1
                
    return displayed_fields

def export_data(data, filename=None, format=None):
    """Exports IP information to a file in the specified format."""
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
                flatten_data = flatten_dict(data)
                writer = csv.DictWriter(f, fieldnames=flatten_data.keys())
                writer.writeheader()
                writer.writerow(flatten_data)
        elif format == "txt":
            with open(filename, 'w') as f:
                write_dict_to_txt(f, data)
        else:
            return {"status": "error", "message": f"Unsupported format: {format}"}
            
        return {"status": "success", "filename": filename}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def flatten_dict(d, parent_key='', sep='_'):
    """Flattens a nested dictionary for CSV export."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            items.append((new_key, json.dumps(v)))
        else:
            items.append((new_key, v))
    return dict(items)

def write_dict_to_txt(file, d, indent=0):
    """Writes a nested dictionary to a text file with indentation."""
    for k, v in d.items():
        if isinstance(v, dict):
            file.write(f"{' ' * indent}{k}:\n")
            write_dict_to_txt(file, v, indent + 4)
        elif isinstance(v, list):
            file.write(f"{' ' * indent}{k}: {json.dumps(v)}\n")
        else:
            file.write(f"{' ' * indent}{k}: {v}\n")

def batch_process(file_path, output_format=None):
    """Process multiple IPs from a file."""
    if not os.path.exists(file_path):
        return {"status": "error", "message": f"File not found: {file_path}"}
    
    results = []
    successful = 0
    failed = 0
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
        
        total = sum(1 for line in lines if line.strip() and not line.strip().startswith('#'))
        processed = 0
        
        clear_screen()
        display_ascii_art("Batch Processing")
        
        for line in lines:
            ip = line.strip()
            if ip and not ip.startswith('#'):  # Skip empty lines and comments
                processed += 1
                print(f"{Colors.CYAN}[{processed}/{total}] Processing: {Colors.YELLOW}{ip}{Colors.ENDC}")
                
                data = get_ip_info(ip)
                if data.get("status") == "success":
                    successful += 1
                else:
                    failed += 1
                
                results.append(data)
                progress = int(processed / total * 40)
                print(f"{Colors.CYAN}[{Colors.GREEN}{'=' * progress}{' ' * (40 - progress)}{Colors.CYAN}] {processed}/{total} ({int(processed / total * 100)}%){Colors.ENDC}")
                
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
                    # Get all possible keys from flattened data
                    all_keys = set()
                    flattened_results = []
                    for result in results:
                        flat = flatten_dict(result)
                        all_keys.update(flat.keys())
                        flattened_results.append(flat)
                    
                    writer = csv.DictWriter(f, fieldnames=sorted(all_keys))
                    writer.writeheader()
                    for result in flattened_results:
                        writer.writerow(result)
            elif output_format == "txt":
                with open(filename, 'w') as f:
                    for i, result in enumerate(results):
                        f.write(f"===== Result {i+1} =====\n")
                        write_dict_to_txt(f, result)
                        f.write("\n")
            
            return {"status": "success", "results": results, "filename": filename, 
                   "successful": successful, "failed": failed, "total": total}
        
        return {"status": "success", "results": results, 
               "successful": successful, "failed": failed, "total": total}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

def view_on_map(data):
    """Opens a browser to show the IP location on a map."""
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

def perform_security_scan(ip):
    """Performs a more comprehensive security scan of the IP."""
    result = {
        "ip": ip,
        "scan_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "port_scan": None,
        "whois": None,
        "traceroute": None,
        "reputation": {}
    }
    
    # Port scan
    print(f"{Colors.YELLOW}[+] Scanning ports on {ip}...{Colors.ENDC}")
    port_result = scan_ports(ip, config["extended_ports"])
    result["port_scan"] = port_result
    
    # WHOIS lookup
    print(f"{Colors.YELLOW}[+] Performing WHOIS lookup for {ip}...{Colors.ENDC}")
    whois_result = whois_lookup(ip)
    result["whois"] = whois_result
    
    # Traceroute
    print(f"{Colors.YELLOW}[+] Performing traceroute to {ip}...{Colors.ENDC}")
    traceroute_result = traceroute(ip)
    result["traceroute"] = traceroute_result
    
    # Check reputation in AbuseIPDB if API key available
    if API_KEYS["abuseipdb"]:
        print(f"{Colors.YELLOW}[+] Checking reputation on AbuseIPDB...{Colors.ENDC}")
        url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
        headers = {
            'Key': API_KEYS["abuseipdb"],
            'Accept': 'application/json',
            'User-Agent': get_random_user_agent()
        }
        try:
            response = requests.get(url, headers=headers, timeout=config["timeout"])
            if response.status_code == 200:
                data = response.json()
                if "data" in data:
                    result["reputation"]["abuseipdb"] = {
                        "status": "success",
                        "score": data["data"].get("abuseConfidenceScore", "N/A"),
                        "reports": data["data"].get("totalReports", "N/A"),
                        "last_reported": data["data"].get("lastReportedAt", "N/A")
                    }
        except Exception as e:
            result["reputation"]["abuseipdb"] = {"status": "error", "message": str(e)}
    
    return result

def display_security_scan(data):
    """Displays security scan results in a formatted way."""
    clear_screen()
    display_ascii_art("Security Scan")
    
    # Header
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_YELLOW}{' ' * 20}SECURITY SCAN REPORT{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    
    print(f"{Colors.YELLOW}IP Address: {Colors.GREEN}{data['ip']}{Colors.ENDC}")
    print(f"{Colors.YELLOW}Scan Time: {Colors.GREEN}{data['scan_time']}{Colors.ENDC}")
    
    # Port scan results
    print(f"\n{Colors.BRIGHT_BLUE}[+] PORT SCAN RESULTS:{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    
    if data["port_scan"] and "open_ports" in data["port_scan"]:
        open_ports = data["port_scan"]["open_ports"]
        scan_results = data["port_scan"]["scan_results"]
        
        if open_ports:
            print(f"{Colors.YELLOW}Found {Colors.RED}{len(open_ports)}{Colors.YELLOW} open ports:{Colors.ENDC}")
            for port in open_ports:
                service = scan_results[port]["service"]
                print(f"{Colors.CYAN}  Port {Colors.GREEN}{port}{Colors.CYAN}: {Colors.YELLOW}{service}{Colors.ENDC}")
        else:
            print(f"{Colors.GREEN}No open ports found (from scanned port list){Colors.ENDC}")
    else:
        print(f"{Colors.RED}Port scan failed or returned no results{Colors.ENDC}")
    
    # Reputation information
    if data["reputation"]:
        print(f"\n{Colors.BRIGHT_BLUE}[+] REPUTATION INFORMATION:{Colors.ENDC}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
        
        for source, rep_data in data["reputation"].items():
            if source == "abuseipdb" and rep_data.get("status") == "success":
                score = rep_data.get("score", "N/A")
                if score != "N/A":
                    score_color = Colors.GREEN if score < 30 else (Colors.YELLOW if score < 70 else Colors.RED)
                    print(f"{Colors.YELLOW}AbuseIPDB Score: {score_color}{score}%{Colors.ENDC}")
                
                reports = rep_data.get("reports", "N/A")
                if reports != "N/A" and reports > 0:
                    print(f"{Colors.YELLOW}Total Reports: {Colors.RED}{reports}{Colors.ENDC}")
                    print(f"{Colors.YELLOW}Last Reported: {Colors.CYAN}{rep_data.get('last_reported', 'N/A')}{Colors.ENDC}")
                else:
                    print(f"{Colors.YELLOW}Total Reports: {Colors.GREEN}0{Colors.ENDC}")
    
    # WHOIS information summary
    if data["whois"]:
        print(f"\n{Colors.BRIGHT_BLUE}[+] WHOIS INFORMATION (SUMMARY):{Colors.ENDC}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
        
        whois_data = data["whois"]
        # Extract just the first few lines for summary
        whois_lines = whois_data.split('\n')[:15]
        for line in whois_lines:
            if line.strip():
                print(f"{Colors.CYAN}{line}{Colors.ENDC}")
        
        if len(whois_data.split('\n')) > 15:
            print(f"{Colors.YELLOW}... (truncated, use option to view full WHOIS){Colors.ENDC}")
    
    # Traceroute summary
    if data["traceroute"]:
        print(f"\n{Colors.BRIGHT_BLUE}[+] TRACEROUTE INFORMATION (SUMMARY):{Colors.ENDC}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
        
        traceroute_data = data["traceroute"]
        # Extract just the first few lines for summary
        traceroute_lines = traceroute_data.split('\n')[:10]
        for line in traceroute_lines:
            if line.strip():
                print(f"{Colors.CYAN}{line}{Colors.ENDC}")
        
        if len(traceroute_data.split('\n')) > 10:
            print(f"{Colors.YELLOW}... (truncated, use option to view full traceroute){Colors.ENDC}")
    
    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_YELLOW}{' ' * 15}END OF SECURITY SCAN{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")

def main_menu():
    """Displays the main menu and handles user input."""
    clear_screen()
    display_ascii_art("Enhanced IPInfo")
    
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_YELLOW}{' ' * 20}MAIN MENU{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    
    print(f"{Colors.CYAN}[1] {Colors.YELLOW}IP/Domain Information Lookup{Colors.ENDC}")
    print(f"{Colors.CYAN}[2] {Colors.YELLOW}Batch Processing (Multiple IPs){Colors.ENDC}")
    print(f"{Colors.CYAN}[3] {Colors.YELLOW}Security Scan{Colors.ENDC}")
    print(f"{Colors.CYAN}[4] {Colors.YELLOW}View History{Colors.ENDC}")
    print(f"{Colors.CYAN}[5] {Colors.YELLOW}Settings{Colors.ENDC}")
    print(f"{Colors.CYAN}[6] {Colors.YELLOW}About{Colors.ENDC}")
    print(f"{Colors.CYAN}[0] {Colors.YELLOW}Exit{Colors.ENDC}")
    
    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_GREEN}Version: {VERSION} | Updated: {UPDATE_DATE}{Colors.ENDC}")
    
    choice = input(f"\n{Colors.BRIGHT_CYAN}Select an option [0-6]: {Colors.GREEN}")
    
    if choice == "1":
        ip_lookup()
    elif choice == "2":
        batch_mode()
    elif choice == "3":
        security_scan()
    elif choice == "4":
        view_history_menu()
    elif choice == "5":
        settings_menu()
    elif choice == "6":
        about()
    elif choice == "0":
        clear_screen()
        print(f"{Colors.BRIGHT_GREEN}Thank you for using Enhanced IPInfo!{Colors.ENDC}")
        sys.exit(0)
    else:
        print(f"{Colors.RED}Invalid choice. Press Enter to continue...{Colors.ENDC}")
        input()
    
    return main_menu()

def ip_lookup():
    """Handles IP/domain information lookup."""
    clear_screen()
    display_ascii_art("IP Lookup")
    
    query = input(f"{Colors.BRIGHT_CYAN}Enter IP Address, URL or Hostname: {Colors.GREEN}").strip()
    
    if not query:
        print(f"{Colors.RED}Error: Please enter a valid IP address, URL or hostname!{Colors.ENDC}")
        input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.ENDC}")
        return ip_lookup()
    
    # Get and display IP information
    print(f"{Colors.YELLOW}Collecting information for {query}...{Colors.ENDC}")
    data = get_ip_info(query)
    display_ip_info(data)
    
    # Additional actions menu
    while True:
        print(f"\n{Colors.BRIGHT_YELLOW}OPTIONS:{Colors.ENDC}")
        print(f"{Colors.CYAN}[1] {Colors.YELLOW}Export data to file{Colors.ENDC}")
        print(f"{Colors.CYAN}[2] {Colors.YELLOW}View on map{Colors.ENDC}")
        print(f"{Colors.CYAN}[3] {Colors.YELLOW}Ping IP{Colors.ENDC}")
        print(f"{Colors.CYAN}[4] {Colors.YELLOW}Port scan{Colors.ENDC}")
        print(f"{Colors.CYAN}[5] {Colors.YELLOW}Full security scan{Colors.ENDC}")
        print(f"{Colors.CYAN}[6] {Colors.YELLOW}WHOIS lookup{Colors.ENDC}")
        print(f"{Colors.CYAN}[7] {Colors.YELLOW}Traceroute{Colors.ENDC}")
        print(f"{Colors.CYAN}[8] {Colors.YELLOW}Change API provider{Colors.ENDC}")
        print(f"{Colors.CYAN}[0] {Colors.YELLOW}Return to main menu{Colors.ENDC}")
        
        choice = input(f"\n{Colors.BRIGHT_CYAN}Select an option [0-8]: {Colors.GREEN}")
        
        ip = data.get("query", data.get("ip", None))
        if not ip:
            print(f"{Colors.RED}Error: IP address not found in data!{Colors.ENDC}")
            input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.ENDC}")
            break
        
        if choice == "1":
            formats = ["json", "csv", "txt"]
            print(f"\n{Colors.YELLOW}Export formats:{Colors.ENDC}")
            for i, fmt in enumerate(formats):
                print(f"{Colors.CYAN}[{i+1}] {Colors.YELLOW}{fmt}{Colors.ENDC}")
            
            fmt_choice = input(f"\n{Colors.BRIGHT_CYAN}Select format [1-3] (default: json): {Colors.GREEN}").strip()
            if fmt_choice == "2":
                format = "csv"
            elif fmt_choice == "3":
                format = "txt"
            else:
                format = "json"
                
            result = export_data(data, format=format)
            if result["status"] == "success":
                print(f"{Colors.GREEN}Data exported to {result['filename']}{Colors.ENDC}")
            else:
                print(f"{Colors.RED}Export failed: {result.get('message', 'Unknown error')}{Colors.ENDC}")
            
        elif choice == "2":
            print(f"{Colors.YELLOW}Opening map in your browser...{Colors.ENDC}")
            if not view_on_map(data):
                print(f"{Colors.RED}Couldn't open map. Location data not available.{Colors.ENDC}")
                
        elif choice == "3":
            print(f"{Colors.YELLOW}Pinging {ip}...{Colors.ENDC}")
            ping_result = ping_ip(ip)
            print(f"{Colors.CYAN}{ping_result}{Colors.ENDC}")
            
        elif choice == "4":
            print(f"{Colors.YELLOW}Scanning ports on {ip}...{Colors.ENDC}")
            scan_type = input(f"{Colors.BRIGHT_CYAN}Scan type - Quick [1] or Full [2] (default: 1): {Colors.GREEN}").strip()
            
            ports = config["common_ports"] if scan_type != "2" else config["extended_ports"]
            port_results = scan_ports(ip, ports)
            
            print(f"\n{Colors.BRIGHT_BLUE}[+] PORT SCAN RESULTS:{Colors.ENDC}")
            print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
            
            open_ports = port_results.get("open_ports", [])
            scan_results = port_results.get("scan_results", {})
            
            if open_ports:
                print(f"{Colors.YELLOW}Found {Colors.RED}{len(open_ports)}{Colors.YELLOW} open ports:{Colors.ENDC}")
                for port in open_ports:
                    service = scan_results[port]["service"]
                    print(f"{Colors.CYAN}  Port {Colors.GREEN}{port}{Colors.CYAN}: {Colors.YELLOW}{service}{Colors.ENDC}")
            else:
                print(f"{Colors.GREEN}No open ports found from scanned list{Colors.ENDC}")
            
        elif choice == "5":
            print(f"{Colors.YELLOW}Performing full security scan on {ip}...{Colors.ENDC}")
            security_data = perform_security_scan(ip)
            display_security_scan(security_data)
            
            input(f"\n{Colors.YELLOW}Press Enter to return to IP information...{Colors.ENDC}")
            display_ip_info(data)  # Return to IP info display
            
        elif choice == "6":
            print(f"{Colors.YELLOW}Performing WHOIS lookup for {ip}...{Colors.ENDC}")
            whois_result = whois_lookup(ip)
            print(f"{Colors.CYAN}{whois_result}{Colors.ENDC}")
            
        elif choice == "7":
            print(f"{Colors.YELLOW}Performing traceroute to {ip}...{Colors.ENDC}")
            traceroute_result = traceroute(ip)
            print(f"{Colors.CYAN}{traceroute_result}{Colors.ENDC}")
            
        elif choice == "8":
            print(f"\n{Colors.YELLOW}Available API providers:{Colors.ENDC}")
            for i, provider in enumerate(config["api_providers"]):
                current = " (current)" if provider == config["primary_provider"] else ""
                print(f"{Colors.CYAN}[{i+1}] {Colors.YELLOW}{provider}{current}{Colors.ENDC}")
            
            provider_choice = input(f"\n{Colors.BRIGHT_CYAN}Select provider [1-{len(config['api_providers'])}]: {Colors.GREEN}").strip()
            try:
                idx = int(provider_choice) - 1
                if 0 <= idx < len(config["api_providers"]):
                    config["primary_provider"] = config["api_providers"][idx]
                    print(f"{Colors.GREEN}API provider changed to {config['primary_provider']}{Colors.ENDC}")
                    
                    # Refresh data with new provider
                    print(f"{Colors.YELLOW}Refreshing data with new provider...{Colors.ENDC}")
                    data = get_ip_info(query)
                    display_ip_info(data)
                else:
                    print(f"{Colors.RED}Invalid selection!{Colors.ENDC}")
            except ValueError:
                print(f"{Colors.RED}Invalid input!{Colors.ENDC}")
            
        elif choice == "0":
            break
        else:
            print(f"{Colors.RED}Invalid option!{Colors.ENDC}")
            
    return main_menu()

def batch_mode():
    """Handles batch processing of multiple IPs from a file."""
    clear_screen()
    display_ascii_art("Batch Mode")
    
    file_path = input(f"{Colors.BRIGHT_CYAN}Enter path to file with IPs/domains (one per line): {Colors.GREEN}").strip()
    
    if not file_path or not os.path.exists(file_path):
        print(f"{Colors.RED}File not found: {file_path}{Colors.ENDC}")
        input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.ENDC}")
        return main_menu()
    
    formats = ["none", "json", "csv", "txt"]
    print(f"\n{Colors.YELLOW}Export formats:{Colors.ENDC}")
    print(f"{Colors.CYAN}[1] {Colors.YELLOW}Don't export (just show results){Colors.ENDC}")
    print(f"{Colors.CYAN}[2] {Colors.YELLOW}JSON{Colors.ENDC}")
    print(f"{Colors.CYAN}[3] {Colors.YELLOW}CSV{Colors.ENDC}")
    print(f"{Colors.CYAN}[4] {Colors.YELLOW}Text{Colors.ENDC}")
    
    fmt_choice = input(f"\n{Colors.BRIGHT_CYAN}Select format [1-4]: {Colors.GREEN}").strip()
    format = None
    if fmt_choice == "2":
        format = "json"
    elif fmt_choice == "3":
        format = "csv"
    elif fmt_choice == "4":
        format = "txt"
    
    deep_scan = config["deep_scan"]
    scan_choice = input(f"\n{Colors.BRIGHT_CYAN}Use deep scan? (slower but more comprehensive) [y/N]: {Colors.GREEN}").strip().lower()
    if scan_choice == 'y':
        config["deep_scan"] = True
    else:
        config["deep_scan"] = False
    
    print(f"{Colors.YELLOW}Processing IPs/domains from {file_path}...{Colors.ENDC}")
    result = batch_process(file_path, output_format=format)
    
    # Restore original deep_scan setting
    config["deep_scan"] = deep_scan
    
    if result["status"] == "success":
        clear_screen()
        display_ascii_art("Batch Results")
        
        print(f"{Colors.GREEN}Successfully processed {result['total']} entries{Colors.ENDC}")
        print(f"{Colors.GREEN}Successful: {result['successful']} | Failed: {Colors.RED}{result['failed']}{Colors.ENDC}")
        
        if format:
            print(f"{Colors.GREEN}Results saved to {result.get('filename', 'unknown')}{Colors.ENDC}")
            
        if result["results"]:
            print(f"\n{Colors.BRIGHT_BLUE}[+] RESULTS SUMMARY:{Colors.ENDC}")
            print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
            
            for i, data in enumerate(result["results"]):
                ip = data.get("query", data.get("ip", "unknown"))
                status = data.get("status", "unknown")
                country = data.get("country", "unknown")
                city = data.get("city", "unknown")
                isp = data.get("isp", data.get("org", "unknown"))
                
                status_color = Colors.GREEN if status == "success" else Colors.RED
                print(f"{Colors.CYAN}[{i+1}] {Colors.YELLOW}IP: {ip}")
                print(f"    Status: {status_color}{status}")
                
                if status == "success":
                    print(f"{Colors.YELLOW}    Location: {Colors.CYAN}{country}, {city}")
                    print(f"{Colors.YELLOW}    ISP: {Colors.CYAN}{isp}")
                else:
                    print(f"{Colors.YELLOW}    Error: {Colors.RED}{data.get('message', 'Unknown error')}")
                
                print()
    else:
        print(f"{Colors.RED}Failed to process file: {result.get('message', 'Unknown error')}{Colors.ENDC}")
    
    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.ENDC}")
    return main_menu()

def security_scan():
    """Handles security scanning of an IP."""
    clear_screen()
    display_ascii_art("Security Scan")
    
    ip = input(f"{Colors.BRIGHT_CYAN}Enter IP Address to scan: {Colors.GREEN}").strip()
    
    if not ip:
        print(f"{Colors.RED}Error: Please enter a valid IP address!{Colors.ENDC}")
        input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.ENDC}")
        return security_scan()
    
    # Validate IP
    if not validate_ip(ip):
        hostname = ip
        print(f"{Colors.YELLOW}Resolving hostname {hostname}...{Colors.ENDC}")
        ip = resolve_hostname(hostname)
        if not ip:
            print(f"{Colors.RED}Error: Could not resolve hostname {hostname}!{Colors.ENDC}")
            input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.ENDC}")
            return main_menu()
        print(f"{Colors.GREEN}Resolved to IP: {ip}{Colors.ENDC}")
    
    print(f"{Colors.YELLOW}Performing security scan on {ip}...{Colors.ENDC}")
    security_data = perform_security_scan(ip)
    display_security_scan(security_data)
    
    # Additional actions menu
    while True:
        print(f"\n{Colors.BRIGHT_YELLOW}OPTIONS:{Colors.ENDC}")
        print(f"{Colors.CYAN}[1] {Colors.YELLOW}Export scan results{Colors.ENDC}")
        print(f"{Colors.CYAN}[2] {Colors.YELLOW}View full WHOIS information{Colors.ENDC}")
        print(f"{Colors.CYAN}[3] {Colors.YELLOW}View full traceroute information{Colors.ENDC}")
        print(f"{Colors.CYAN}[4] {Colors.YELLOW}Perform new scan{Colors.ENDC}")
        print(f"{Colors.CYAN}[0] {Colors.YELLOW}Return to main menu{Colors.ENDC}")
        
        choice = input(f"\n{Colors.BRIGHT_CYAN}Select an option [0-4]: {Colors.GREEN}")
        
        if choice == "1":
            formats = ["json", "csv", "txt"]
            print(f"\n{Colors.YELLOW}Export formats:{Colors.ENDC}")
            for i, fmt in enumerate(formats):
                print(f"{Colors.CYAN}[{i+1}] {Colors.YELLOW}{fmt}{Colors.ENDC}")
            
            fmt_choice = input(f"\n{Colors.BRIGHT_CYAN}Select format [1-3] (default: json): {Colors.GREEN}").strip()
            if fmt_choice == "2":
                format = "csv"
            elif fmt_choice == "3":
                format = "txt"
            else:
                format = "json"
                
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = f"security_scan_{ip}_{timestamp}.{format}"
            
            if format == "json":
                with open(filename, 'w') as f:
                    json.dump(security_data, f, indent=4)
            elif format == "csv":
                # For CSV, we'll need to flatten the data
                with open(filename, 'w', newline='') as f:
                    flat_data = flatten_dict(security_data)
                    writer = csv.DictWriter(f, fieldnames=flat_data.keys())
                    writer.writeheader()
                    writer.writerow(flat_data)
            elif format == "txt":
                with open(filename, 'w') as f:
                    write_dict_to_txt(f, security_data)
            
            print(f"{Colors.GREEN}Scan results exported to {filename}{Colors.ENDC}")
                
        elif choice == "2":
            clear_screen()
            print(f"{Colors.BRIGHT_BLUE}[+] FULL WHOIS INFORMATION:{Colors.ENDC}")
            print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
            print(f"{Colors.CYAN}{security_data['whois']}{Colors.ENDC}")
            input(f"\n{Colors.YELLOW}Press Enter to return to scan results...{Colors.ENDC}")
            display_security_scan(security_data)
            
        elif choice == "3":
            clear_screen()
            print(f"{Colors.BRIGHT_BLUE}[+] FULL TRACEROUTE INFORMATION:{Colors.ENDC}")
            print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
            print(f"{Colors.CYAN}{security_data['traceroute']}{Colors.ENDC}")
            input(f"\n{Colors.YELLOW}Press Enter to return to scan results...{Colors.ENDC}")
            display_security_scan(security_data)
            
        elif choice == "4":
            return security_scan()
            
        elif choice == "0":
            break
        else:
            print(f"{Colors.RED}Invalid option!{Colors.ENDC}")
    
    return main_menu()

def view_history_menu():
    """Displays and manages lookup history."""
    clear_screen()
    display_ascii_art("History")
    
    if not history:
        print(f"{Colors.YELLOW}No history available{Colors.ENDC}")
        input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.ENDC}")
        return main_menu()
    
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_YELLOW}{' ' * 20}LOOKUP HISTORY{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    
    for i, entry in enumerate(history):
        ip = entry.get("ip", "unknown")
        time = entry.get("time", "unknown")
        data = entry.get("data", {})
        
        # Get some basic info for display
        status = data.get("status", "unknown")
        country = data.get("country", "unknown")
        city = data.get("city", "unknown")
        
        status_color = Colors.GREEN if status == "success" else Colors.RED
        print(f"{Colors.CYAN}[{i+1}] {Colors.YELLOW}IP: {ip} - Time: {time}")
        print(f"    Status: {status_color}{status}")
        
        if status == "success":
            print(f"{Colors.YELLOW}    Location: {Colors.CYAN}{country}, {city}")
        
        print()
    
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.CYAN}[0] {Colors.YELLOW}Return to main menu{Colors.ENDC}")
    
    choice = input(f"\n{Colors.BRIGHT_CYAN}Select entry to view details or 0 to return: {Colors.GREEN}")
    
    try:
        if choice == "0":
            return main_menu()
            
        index = int(choice) - 1
        if 0 <= index < len(history):
            display_ip_info(history[index]["data"])
            
            # After viewing details, provide additional options
            print(f"\n{Colors.BRIGHT_YELLOW}OPTIONS:{Colors.ENDC}")
            print(f"{Colors.CYAN}[1] {Colors.YELLOW}Export this entry{Colors.ENDC}")
            print(f"{Colors.CYAN}[2] {Colors.YELLOW}Refresh this lookup{Colors.ENDC}")
            print(f"{Colors.CYAN}[3] {Colors.YELLOW}Delete this entry{Colors.ENDC}")
            print(f"{Colors.CYAN}[0] {Colors.YELLOW}Return to history list{Colors.ENDC}")
            
            sub_choice = input(f"\n{Colors.BRIGHT_CYAN}Select an option [0-3]: {Colors.GREEN}")
            
            if sub_choice == "1":
                # Export entry
                formats = ["json", "csv", "txt"]
                print(f"\n{Colors.YELLOW}Export formats:{Colors.ENDC}")
                for i, fmt in enumerate(formats):
                    print(f"{Colors.CYAN}[{i+1}] {Colors.YELLOW}{fmt}{Colors.ENDC}")
                
                fmt_choice = input(f"\n{Colors.BRIGHT_CYAN}Select format [1-3] (default: json): {Colors.GREEN}").strip()
                if fmt_choice == "2":
                    format = "csv"
                elif fmt_choice == "3":
                    format = "txt"
                else:
                    format = "json"
                    
                result = export_data(history[index]["data"], format=format)
                if result["status"] == "success":
                    print(f"{Colors.GREEN}Data exported to {result['filename']}{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}Export failed: {result.get('message', 'Unknown error')}{Colors.ENDC}")
                
            elif sub_choice == "2":
                # Refresh lookup
                ip = history[index]["ip"]
                print(f"{Colors.YELLOW}Refreshing lookup for {ip}...{Colors.ENDC}")
                data = get_ip_info(ip)
                display_ip_info(data)
                
            elif sub_choice == "3":
                # Delete entry
                del history[index]
                print(f"{Colors.GREEN}Entry deleted{Colors.ENDC}")
        else:
            print(f"{Colors.RED}Invalid selection!{Colors.ENDC}")
    except ValueError:
        print(f"{Colors.RED}Invalid input!{Colors.ENDC}")
    
    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.ENDC}")
    return view_history_menu()

def settings_menu():
    """Manages application settings."""
    clear_screen()
    display_ascii_art("Settings")
    
    while True:
        print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
        print(f"{Colors.BRIGHT_YELLOW}{' ' * 25}SETTINGS{Colors.ENDC}")
        print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
        
        print(f"{Colors.CYAN}[1] {Colors.YELLOW}Slow Print: {Colors.GREEN if config['slow_print'] else Colors.RED}{config['slow_print']}{Colors.ENDC}")
        print(f"{Colors.CYAN}[2] {Colors.YELLOW}Print Delay: {Colors.GREEN}{config['print_delay']}{Colors.ENDC}")
        print(f"{Colors.CYAN}[3] {Colors.YELLOW}Show ASCII Art: {Colors.GREEN if config['show_ascii_art'] else Colors.RED}{config['show_ascii_art']}{Colors.ENDC}")
        print(f"{Colors.CYAN}[4] {Colors.YELLOW}Color Mode: {Colors.GREEN if config['color_mode'] else Colors.RED}{config['color_mode']}{Colors.ENDC}")
        print(f"{Colors.CYAN}[5] {Colors.YELLOW}Export Format: {Colors.GREEN}{config['export_format']}{Colors.ENDC}")
        print(f"{Colors.CYAN}[6] {Colors.YELLOW}Max History: {Colors.GREEN}{config['max_history']}{Colors.ENDC}")
        print(f"{Colors.CYAN}[7] {Colors.YELLOW}Request Timeout: {Colors.GREEN}{config['timeout']}{Colors.ENDC}")
        print(f"{Colors.CYAN}[8] {Colors.YELLOW}Deep Scan: {Colors.GREEN if config['deep_scan'] else Colors.RED}{config['deep_scan']}{Colors.ENDC}")
        print(f"{Colors.CYAN}[9] {Colors.YELLOW}Set Proxy: {Colors.GREEN}{config['proxy'] or 'None'}{Colors.ENDC}")
        print(f"{Colors.CYAN}[10] {Colors.YELLOW}Manage API Keys{Colors.ENDC}")
        print(f"{Colors.CYAN}[11] {Colors.YELLOW}Primary API Provider: {Colors.GREEN}{config['primary_provider']}{Colors.ENDC}")
        print(f"{Colors.CYAN}[0] {Colors.YELLOW}Return to Main Menu{Colors.ENDC}")
        
        choice = input(f"\n{Colors.BRIGHT_CYAN}Select setting to change [0-11]: {Colors.GREEN}")
        
        if choice == "1":
            config["slow_print"] = not config["slow_print"]
        elif choice == "2":
            try:
                new_delay = float(input(f"{Colors.BRIGHT_CYAN}Enter new delay (e.g. 0.03): {Colors.GREEN}"))
                if 0 <= new_delay <= 0.1:
                    config["print_delay"] = new_delay
                else:
                    print(f"{Colors.RED}Delay must be between 0 and 0.1{Colors.ENDC}")
            except ValueError:
                print(f"{Colors.RED}Invalid input!{Colors.ENDC}")
        elif choice == "3":
            config["show_ascii_art"] = not config["show_ascii_art"]
        elif choice == "4":
            config["color_mode"] = not config["color_mode"]
            if not config["color_mode"]:
                Colors.disable()
        elif choice == "5":
            formats = ["json", "csv", "txt"]
            for i, fmt in enumerate(formats):
                print(f"{Colors.CYAN}  [{i+1}] {Colors.YELLOW}{fmt}{Colors.ENDC}")
            try:
                format_choice = int(input(f"{Colors.BRIGHT_CYAN}Select format [1-3]: {Colors.GREEN}"))
                if 1 <= format_choice <= len(formats):
                    config["export_format"] = formats[format_choice - 1]
                else:
                    print(f"{Colors.RED}Invalid selection!{Colors.ENDC}")
            except ValueError:
                print(f"{Colors.RED}Invalid input!{Colors.ENDC}")
        elif choice == "6":
            try:
                new_max = int(input(f"{Colors.BRIGHT_CYAN}Enter new max history size: {Colors.GREEN}"))
                if 0 <= new_max <= 100:
                    config["max_history"] = new_max
                else:
                    print(f"{Colors.RED}Max history must be between 0 and 100{Colors.ENDC}")
            except ValueError:
                print(f"{Colors.RED}Invalid input!{Colors.ENDC}")
        elif choice == "7":
            try:
                new_timeout = int(input(f"{Colors.BRIGHT_CYAN}Enter new timeout in seconds: {Colors.GREEN}"))
                if 1 <= new_timeout <= 30:
                    config["timeout"] = new_timeout
                else:
                    print(f"{Colors.RED}Timeout must be between 1 and 30 seconds{Colors.ENDC}")
            except ValueError:
                print(f"{Colors.RED}Invalid input!{Colors.ENDC}")
        elif choice == "8":
            config["deep_scan"] = not config["deep_scan"]
        elif choice == "9":
            proxy = input(f"{Colors.BRIGHT_CYAN}Enter proxy (format: http://host:port) or 'none' to disable: {Colors.GREEN}")
            if proxy.lower() == 'none':
                config["proxy"] = None
            elif re.match(r'^https?://\S+:\d+$', proxy):
                config["proxy"] = proxy
            else:
                print(f"{Colors.RED}Invalid proxy format!{Colors.ENDC}")
        elif choice == "10":
            manage_api_keys()
        elif choice == "11":
            print(f"\n{Colors.YELLOW}Available API providers:{Colors.ENDC}")
            for i, provider in enumerate(config["api_providers"]):
                current = " (current)" if provider == config["primary_provider"] else ""
                print(f"{Colors.CYAN}[{i+1}] {Colors.YELLOW}{provider}{current}{Colors.ENDC}")
            
            provider_choice = input(f"\n{Colors.BRIGHT_CYAN}Select provider [1-{len(config['api_providers'])}]: {Colors.GREEN}").strip()
            try:
                idx = int(provider_choice) - 1
                if 0 <= idx < len(config["api_providers"]):
                    config["primary_provider"] = config["api_providers"][idx]
                    print(f"{Colors.GREEN}Primary API provider changed to {config['primary_provider']}{Colors.ENDC}")
                else:
                    print(f"{Colors.RED}Invalid selection!{Colors.ENDC}")
            except ValueError:
                print(f"{Colors.RED}Invalid input!{Colors.ENDC}")
        elif choice == "0":
            break
        else:
            print(f"{Colors.RED}Invalid option!{Colors.ENDC}")
        
        # Refresh screen
        time.sleep(1)
        clear_screen()
        display_ascii_art("Settings")
    
    return main_menu()

def manage_api_keys():
    """Manages API keys for various services."""
    clear_screen()
    display_ascii_art("API Keys")
    
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_YELLOW}{' ' * 23}API KEYS{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    
    print(f"{Colors.YELLOW}Current API Keys:{Colors.ENDC}")
    for provider, key in API_KEYS.items():
        masked_key = "Not set" if not key else key[:4] + "*" * (len(key) - 8) + key[-4:] if len(key) > 8 else "*" * len(key)
        print(f"{Colors.CYAN}[{provider}] {Colors.GREEN}{masked_key}{Colors.ENDC}")
    
    print(f"\n{Colors.YELLOW}Choose a provider to update:{Colors.ENDC}")
    for i, provider in enumerate(API_KEYS.keys(), 1):
        print(f"{Colors.CYAN}[{i}] {Colors.YELLOW}{provider}{Colors.ENDC}")
    print(f"{Colors.CYAN}[0] {Colors.YELLOW}Return to Settings{Colors.ENDC}")
    
    choice = input(f"\n{Colors.BRIGHT_CYAN}Select provider [0-{len(API_KEYS)}]: {Colors.GREEN}")
    
    try:
        if choice == "0":
            return
            
        idx = int(choice) - 1
        providers = list(API_KEYS.keys())
        if 0 <= idx < len(providers):
            provider = providers[idx]
            new_key = input(f"{Colors.BRIGHT_CYAN}Enter new API key for {provider} (leave empty to clear): {Colors.GREEN}")
            API_KEYS[provider] = new_key.strip()
            print(f"{Colors.GREEN}API key for {provider} updated{Colors.ENDC}")
        else:
            print(f"{Colors.RED}Invalid selection!{Colors.ENDC}")
    except ValueError:
        print(f"{Colors.RED}Invalid input!{Colors.ENDC}")
    
    input(f"\n{Colors.YELLOW}Press Enter to continue...{Colors.ENDC}")
    return manage_api_keys()

def about():
    """Displays information about the application."""
    clear_screen()
    display_ascii_art("About")
    
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_YELLOW}{' ' * 25}ABOUT{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    
    print(f"{Colors.YELLOW}Enhanced IPInfo Tool v{VERSION}{Colors.ENDC}")
    print(f"{Colors.YELLOW}Last Updated: {UPDATE_DATE}{Colors.ENDC}")
    print(f"{Colors.YELLOW}Author: {AUTHOR}{Colors.ENDC}")
    print(f"{Colors.YELLOW}GitHub: {GITHUB}{Colors.ENDC}")
    
    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_YELLOW}{' ' * 18}TOOL DESCRIPTION{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    
    description = """
Enhanced IPInfo is a comprehensive IP and domain information gathering tool.
It provides detailed information about IP addresses, domains, and URLs,
including geolocation, network details, security insights, and more.

The tool supports multiple API providers for information gathering and
offers features like batch processing, port scanning, security analysis,
and export capabilities.
    """
    print(f"{Colors.CYAN}{description}{Colors.ENDC}")
    
    print(f"\n{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    print(f"{Colors.BRIGHT_YELLOW}{' ' * 22}API CREDITS{Colors.ENDC}")
    print(f"{Colors.CYAN}{'=' * 60}{Colors.ENDC}")
    
    print(f"{Colors.CYAN}This tool uses the following API services:{Colors.ENDC}")
    print(f"{Colors.CYAN}- ip-api.com{Colors.ENDC}")
    print(f"{Colors.CYAN}- ipinfo.io{Colors.ENDC}")
    print(f"{Colors.CYAN}- ipgeolocation.io{Colors.ENDC}")
    print(f"{Colors.CYAN}- ipdata.co{Colors.ENDC}")
    print(f"{Colors.CYAN}- abuseipdb.com{Colors.ENDC}")
    print(f"{Colors.CYAN}- shodan.io{Colors.ENDC}")
    
    print(f"\n{Colors.YELLOW}Note: Some features may require API keys for full functionality.{Colors.ENDC}")
    
    input(f"\n{Colors.YELLOW}Press Enter to return to main menu...{Colors.ENDC}")
    return main_menu()

def main():
    """Main entry point for the application."""
    try:
        # Parse command-line arguments
        parser = argparse.ArgumentParser(description='Enhanced IPInfo Tool')
        parser.add_argument('-i', '--ip', help='IP address or hostname to lookup')
        parser.add_argument('-b', '--batch', help='Path to file with IPs for batch processing')
        parser.add_argument('-e', '--export', help='Export format (json, csv, txt)')
        parser.add_argument('-s', '--scan', action='store_true', help='Perform security scan')
        parser.add_argument('-q', '--quick', action='store_true', help='Quick mode (minimal output)')
        parser.add_argument('-nc', '--no-color', action='store_true', help='Disable color output')
        parser.add_argument('-nd', '--no-deep', action='store_true', help='Disable deep scanning')
        parser.add_argument('-v', '--version', action='store_true', help='Show version information')
        
        args = parser.parse_args()
        
        # Handle version information
        if args.version:
            print(f"Enhanced IPInfo Tool v{VERSION}")
            print(f"Last Updated: {UPDATE_DATE}")
            print(f"Author: {AUTHOR}")
            print(f"GitHub: {GITHUB}")
            sys.exit(0)
        
        # Apply command-line settings
        if args.no_color:
            config["color_mode"] = False
            Colors.disable()
        
        if args.no_deep:
            config["deep_scan"] = False
        
        if args.quick:
            config["slow_print"] = False
            config["show_ascii_art"] = False
        
        # Handle command-line operations
        if args.ip:
            # Single IP lookup
            data = get_ip_info(args.ip)
            
            if args.scan:
                security_data = perform_security_scan(args.ip)
                display_security_scan(security_data)
            else:
                display_ip_info(data)
            
            if args.export:
                if args.export.lower() in ['json', 'csv', 'txt']:
                    export_data(data, format=args.export.lower())
                else:
                    print(f"Invalid export format: {args.export}")
            
            sys.exit(0)
            
        elif args.batch:
            # Batch processing
            if not os.path.exists(args.batch):
                print(f"File not found: {args.batch}")
                sys.exit(1)
                
            export_format = args.export if args.export and args.export.lower() in ['json', 'csv', 'txt'] else None
            result = batch_process(args.batch, output_format=export_format)
            
            if result["status"] == "success":
                print(f"Successfully processed {result['total']} entries")
                print(f"Successful: {result['successful']} | Failed: {result['failed']}")
                
                if export_format:
                    print(f"Results saved to {result.get('filename', 'unknown')}")
            else:
                print(f"Failed to process file: {result.get('message', 'Unknown error')}")
                
            sys.exit(0)
        
        # If no command-line operations, start interactive mode
        return main_menu()
        
    except KeyboardInterrupt:
        print(f"\n{Colors.BRIGHT_GREEN}Thank you for using Enhanced IPInfo!{Colors.ENDC}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}An error occurred: {str(e)}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
