# IP-Info Tool v2.0

## Description
IP-Info is a powerful and feature-rich Python tool for gathering detailed information about IP addresses and hostnames. The tool provides comprehensive geolocation data, network diagnostics, and allows for both interactive and batch processing modes.

## Features
- **IP Geolocation**: Get detailed information about any IP address or hostname
- **Multiple API Providers**: Switch between different geolocation data providers
- **Network Tools**: Integrated ping, traceroute, WHOIS lookup, and port scanning
- **Batch Processing**: Process multiple IPs from a file in one go
- **Export Options**: Save results in JSON, CSV, or TXT formats
- **Visual Maps**: View IP locations directly on Google Maps
- **History Tracking**: Access previously looked up IPs
- **Customizable Settings**: Configure display preferences and tool behavior
- **Proxy Support**: Route requests through a proxy
- **Command-line Interface**: Run queries directly from terminal

## Requirements
- Python 3.6+
- Required modules:
  - os, sys, time, socket, re, json, csv, datetime, argparse
  - urllib.request (standard library)
  - ipaddress (standard library)
  - webbrowser (standard library)
  - requests (optional)

### Optional Dependencies
- `figlet`: For ASCII art headers
- `lolcat`: For colorful ASCII art

## Installation

1. Clone the repository or download the script:
```bash
git clone https://github.com/NebulaStudioTM/ipinfo.git
cd ipinfo
```

2. Install required Python packages:
```bash
pip install -r requirements.txt
```

3. Make the script executable (Linux/Mac):
```bash
chmod +x ipinfo.py
```

## Usage

### Interactive Mode
```bash
python ipinfo.py
```

### Command-line Mode
Lookup a single IP:
```bash
python ipinfo.py -i 8.8.8.8
```

Process multiple IPs from a file:
```bash
python ipinfo.py -b ips.txt -o results.json -f json
```

### Command-line Options
```
-i, --ip        IP address or hostname to look up
-b, --batch     Path to file with IPs to process in batch mode
-o, --output    Output file for results
-f, --format    Output format (json, csv, txt)
-p, --provider  API provider (ip-api, ipinfo, ipgeolocation)
-nc, --no-color Disable colored output
-ns, --no-slow  Disable slow printing effect
```

## Interactive Menu Options

1. **Scan IP Address**: Look up information for a single IP or hostname
2. **Batch Process**: Process multiple IPs from a file
3. **View History**: See previously looked up IPs
4. **Settings**: Configure tool preferences
5. **About**: Information about the tool
0. **Exit**: Quit the program

### IP Information Features
After looking up an IP, you can:
- Export data to a file (JSON, CSV, TXT)
- View the location on Google Maps
- Ping the IP address
- Run a traceroute
- Perform a WHOIS lookup
- Scan common ports
- Change the API provider

## Settings
- **Slow Print**: Enable/disable text animation
- **Print Delay**: Adjust animation speed
- **Show ASCII Art**: Enable/disable ASCII headers
- **Color Mode**: Enable/disable colored output
- **API Provider**: Select data source
- **Export Format**: Default format for exports
- **Max History**: Number of IPs to remember
- **Request Timeout**: API request timeout
- **Set Proxy**: Route requests through a proxy

## Sample Output
```
 =====================================
|            IP Information           |
 =====================================
 IP          :  8.8.8.8
 Status      :  success
 Region      :  California
 Country     :  United States
 Date & Time :  2025-04-06 12:34:56
 City        :  Mountain View
 ISP         :  Google LLC
 Lat,Lon     :  37.4056, -122.0775
 ZIPCODE     :  94043
 TimeZone    :  America/Los_Angeles
 AS          :  AS15169 Google LLC

 =====================================
|        By Bobi.exe & NebulaStudioTM        |
 =====================================
|  https://github.com/NebulaStudioTM/ |
 =====================================

What would you like to do next?
[1] Export data to file
[2] View on map
[3] Ping IP
[4] Traceroute
[5] WHOIS lookup
[6] Port scan (common ports)
[7] Change API provider
[0] Return to main menu
```

## Author
- **Created by**: Bobi.exe & NebulaStudioTM
- **Version**: 2.0
- **Last Updated**: 06/04/2025
- **GitHub**: [NebulaStudioTM](https://github.com/NebulaStudioTM/)

## License
This tool is provided for educational and research purposes only. Use responsibly and respect privacy laws and terms of service for the APIs used.
