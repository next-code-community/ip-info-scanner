#!/bin/bash

# Colori ANSI per una migliore leggibilità
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
RED='\033[1;91m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
NC='\033[0m' # Reset colore

# Banner
display_banner() {
    echo -e "${CYAN}"
    echo -e "╔═══════════════════════════════════════════╗"
    echo -e "║          ${YELLOW}IP-Info Installer v2.0${CYAN}           ║"
    echo -e "║      ${GREEN}By Bobi.exe & NebulaStudioTM${CYAN}      ║"
    echo -e "╚═══════════════════════════════════════════╝${NC}"
    echo ""
}

# Funzione per controllare errori
check_error() {
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Error encountered during installation. Exiting...${NC}"
        exit 1
    fi
}

# Funzione per controllare se il comando esiste
command_exists() {
    command -v "$1" &> /dev/null
}

# Funzione per controllare i requisiti di sistema
check_requirements() {
    echo -e "${BLUE}[*] Checking system requirements...${NC}"
    
    # Controlla se lo script è eseguito come root
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}[!] This script must be run as root!${NC}"
        echo -e "${YELLOW}[+] Please run: sudo ./install.sh${NC}"
        exit 1
    fi
    
    # Controlla sistema operativo
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        echo -e "${GREEN}[+] Detected OS: $OS${NC}"
    else
        echo -e "${YELLOW}[!] Could not determine OS, continuing anyway...${NC}"
    fi
    
    echo -e "${GREEN}[+] System requirements met.${NC}"
}

# Funzione per installare dipendenze
install_dependencies() {
    echo -e "\n${BLUE}[*] Installing required packages...${NC}"

    # Aggiorna repository
    echo -e "${YELLOW}[+] Updating package repositories...${NC}"
    apt update
    check_error
    
    # Installa pacchetti Python e utility
    echo -e "${YELLOW}[+] Installing Python and required utilities...${NC}"
    apt install -y python3 python3-pip figlet ruby curl whois traceroute
    check_error
    
    # Installa lolcat
    echo -e "${YELLOW}[+] Installing lolcat...${NC}"
    if ! command_exists lolcat; then
        gem install lolcat
        check_error
    else
        echo -e "${GREEN}[+] lolcat already installed.${NC}"
    fi
    
    # Installa moduli Python
    echo -e "${YELLOW}[+] Installing Python modules...${NC}"
    pip3 install requests ipaddress argparse
    check_error
    
    echo -e "${GREEN}[+] All dependencies installed successfully.${NC}"
}

# Funzione per configurare IP-Info
configure_ipinfo() {
    echo -e "\n${BLUE}[*] Configuring IP-Info...${NC}"
    
    # Rendi eseguibile lo script Python
    chmod +x ipinfo.py
    check_error
    
    # Crea link simbolico (opzionale)
    echo -e "${YELLOW}[+] Creating symbolic link for easier access...${NC}"
    if [ -f /usr/local/bin/ipinfo ]; then
        rm /usr/local/bin/ipinfo
    fi
    ln -s "$(pwd)/ipinfo.py" /usr/local/bin/ipinfo
    check_error
    
    echo -e "${GREEN}[+] IP-Info configured successfully.${NC}"
}

# Funzione principale
main() {
    display_banner
    check_requirements
    
    echo -e "${MAGENTA}[?] Do you want to perform a full installation? (y/n)${NC}"
    read -r response
    
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        install_dependencies
        configure_ipinfo
    else
        echo -e "${YELLOW}[+] Skipping installation. Make sure to install required dependencies manually.${NC}"
    fi
    
    # Messaggio di completamento
    echo -e "\n${GREEN}[+] Installation completed successfully!${NC}"
    echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  ${YELLOW}Now you can run IP-Info using:${NC}               ${CYAN}║${NC}"
    echo -e "${CYAN}║  ${GREEN}python3 ipinfo.py${NC}                            ${CYAN}║${NC}"
    echo -e "${CYAN}║  ${GREEN}or simply: ipinfo${NC}                            ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
    echo -e "${BLUE}[*] For more information, see the README.md file.${NC}"
}

# Esegui la funzione principale
main
