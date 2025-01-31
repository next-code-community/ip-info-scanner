#!/bin/bash

# Colori ANSI per una migliore leggibilità
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
RED='\033[1;91m'
NC='\033[0m' # Reset colore

# Funzione per controllare errori
check_error() {
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] Error encountered during installation. Exiting...${NC}"
        exit 1
    fi
}

echo -e "${CYAN}Updating system and installing dependencies...${NC}"

# Aggiorna e installa pacchetti necessari
apt update && apt upgrade -y && apt install -y python3 ruby lolcat
check_error

# Installa il gemma lolcat
gem install lolcat
check_error

# Messaggio di completamento
echo -e "\n${GREEN}Installation completed successfully!${NC}"
echo -e "${CYAN} ============================================== ${NC}"
echo -e "${YELLOW}|      Now Type: ${GREEN}python3 ipinfo.py      ${YELLOW}|${NC}"
echo -e "${CYAN} ============================================== ${NC}"
