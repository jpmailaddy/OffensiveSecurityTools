# OffensiveSecurityTools

## Requires the following tools:

- httpx
- subfinder
- shuffledns
- AltDNS
- MassDNS
- EyeWitness (if you want screenshots)
- Seclists (looks for this directory: /usr/share/wordlists/SecLists/Discovery/DNS)

## Getting it to run: 

The one finicky thing about this is it wants the shuffledns folder in the same directory. Use the following command to install shuffledns in the same place you put 'Subdomain_script.sh'

go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest

## Usage

./Subdomain_script --help

Usage: ./Subdomain_script.sh [OPTIONS]
  --ss              Enable Eyewitness screenshots
  -d DOMAIN         Target domain
  -h                Help

