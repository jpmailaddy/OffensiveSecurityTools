# OffensiveSecurityTools

## Requires the following tools:

- httpx
- subfinder
- shuffledns
- AltDNS
- MassDNS
- gobuster
- jq
- EyeWitness (if you want screenshots)
- Seclists (looks for this directory: /usr/share/wordlists/SecLists/Discovery/DNS)
- Resolvers_trusted.txt file in the 'shuffledns' folder

## Getting it to run: 

The one finicky thing about this is it wants the shuffledns folder in the same directory. Go to https://github.com/projectdiscovery/shuffledns/releases and download the latest package into the same folder where you put the Subdomain_script.sh, extract the zip file there and rename the folder 'shuffledns'. 

## Usage

./Subdomain_script --help

Usage: ./Subdomain_script.sh [OPTIONS]
  --ss              Enable Eyewitness screenshots
  -d DOMAIN         Target domain
  -h                Help

