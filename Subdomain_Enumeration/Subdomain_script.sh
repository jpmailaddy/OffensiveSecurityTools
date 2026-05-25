#!/bin/bash

# Subdomain Enumeration Script
# Integrated: Subfinder, crt.sh, Altdns, MassDNS, httpx, Eyewitness

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
log() { echo -e "${GREEN}[+]${NC} $(date '+%H:%M:%S') - $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $(date '+%H:%M:%S') - $1"; }
error() { echo -e "${RED}[-]${NC} $(date '+%H:%M:%S') - $1"; }
info() { echo -e "${BLUE}[i]${NC} $(date '+%H:%M:%S') - $1"; }

# Arguments
SCREENSHOT_MODE=false
TARGET_DOMAIN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --ss|--screenshots) SCREENSHOT_MODE=true; shift ;;
        -d|--domain) TARGET_DOMAIN="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo "  --ss              Enable Eyewitness screenshots"
            echo "  -d DOMAIN         Target domain"
            echo "  -h                Help"
            exit 0 ;;
        *) if [ -z "$TARGET_DOMAIN" ]; then TARGET_DOMAIN="$1"; fi; shift ;;
    esac
done

if [ -z "$TARGET_DOMAIN" ]; then
    read -p "Enter domain: " TARGET_DOMAIN
fi
TARGET_DOMAIN=$(echo "$TARGET_DOMAIN" | sed 's|https://||' | sed 's|http://||' | sed 's|/||g')

log "Target: $TARGET_DOMAIN"
mkdir -p Results

# --- DEPENDENCY CHECKS ---
check_dep() {
    if ! command -v "$1" >/dev/null 2>&1; then
        warn "$1 not found. Install it or skip this module."
        return 1
    fi
    log "✓ $1 ready"
    return 0
}

log "Checking tools..."
check_dep "gobuster"
check_dep "massdns"
check_dep "httpx"
check_dep "subfinder" || SUBFINDER_MISSING=true
check_dep "altdns" || ALTDNS_MISSING=true
check_dep "jq" || JQ_MISSING=true

if [ "$SCREENSHOT_MODE" = true ]; then
    if ! command -v eyewitness >/dev/null 2>&1; then
        error "Eyewitness not found in PATH. Aborting screenshot mode."
        exit 1
    fi
    log "✓ Eyewitness ready"
fi

# --- WORDLISTS & RESOLVERS ---

# Default paths (will be overwritten by selection)
WORDLIST1=""
WORDLIST2=""
ALTDNS_WORDS="/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"

RESOLVER_FILE="shuffledns/resolvers_trusted.txt"
[ ! -f "$RESOLVER_FILE" ] && RESOLVER_FILE="/usr/share/massdns/resolvers.txt"

# Wordlist Options
WL_SMALL_1="/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
WL_BIG_1="/usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-20000.txt"

WL_SMALL_2="/usr/share/wordlists/SecLists/Discovery/DNS/fierce-hostlist.txt"
WL_BIG_2="/usr/share/wordlists/SecLists/Discovery/DNS/shubs-subdomains.txt"
WL_HUGE_2="/usr/share/wordlists/SecLists/Discovery/DNS/dns-Jhaddix.txt"

# Interactive Selection
log "Select wordlist size for Active Brute-Force:"
echo "  1) Small (Fast, ~5k-10k entries)"
echo "  2) Big (Balanced, ~20k entries)"
echo "  3) Huge (Comprehensive, ~100k+ entries)"
read -p "Choose option [1-3]: " WL_OPTION

case "$WL_OPTION" in
    1)
        log "Using Small wordlists."
        WORDLIST1="$WL_SMALL_1"
        WORDLIST2="$WL_SMALL_2"
        ;;
    2)
        log "Using Big wordlists."
        WORDLIST1="$WL_BIG_1"
        WORDLIST2="$WL_BIG_2"
        ;;
    3)
        log "Using Huge wordlists (Warning: This will take significantly longer, but it is Jason Haddix's wordlist so...)."
        WORDLIST1="$WL_BIG_1"
        WORDLIST2="$WL_HUGE_2"
        ;;
    *)
        error "Invalid option. Defaulting to Small."
        WORDLIST1="$WL_SMALL_1"
        WORDLIST2="$WL_SMALL_2"
        ;;
esac

# Validate selected wordlists
if [ ! -f "$WORDLIST1" ]; then
    error "Wordlist 1 not found: $WORDLIST1"
    error "Please ensure SecLists is installed or the path is correct."
    exit 1
fi

if [ ! -f "$WORDLIST2" ]; then
    warn "Wordlist 2 not found: $WORDLIST2"
    warn "Attempting to fallback to Wordlist 1 for Gobuster."
    WORDLIST2="$WORDLIST1"
fi

# --- CLEANUP ---
rm -f subfinder_out.txt crtsh_out.txt altdns_out.txt final_step.txt subdomain_step*.txt subdomain_massdns*.txt final_found.txt "$TARGET_DOMAIN"_final_*.txt 2>/dev/null

# ==========================================
# PHASE 1: PASSIVE ENUMERATION (OSINT)
# ==========================================
log "=== PHASE 1: Passive Enumeration ==="

# 1. Subfinder
if [ "$SUBFINDER_MISSING" != true ]; then
    log "Running Subfinder..."
    subfinder -d "$TARGET_DOMAIN" -silent -all -o subfinder_out.txt 2>/dev/null
    
    if [ -s subfinder_out.txt ]; then
        subfinder_count=$(wc -l < subfinder_out.txt)
        log "Subfinder found $subfinder_count subdomains"
        cat subfinder_out.txt >> final_step.txt
    else
        warn "Subfinder found nothing."
    fi
else
    warn "Skipping Subfinder (not installed)."
fi

# 2. crt.sh (Certificate Transparency)
log "Querying crt.sh..."
if [ "$JQ_MISSING" != true ]; then
    # Using jq for robust JSON parsing
    # Query crt.sh API, extract 'name_value' field, filter duplicates
    curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" | \
        jq -r '.[].name_value' 2>/dev/null | \
        tr ',' '\n' | \
        grep -v '^*$' | \
        sort -u > crtsh_out.txt
    
    crtsh_count=$(wc -l < crtsh_out.txt)
    log "✓ crt.sh found $crtsh_count subdomains"
    cat crtsh_out.txt >> final_step.txt
else
    # Fallback if jq is missing (using grep/sed)
    warn "jq not found. Attempting basic parsing (less reliable)..."
    curl -s "https://crt.sh/?q=%25.$TARGET_DOMAIN&output=json" | \
        grep -o '"name_value"[[:space:]]*:[[:space:]]*"[^"]*"' | \
        sed 's/"name_value"[[:space:]]*:[[:space:]]*"//g' | \
        sed 's/"$//g' | \
        tr ',' '\n' | \
        grep -v '^*$' | \
        sort -u > crtsh_out.txt
    
    crtsh_count=$(wc -l < crtsh_out.txt)
    log "crt.sh (basic) found $crtsh_count subdomains"
    cat crtsh_out.txt >> final_step.txt
fi

# ==========================================
# PHASE 2: ACTIVE BRUTE-FORCE
# ==========================================
log "=== PHASE 2: Active Brute-Force ==="

# ShuffleDNS (if available)
if [ -d "./shuffledns" ] && [ -f "./shuffledns/shuffledns" ]; then
    log "Running ShuffleDNS..."
    ./shuffledns/shuffledns -d "$TARGET_DOMAIN" -r "$RESOLVER_FILE" -mode bruteforce -w "$WORDLIST1" >> subdomain_step.txt 2>&1 &
    SHUFFLE_PID=$!
fi

# Gobuster
log "Running Gobuster..."
gobuster dns -w "$WORDLIST2" --domain "$TARGET_DOMAIN" -t 10 -o subdomain_step2.txt 2>&1 &
GOBUSTER_PID=$!

wait $GOBUSTER_PID 2>/dev/null
[ -n "$SHUFFLE_PID" ] && wait $SHUFFLE_PID 2>/dev/null

# Merge active results
{
    cat subdomain_step.txt 2>/dev/null
    cat subdomain_step2.txt 2>/dev/null
} | grep -v "^$" | grep -v "No entries" >> final_step.txt

active_count=$(grep -c "." final_step.txt 2>/dev/null || echo "0")
log "Active brute-force added $active_count candidates"

# ==========================================
# PHASE 3: SAFE PERMUTATION (ALTDNS)
# ==========================================
log "=== PHASE 3: Safe Permutation (Altdns) ==="

# Define MAX_OUTPUT BEFORE any altdns calls
MAX_OUTPUT=50000

if [ "$ALTDNS_MISSING" = true ]; then
    warn "Skipping Altdns (not installed)."
elif [ ! -s final_step.txt ]; then
    warn "Skipping Altdns (no input data)."
else
    log "Filtering input for high-value targets..."
    
    # 1. FILTER INPUT: Only process subdomains that look like they might have variants
    KEYWORDS="dev|test|staging|uat|beta|alpha|new|old|app|api|web|portal|admin|manage|devops|ci|cd|jenkins|gitlab|docker|k8s|aws|azure|cloud|demo|prod|dr|colo"
    
    # Create a filtered input file with additional constraints
    grep -iE "$KEYWORDS" final_step.txt | \
        awk 'length($0) < 50' > altdns_filtered_input.txt 2>/dev/null || true
    
    # Limit input size to prevent combinatorial explosion
    input_count=$(wc -l < altdns_filtered_input.txt 2>/dev/null || echo "0")
    
    if [ "$input_count" -gt 500 ]; then
        warn "Input has $input_count subdomains (too many for altdns). Limiting to 500."
        head -n 500 altdns_filtered_input.txt > altdns_filtered_input_limited.txt
        mv altdns_filtered_input_limited.txt altdns_filtered_input.txt
        input_count=500
    fi
    
    if [ "$input_count" -eq 0 ]; then
        warn "No 'high-value' subdomains found for permutation. Skipping Altdns."
    else
        log "Found $input_count high-value candidates for permutation."
        
        # 2. PREPARE WORDLIST (keep it small)
        SMALL_WORDLIST="/tmp/altdns_small_words.txt"
        if [ ! -f "$ALTDNS_WORDS" ]; then
            echo -e "dev\ntest\nstaging\nprod\nuat\nbeta\nalpha\nnew\nold\napp\napi\nweb\nwww\nv1\nv2\nv3\ninternal\nexternal" > "$SMALL_WORDLIST"
            ALTDNS_WORDS="$SMALL_WORDLIST"
        fi

        # 3. RUN ALTDNS WITH STREAMING OUTPUT (CRITICAL FIX)
        log "Running Altdns (streaming output, max $MAX_OUTPUT lines)..."
        
        # Pipe directly to head - this prevents disk bloat
        timeout 600 altdns -i altdns_filtered_input.txt -o /dev/stdout -w "$ALTDNS_WORDS" 2>/dev/null | \
            head -n "$MAX_OUTPUT" > altdns_out.txt
        
        # Check if we hit the limit
        actual_lines=$(wc -l < altdns_out.txt 2>/dev/null || echo "0")
        
        if [ "$actual_lines" -eq "$MAX_OUTPUT" ]; then
            warn "Reached output limit ($MAX_OUTPUT lines). Results truncated."
        fi
        
        final_count=$(wc -l < altdns_out.txt 2>/dev/null || echo "0")
        log "Altdns generated $final_count safe permutations."
        
        # Merge into main list
        cat altdns_out.txt >> final_step.txt
    fi
fi

# Clean up temp files
rm -f altdns_filtered_input.txt 2>/dev/null

# ==========================================
# PHASE 4: DEDUPLICATION & VALIDATION
# ==========================================
log "=== PHASE 4: Deduplication & Validation ==="

# Sort and unique
sort -u final_step.txt -o final_step.txt
total_candidates=$(wc -l < final_step.txt)
log "Total unique candidates: $total_candidates"

if [ "$total_candidates" -eq 0 ]; then
    error "No candidates found. Exiting."
    exit 1
fi

log "Running MassDNS..."
timeout 300 massdns -r "$RESOLVER_FILE" -t A -o S -w subdomain_massdns.txt final_step.txt

# Parse MassDNS
grep -v "NXDOMAIN" subdomain_massdns.txt 2>/dev/null | \
    grep -v "^$" | \
    awk '{print $1}' | \
    sed 's/\.$//' | \
    sort -u > subdomain_massdns2.txt

valid_count=$(wc -l < subdomain_massdns2.txt)
log "Validated subdomains: $valid_count"

# ==========================================
# PHASE 5: HTTP PROBE & SCREENSHOTS
# ==========================================
log "=== PHASE 5: HTTP Probing ==="

if [ "$valid_count" -gt 0 ]; then
    httpx -sc -cl --title -l subdomain_massdns2.txt -o final_found.txt 2>&1
    
    # Categorize
    grep -a '200' final_found.txt 2>/dev/null | cut -d "[" -f 1 | awk -F "https://" '{print $2}' | sort -u > "$TARGET_DOMAIN"_final_200.txt
    grep -a '30[0-9]' final_found.txt 2>/dev/null | cut -d "[" -f 1 | awk -F "https://" '{print $2}' | sort -u > "$TARGET_DOMAIN"_final_301.txt
    grep -a '40[0-9]' final_found.txt 2>/dev/null | cut -d "[" -f 1 | awk -F "https://" '{print $2}' | sort -u > "$TARGET_DOMAIN"_final_401.txt
    
    c200=$(wc -l < "$TARGET_DOMAIN"_final_200.txt 2>/dev/null || echo "0")
    c301=$(wc -l < "$TARGET_DOMAIN"_final_301.txt 2>/dev/null || echo "0")
    c401=$(wc -l < "$TARGET_DOMAIN"_final_401.txt 2>/dev/null || echo "0")
    
    log "HTTP 200: $c200 | 301: $c301 | 401: $c401"
fi

# Screenshots
if [ "$SCREENSHOT_MODE" = true ] && [ "$valid_count" -gt 0 ]; then
    log "=== PHASE 6: Eyewitness Screenshots ==="
    mkdir -p Results/screenshots
    
    # Prepare input (ensure https://)
    sed 's/^/https:\/\//g' subdomain_massdns2.txt > Results/"$TARGET_DOMAIN"_ew_input.txt
    
    log "Launching Eyewitness..."
    timeout 600 eyewitness -f Results/"$TARGET_DOMAIN"_ew_input.txt -d Results/screenshots/"$TARGET_DOMAIN" --no-dns --no-prompt 2>&1
    
    s_count=$(find Results/screenshots/"$TARGET_DOMAIN" -name "*.png" 2>/dev/null | wc -l)
    if [ "$s_count" -gt 0 ]; then
        log "Captured $s_count screenshots"
        log "Report: Results/screenshots/$TARGET_DOMAIN/report.html"
    else
        warn "No screenshots captured."
    fi
fi

# ==========================================
# FINAL CLEANUP & ORGANIZATION
# ==========================================
log "Organizing results into Results/..."

# Move all domain-specific result files
mv "$TARGET_DOMAIN"_final_200.txt Results/ 2>/dev/null
mv "$TARGET_DOMAIN"_final_301.txt Results/ 2>/dev/null
mv "$TARGET_DOMAIN"_final_401.txt Results/ 2>/dev/null
mv final_found.txt Results/"$TARGET_DOMAIN"_all_http.txt 2>/dev/null
mv subdomain_massdns2.txt Results/"$TARGET_DOMAIN"_validated_subdomains.txt 2>/dev/null
mv final_step.txt Results/"$TARGET_DOMAIN"_all_candidates.txt 2>/dev/null

# Move intermediate files if you want to keep them for debugging (optional)
#mv subfinder_out.txt Results/ 2>/dev/null
#mv crtsh_out.txt Results/ 2>/dev/null
#mv altdns_out.txt Results/ 2>/dev/null
rm subdomain_massdns.txt
rm subdomain_step*.txt
rm altdns_out.txt
rm crtsh_out.txt
rm subfinder_out.txt

# Ensure screenshots folder is moved if it exists
if [ -d "Results/screenshots/$TARGET_DOMAIN" ]; then
    log "Screenshots organized in Results/screenshots/$TARGET_DOMAIN/"
else
    # If screenshots were created in a different spot, move them
    if [ -d "screenshots/$TARGET_DOMAIN" ]; then
        mv screenshots/$TARGET_DOMAIN Results/screenshots/ 2>/dev/null
    fi
fi

# ==========================================
# FINAL SUMMARY
# ==========================================
log "=========================================="
log "ENUMERATION COMPLETE"
log "=========================================="
log "Domain: $TARGET_DOMAIN"
log "Total Candidates: $total_candidates"
log "Validated Subdomains: $valid_count"
log "HTTP 200 (Active): $c200"
log "HTTP 301 (Redirect): $c301"
log "HTTP 401/403 (Blocked): $c401"

if [ "$SCREENSHOT_MODE" = true ]; then
    s_count=$(find Results/screenshots/"$TARGET_DOMAIN" -name "*.png" 2>/dev/null | wc -l)
    log "Screenshots Captured: $s_count"
    if [ "$s_count" -gt 0 ]; then
        log "View Report: Results/screenshots/$TARGET_DOMAIN/report.html"
    fi
fi

log "=========================================="
log "OUTPUT LOCATION: ./Results/"
log "=========================================="
log "Files saved:"
ls -1 Results/ | sed 's/^/  - /'
log "=========================================="
