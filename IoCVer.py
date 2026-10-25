import sys
import subprocess
import time
import os
import re

# --- 1. AUTOMATIC PREREQUISITE INSTALLER ---
def install_dependencies():
    required = [
        "pandas", 
        "openpyxl", 
        "OTXv2", 
        "tqdm", 
        "crowdstrike-falconpy", 
        "requests"
    ]
    for lib in required:
        try:
            __import__(lib.replace('-', '_'))
        except ImportError:
            print(f"[*] Installing missing dependency: {lib}...")
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", 
                lib, "--break-system-packages"
            ])

install_dependencies()

# --- 2. IMPORTS ---
import pandas as pd
import requests
from OTXv2 import OTXv2
from falconpy import Intel
from tqdm import tqdm
from openpyxl.styles import Font, Alignment, PatternFill

# --- 3. CONFIGURATION & CREDENTIALS ---
# Replace placeholder strings with your actual keys, or set them as environment variables
OTX_API_KEY = os.environ.get('OTX_API_KEY', 'YOUR_OTX_API_KEY_HERE')
CS_CLIENT_ID = os.environ.get('CS_CLIENT_ID', 'YOUR_CROWDSTRIKE_CLIENT_ID_HERE')
CS_CLIENT_SECRET = os.environ.get('CS_CLIENT_SECRET', 'YOUR_CROWDSTRIKE_CLIENT_SECRET_HERE')
CS_BASE_URL = os.environ.get('CS_BASE_URL', 'us1')  # Options: 'us1', 'us2', 'eu1'
VT_API_KEY = os.environ.get('VT_API_KEY', 'YOUR_VIRUSTOTAL_API_KEY_HERE')

INPUT_FILE = 'IoC_verify.txt'
OUTPUT_EXCEL = 'Threat_Intel_DeepDive.xlsx'

# Initialize API Clients
otx = OTXv2(OTX_API_KEY)
falcon = Intel(client_id=CS_CLIENT_ID, client_secret=CS_CLIENT_SECRET, base_url=CS_BASE_URL)

# --- 4. UTILITIES & DEFANGING ---
def defang(text):
    """Neutralizes URLs and IPs to prevent accidental execution."""
    if not text or not isinstance(text, str): 
        return ""
    text = re.sub(r'http', 'hxxp', text, flags=re.IGNORECASE)
    text = re.sub(r'(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})', r'\1[.]\2[.]\3[.]\4', text)
    return text

def guess_type(indicator):
    """Identifies the IoC type using regex patterns."""
    if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', indicator): 
        return "IPv4"
    if re.match(r'^[a-fA-F0-9]{32}$', indicator): 
        return "MD5"
    if re.match(r'^[a-fA-F0-9]{40}$', indicator): 
        return "SHA-1"
    if re.match(r'^[a-fA-F0-9]{64}$', indicator): 
        return "SHA-256"
    if "." in indicator and not any(c.isspace() for c in indicator): 
        return "Domain"
    return "Malware Name"

# --- 5. INTEL ENGINES ---
def check_vt(ioc):
    """Queries VirusTotal API v3 for detection statistics."""
    url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json().get('data', [])
            if data:
                stats = data[0]['attributes'].get('last_analysis_stats', {})
                return stats.get('malicious', 0)
    except Exception:
        pass
    return 0

def get_otx_details(ioc, dtype):
    """Queries AlienVault OTX for indicator pulses and associated context."""
    type_map = {
        "IPv4": "IPv4", 
        "Domain": "domain", 
        "MD5": "file", 
        "SHA-1": "file", 
        "SHA-256": "file"
    }
    try:
        otx_type = type_map.get(dtype, "IPv4")
        res = otx.get_indicator_details_full(otx_type, ioc)
        pulses = res.get('general', {}).get('pulse_info', {}).get('pulses', [])
        count = res.get('general', {}).get('pulse_info', {}).get('count', 0)
        
        actor = "Unknown"
        if pulses:
            families = pulses[0].get('malware_families', [])
            actor = families[0]['name'] if families else pulses[0].get('author_name', 'Community')
            
        return count, actor
    except Exception:
        return 0, "Unknown"

def search_malware_intel(name):
    """Pivots on a malware family name across CrowdStrike and OTX."""
    intel_data = {"Found": False, "Actors": [], "Details": ""}
    
    # Check OTX Pulses
    try:
        pulses = otx.search_pulses(name)
        if pulses.get('results'):
            intel_data["Found"] = True
            first_pulse = pulses['results'][0]
            intel_data["Details"] = f"OTX Pulse: {first_pulse.get('name', 'N/A')}"
            if first_pulse.get('malware_families'):
                intel_data["Actors"].extend([f['name'] for f in first_pulse['malware_families']])
    except Exception:
        pass

    # Check CrowdStrike
    try:
        clean_name = name.replace(" ", "")
        cs_res = falcon.query_malware_entities(filter=f"name:'{name}',name:'{clean_name}'")
        if cs_res['status_code'] == 200 and cs_res['body']['resources']:
            intel_data["Found"] = True
            resource = cs_res['body']['resources'][0]
            intel_data["Actors"].extend([a['name'] for a in resource.get('associated_actors', [])])
            intel_data["Details"] += (" | " if intel_data["Details"] else "") + "CS Malware Family Match"
    except Exception:
        pass

    return intel_data

# --- 6. MAIN ENGINE ---
def main():
    if not os.path.exists(INPUT_FILE):
        print(f"[-] Input file '{INPUT_FILE}' not found. Please create it and add indicators.")
        return

    with open(INPUT_FILE, 'r') as f:
        lines = [line.strip() for line in f if line.strip()]

    if not lines:
        print(f"[-] Input file '{INPUT_FILE}' is empty.")
        return

    all_results = []
    pbar = tqdm(lines, desc="[🔍] Hunting Intel", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]")

    for raw_line in pbar:
        entry = None
        
        # Handle explicit tags or guess automatically
        if raw_line.startswith("[MALWARE]"):
            item = raw_line.replace("[MALWARE]", "").strip()
            dtype = "Malware Name"
        elif raw_line.startswith("
