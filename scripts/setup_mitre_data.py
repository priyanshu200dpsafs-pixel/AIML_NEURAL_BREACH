#!/usr/bin/env python3
"""
MITRE ATT&CK Reference Data Setup Utility
Team Neural Breach — AI/ML Cyber Defense Platform

Downloads and verifies the official MITRE ATT&CK STIX 2.1 Enterprise bundle
directly from the official MITRE CTI repository.
"""

import os
import sys
import json
import urllib.request

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET_DIR = os.path.join(PROJECT_ROOT, "data", "reference", "MITRE-ATT-CK")
TARGET_FILE = os.path.join(TARGET_DIR, "enterprise-attack.json")

OFFICIAL_MITRE_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


def setup_mitre_stix():
    os.makedirs(TARGET_DIR, exist_ok=True)
    if os.path.exists(TARGET_FILE):
        file_size = os.path.getsize(TARGET_FILE)
        print(f"[✓] MITRE ATT&CK STIX file already exists at {TARGET_FILE} ({file_size / (1024*1024):.2f} MB)")
        try:
            with open(TARGET_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(f"[✓] Successfully validated JSON structure ({len(data.get('objects', []))} objects)")
            return True
        except Exception as e:
            print(f"[!] Existing file corrupted ({e}). Re-downloading...")

    print(f"[*] Downloading official MITRE ATT&CK Enterprise Matrix from {OFFICIAL_MITRE_STIX_URL}...")
    try:
        urllib.request.urlretrieve(OFFICIAL_MITRE_STIX_URL, TARGET_FILE)
        print(f"[✓] Download complete: {TARGET_FILE} ({os.path.getsize(TARGET_FILE) / (1024*1024):.2f} MB)")
        return True
    except Exception as e:
        print(f"[!] Download failed: {e}")
        print("[!] Note: src/xai/mitre_mapper.py contains an in-code verified catalog and will function without this file.")
        return False


if __name__ == "__main__":
    setup_mitre_stix()
