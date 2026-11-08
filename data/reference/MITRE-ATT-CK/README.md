# MITRE ATT&CK Reference Data Hub
**Team Neural Breach — AI/ML Cyber Defense Platform**

This directory houses the official MITRE ATT&CK Enterprise Matrix STIX 2.1 bundles.

### 1. In-Code Zero-Dependency Verified Catalog
The platform's Threat Intelligence engine (`src/xai/mitre_mapper.py`) contains a fully verified, in-code catalog covering all 15 attack categories, tactics, techniques, URLs, and mitigations. The application runs and serves predictions without requiring external downloads.

### 2. Optional STIX 2.1 Re-Validation
To validate the catalog against the full upstream 55 MB MITRE ATT&CK Enterprise STIX 2.1 JSON bundle:

```bash
# Automated setup script:
python scripts/setup_mitre_data.py

# Or direct download via curl:
curl -o data/reference/MITRE-ATT-CK/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

Large JSON bundles (`*.json`) in this directory are tracked outside Git via `.gitignore`.
