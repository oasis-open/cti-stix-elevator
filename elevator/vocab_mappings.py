# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

# STIX

# Limited in STIX 2.0, no labels available.
COA_LABEL_MAP = \
    {

    }

# Not in STIX 2.0
INCIDENT_LABEL_MAP = \
    {

    }

INDICATOR_LABEL_MAP = \
    {
        "Anonymization": "anonymization",
        "Compromised PKI Certificate": "compromised",
        "Login Name": "compromised",
        "Malware Artifacts": "malicious-activity",
        "Malicious E-mail": "malicious-activity",
        "Exfiltration": "malicious-activity",
        "C2": "malicious-activity",
        "IP Watchlist": "benign",
        "Domain Watchlist": "benign",
        "URL Watchlist": "benign",
        "File Hash Watchlist": "benign",
        "IMEI Watchlist": "benign",
        "IMSI Watchlist": "benign",
        "Host Characteristics": "benign",
    }

MALWARE_LABELS_MAP = \
    {
        "Automated Transfer Scripts": "",
        "Adware": "adware",
        "Dialer": "spyware",  # Verify
        "Bot": "bot",
        "Bot - Credential Theft": "bot",
        "Bot - DDoS": "bot",
        "Bot - Loader": "bot",
        "Bot - Spam": "bot",
        "DoS / DDoS": "ddos",
        "DoS / DDoS - Participatory": "ddos",
        "DoS / DDoS - Script": "ddos",
        "DoS / DDoS - Stress Test Tools": "ddos",
        "Exploit Kits": "exploit-kit",
        "POS / ATM Malware": "",  # Need to determined
        "Ransomware": "ransomware",
        "Remote Access Trojan": "remote-access-trojan",
        "Rogue Antivirus": "rogue-security-software",
        "Rootkit": "rootkit",
    }

ROLES_MAP = {}

SECTORS_MAP = {}

THREAT_ACTOR_LABEL_MAP = \
    {
        "Cyber Espionage Operations": "spy",
        "Hacker": "hacker",
        "Hacker - White hat": "hacker",
        "Hacker - Gray hat": "hacker",
        "Hacker - Black hat": "hacker",
        "Hacktivist": "activist",
        "State Actor / Agency": "nation-state",
        "eCrime Actor - Credential Theft Botnet Operator": "criminal",
        "eCrime Actor - Credential Theft Botnet Service": "criminal",
        "eCrime Actor - Malware Developer": "criminal",
        "eCrime Actor - Money Laundering Network": "criminal",
        "eCrime Actor - Organized Crime Actor": "criminal",
        "eCrime Actor - Spam Service": "criminal",
        "eCrime Actor - Traffic Service": "criminal",
        "eCrime Actor - Underground Call Service": "criminal",
        "Insider Threat": "",  # conflict insider-accidental, insider-disgruntled
        "Disgruntled Customer / User": "insider-disgruntled",
    }

ATTACK_MOTIVATION_MAP = \
    {
        "Ideological": "ideology",
        "Ideological - Anti-Corruption": "ideology",
        "Ideological - Anti-Establishment": "ideology",
        "Ideological - Environmental": "ideology",
        "Ideological - Ethnic / Nationalist": "ideology",
        "Ideological - Information Freedom": "ideology",
        "Ideological - Religious": "ideology",
        "Ideological - Security Awareness": "ideology",
        "Ideological - Human Rights": "ideology",
        "Ego": "personal-satisfaction",
        "Financial or Economic": "",  # conflicting organizational-gain, personal-gain
        "Military": "",         # Need to determine
        "Opportunistic": "",    # Need to determine
        "Political": "",        # Need to determine
    }

THREAT_ACTOR_SOPHISTICATION_MAP = \
    {
        "Innovator": "innovator",
        "Expert": "expert",
        "Practitioner": "intermediate",
        "Novice": "minimal",
        "Aspirant": "none",
    }

TOOL_LABELS_MAP = \
    {
        "Malware": "exploitation",
        "Penetration Testing": "",  # Need to determine
        "Port Scanner": "information-gathering",
        "Traffic Scanner": "information-gathering",
        "Vulnerability Scanner": "vulnerability-scanning",
        "Application Scanner": "",
        "Password Cracking": "credential-exploitation",
    }


REPORT_LABELS_MAP = \
    {
        "Collective Threat Intelligence": "",
        "Threat Report": "threat-report",
        "Indicators": "indicator",
        "Indicators - Phishing": "indicator",
        "Indicators - Watchlist": "indicator",
        "Indicators - Malware Artifacts": "indicator",
        "Indicators - Network Activity": "indicator",
        "Indicators - Endpoint Characteristics": "indicator",
        "Campaign Characterization": "campaign",
        "Threat Actor Characterization": "threat-actor",
        "Exploit Characterization": "",
        "Attack Pattern Characterization": "attack-pattern",
        "Malware Characterization": "malware",
        "TTP - Infrastructure": "",
        "TTP - Tools": "",
        "Courses of Action": "",
        "Incident": "",
        "Observations": "",
        "Observations - Email": "",
        "Malware Samples": ""
    }

#CybOX

WINDOWS_PEBINARY = {}

SERVICE_START_TYPE = {}

SERVICE_TYPE = {}

SERVICE_STATUS = {}
