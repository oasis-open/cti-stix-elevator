# STIX

# Limited in STIX 2.0, no labels available.
COA_LABEL_MAP = \
    {
        "Perimeter Blocking": "perimeter-blocking",
        "Internal Blocking": "internal-blocking",
        "Redirection": "redirection",
        "Redirection (Honey Pot)": "redirection-honey-pot",
        "Hardening": "hardening",
        "Patching": "patching",
        "Eradication": "eradication",
        "Rebuilding": "rebuilding",
        "Training": "training",
        "Monitoring": "monitoring",
        "Physical Access Restrictions": "physical-access-restrictions",
        "Logical Access Restrictions": "logical-access-restrictions",
        "Public Disclosure": "public-disclosure",
        "Diplomatic Actions": "diplomatic-actions",
        "Policy Actions": "policy-actions",
        "Other": "other",
    }

# Not in STIX 2.0
INCIDENT_LABEL_MAP = \
    {
        "Denial of Service": "denial-of-service",
        "Exercise/Network Defense Testing": "exercise-and-network-defense-testing",
        "Improper Usage": "improper-usage",
        "Investigation": "investigation",
        "Malicious Code": "malicious-code",
        "Scans/Probes/Attempted Access": "scans-probes-attempted-access",
        "Unauthorized Access": "unauthorized-access",
    }

INDICATOR_LABEL_MAP = \
    {
        "Anonymization": "anonymization",
        "Compromised PKI Certificate": "compromised-pki-certificate",
        "Login Name": "login-name",
        "Malware Artifacts": "malware-artifacts",
        "Malicious E-mail": "malicious-email",
        "Exfiltration": "exfiltration",
        "C2": "command-and-control",
        "IP Watchlist": "ip-watchlist",
        "Domain Watchlist": "domain-watchlist",
        "URL Watchlist": "url-watchlist",
        "File Hash Watchlist": "file-hash-watchlist",
        "IMEI Watchlist": "imei-watchlist",
        "IMSI Watchlist": "imsi-watchlist",
        "Host Characteristics": "host-characteristics",
    }

MALWARE_LABELS_MAP = \
    {
        "Automated Transfer Scripts": "automated-transfer-scripts",
        "Adware": "adware",
        "Dialer": "dialer",
        "Bot": "bot",
        "Bot - Credential Theft": "bot-credential-theft",
        "Bot - DDoS": "bot-ddos",
        "Bot - Loader": "bot-loader",
        "Bot - Spam": "bot-spam",
        "DoS / DDoS": "dos-ddos",
        "DoS / DDoS - Participatory": "dos-ddos-participatory",
        "DoS / DDoS - Script": "dos-ddos-script",
        "DoS / DDoS - Stress Test Tools": "dos-ddos-stress-test-tools",
        "Exploit Kits": "exploit-kit",
        "POS / ATM Malware": "pos-atm-malware",
        "Ransomware": "ransomware",
        "Remote Access Trojan": "remote-access-trojan",
        "Rogue Antivirus": "rogue-security-software",
        "Rootkit": "rootkit",
    }

ROLES_MAP = \
    {

    }

SECTORS_MAP = \
    {
        "Chemical Sector": "chemical-sector",
        "Commercial Facilities Sector": "commercial-facilities-sector",
        "Communications Sector": "communications-sector",
        "Critical Manufacturing Sector": "critical-manufacturing-sector",
        "Dams Sector": "dams-sector",
        "Defense Industrial Base Sector": "defense-industrial-base-sector",
        "Emergency Services Sector": "emergency-services-sector",
        "Energy Sector": "energy-sector",
        "Financial Services Sector": "financial-services-sector",
        "Food and Agriculture Sector": "food-and-agriculture-sector",
        "Government Facilities Sector": "government-facilities-sector",
        "Healthcare and Public Health Sector": "healthcare-and-public-health-sector",
        "Information Technology Sector": "information-technology-sector",
        "Nuclear Reactors, Materials, and Waste Sector": "nuclear-reactors-materials-and-waste-sector",
        "Other": "other",
        "Transportation Systems Sector": "transportation-systems-sector",
        "Water and Wastewater Systems Sector": "water-and-wastewater-systems-sector",
    }

THREAT_ACTOR_LABEL_MAP = \
    {
        "Cyber Espionage Operations": "cyber-espionage-operations",
        "Hacker": "hacker",
        "Hacker - White hat": "hacker-white-hat",
        "Hacker - Gray hat": "hacker-gray-hat",
        "Hacker - Black hat": "hacker-black-hat",
        "Hacktivist": "hactivist",
        "State Actor / Agency": "nation-state",
        "eCrime Actor - Credential Theft Botnet Operator": "ecrime-actor-botnet-operator",
        "eCrime Actor - Credential Theft Botnet Service": "ecrime-actor-botnet-service",
        "eCrime Actor - Malware Developer": "ecrime-actor-malware-developer",
        "eCrime Actor - Money Laundering Network": "ecrime-actor-money-laundering-network",
        "eCrime Actor - Organized Crime Actor": "ecrime-actor-organized-crime-actor",
        "eCrime Actor - Spam Service": "ecrime-actor-spam-service",
        "eCrime Actor - Traffic Service": "ecrime-actor-traffic-service",
        "eCrime Actor - Underground Call Service": "ecrime-actor-underground-call-service",
        "Insider Threat": "insider-threat",
        "Disgruntled Customer / User": "disgruntled-customer-user",
    }

ATTACK_MOTIVATION_MAP = \
    {
        "Ideological": "ideology",
        "Ideological - Anti-Corruption": "ideology-anti-corruption",
        "Ideological - Anti-Establishment": "ideology-anti-establishment",
        "Ideological - Environmental": "ideology-environmental",
        "Ideological - Ethnic / Nationalist": "ideology-ethnic-nationalist",
        "Ideological - Information Freedom": "ideology-information-freedom",
        "Ideological - Religious": "ideology-religious",
        "Ideological - Security Awareness": "ideology-security-awareness",
        "Ideological - Human Rights": "ideology-human-rights",
        "Ego": "personal-satisfaction",
        "Financial or Economic": "financial-or-economic-gain",
        "Military": "military",
        "Opportunistic": "opportunistic",
        "Political": "political",
    }

THREAT_ACTOR_SOPHISTICATION_MAP = \
    {
        "Innovator": "innovator",
        "Expert": "expert",
        "Practitioner": "intermediate",
        "Novice": "novice",
        "Aspirant": "aspirant",
    }

TOOL_LABELS_MAP = \
    {
        "Malware": "malware",
        "Penetration Testing": "penetration-testing",
        "Port Scanner": "port-scanning",
        "Traffic Scanner": "traffic-scanning",
        "Vulnerability Scanner": "vulnerability-scanning",
        "Application Scanner": "application-scanning",
        "Password Cracking": "password-cracking",
    }


REPORT_LABELS_MAP = \
    {
        "Collective Threat Intelligence": "collective-threat-intelligence",
        "Threat Report": "threat-report",
        "Indicators": "indicator",
        "Indicators - Phishing": "indicator-phising",
        "Indicators - Watchlist": "indicator-watchlist",
        "Indicators - Malware Artifacts": "indicator-malware-artifacts",
        "Indicators - Network Activity": "indicator-network-artifacts",
        "Indicators - Endpoint Characteristics": "indicator-endpoint-characteristics",
        "Campaign Characterization": "campaign-characterization",
        "Threat Actor Characterization": "threat-actor-characterization",
        "Exploit Characterization": "exploit-characterization",
        "Attack Pattern Characterization": "attack-pattern-characterization",
        "Malware Characterization": "malware-characterization",
        "TTP - Infrastructure": "ttp-infrastructure",
        "TTP - Tools": "ttp-tools",
        "Courses of Action": "courses-of-action",
        "Incident": "incident",
        "Observations": "observations",
        "Observations - Email": "observations-email",
        "Malware Samples": "malware-samples",
    }

# CybOX

WINDOWS_PEBINARY = \
    {

    }

SERVICE_START_TYPE = \
    {

    }

SERVICE_TYPE = \
    {

    }

SERVICE_STATUS = \
    {

    }
