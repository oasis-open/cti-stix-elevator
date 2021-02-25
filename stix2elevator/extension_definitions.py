MITRE_COPYRIGHT_STATEMENT_DATA_MARKING = {
    "created": "2020-12-22T00:00:00.000000Z",
    "definition": {
        "statement": "Copyright 2020 - The MITRE Corporation, Inc."
    },
    "definition_type": "statement",
    "id": "marking-definition--3cd55916-d34b-4747-a8e0-dedec14b711b",
    "spec_version": "2.1",
    "type": "marking-definition"
}

MITRE_IDENTITY_OBJECT = {
    "created": "2020-12-22T00:00:00.000000Z",
    "id": "identity--659e8342-f720-4d0d-b193-6a04fdfbb401",
    "modified": "2020-12-22T00:00:00.000000Z",
    "name": "MITRE",
    "object_marking_refs": [
        MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
    ],
    "spec_version": "2.1",
    "type": "identity"
}

EXTENSION_DEFINITION_FOR_STIX_1_X = {
    "archive-file": {
        "id": "extension-definition--db4b5429-6927-4d0c-a194-4695f05c629a",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x archive-file",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-archive-file/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "attack-pattern": {
        "id": "extension-definition--abfeb963-42a9-45a7-841a-e1d97838e2c9",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x Attack Pattern",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-attack-pattern/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "campaign": {
        "id": "extension-definition--d83fce45-ef58-4c6c-a3f4-1fbc32e98c6e",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x Campaigns",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-campaign/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "course-of-action": {
        "id": "extension-definition--a46b18de-0b41-4a95-9d2d-67a360f2d859",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x Courses of Action",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-course-of-action/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "email-message": {
        "id": "extension-definition--0d4dda28-1b6c-446a-be85-38b9d9cd297c",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x email-message",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-email-message/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "icmp-header": {
        "id": "extension-definition--6f6973cb-70be-40cb-b1ac-15ed78cebe56",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x Malware Instances",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-icmp-header/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "identity": {
        "id": "extension-definition--8f0b8ed7-c7ad-4650-babe-c4c45cac4a0b",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x Identities",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://https://github.com/mitre/cti/extension-definitions/stix-1-identity/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "identity-ciq": {
        "id": "extension-definition--ec1760d6-6e8a-4a13-8237-574e5bbcc785",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x CIQ Identities",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-identity-ciq/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "incident": {
        "id": "extension-definition--7a8eaf47-9b0f-487d-b280-1e6cc4cccee9",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x Incident",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-incident/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "indicator": {
        "id": "extension-definition--7c8ca481-f0e9-4389-94f5-90df472eb01d",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x Indicators",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-indicator/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "information_source": {
        "id": "extension-definition--58c914a2-0b19-4f62-8221-0af0b542e130",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x information_source",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-information-source/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "infrastructure": {
        "id": "extension-definition--9ae2f90d-ea55-47e5-9d72-6f51344997e2",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x Infrastucture",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-infrastucture/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "malware": {
        "id": "extension-definition--5efa53f9-cf17-4867-bb4f-4cd2ac055e7c",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x Malware Instances",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-malware/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "network-socket": {
        "id": "extension-definition--005e229c-fffc-42b0-a912-84671ab2829d",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x Malware Instances",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-network-socket/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "threat-actor": {
        "id": "extension-definition--bcaf7e25-8446-41d4-973a-0098c889d51d",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x Threat Actors",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-threat-actor/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "tool": {
        "id": "extension-definition--683e2ed4-80fb-4910-a179-64e88ac6c259",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x Tools",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-tool/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    },
    "vulnerability": {
        "id": "extension-definition--ac577b78-8356-41e0-bc5a-2cd3e5c17b2c",
        "type": "extension-definition",
        "spec_version": "2.1",
        "name": "Extension to support STIX 1.x Vulnerabilities",
        "description": "This schema adds two properties to a STIX object",
        "created": "2020-12-22T00:00:00.000000Z",
        "modified": "2020-12-22T00:00:00.000000Z",
        "created_by_ref": MITRE_IDENTITY_OBJECT["id"],
        "object_marking_refs": [
            MITRE_COPYRIGHT_STATEMENT_DATA_MARKING["id"]
        ],
        "schema": "https://github.com/mitre/cti/extension-definitions/stix-1-vulnerabilities/",
        "version": "1.0.0",
        "extension_types": ["property-extension"]
    }
}


def get_extension_definition_id(stix_1_type):
    if stix_1_type in EXTENSION_DEFINITION_FOR_STIX_1_X:
        return EXTENSION_DEFINITION_FOR_STIX_1_X[stix_1_type]["id"]
