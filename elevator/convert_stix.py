# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import stix
import cybox
from stix.utils.parser import EntityParser
from stix.core import STIXPackage
from stix.campaign import Campaign
from stix.coa import CourseOfAction
from stix.exploit_target import ExploitTarget
from stix.incident import Incident
from stix.indicator import Indicator
from stix.report import Report
from stix.threat_actor import ThreatActor
from stix.ttp import TTP
from stix.common.kill_chains import KillChain, KillChainPhase, KillChainPhaseReference
from stix.common.identity import Identity
from stix.ttp.attack_pattern import (AttackPattern)
from cybox.core import Observable
from stix.extensions.test_mechanism.yara_test_mechanism import YaraTestMechanism
from stix.extensions.test_mechanism.snort_test_mechanism import SnortTestMechanism
from stix.extensions.identity.ciq_identity_3_0 import CIQIdentity3_0Instance

import sys
import python_jsonschema_objects as pjs
import json
from datetime import *
import uuid
import pycountry
from dateutil.parser import *

from convert_cybox import convert_cybox_object
from convert_pattern import convert_observable_to_pattern, fix_pattern
from utils import info, warn, error

SQUIRREL_GAPS_IN_DESCRIPTIONS = True

INFRASTRUCTURE_IN_20 = False

INCIDENT_IN_20 = True

# TODO: specify controlled vocab mappings


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

IDENTITIES = {}

# collect kill chains

KILL_CHAINS_PHASES = {}

OBSERVABLE_MAPPING = {}

def process_kill_chain(kc):
    for kcp in kc.kill_chain_phases:
        KILL_CHAINS_PHASES[kcp.phase_id] = {"kill_chain_name": kc.name, "phase_name": kcp.name}


def map_1x_type_to_20(stix1xType):
    # TODO: stub
    return stix1xType


def generateSTIX20Id(stix20SOName, stix12ID = None):
    if stix12ID is None:
        return stix20SOName + "--" + str(uuid.uuid4())
    else:
        namespace_type_uuid = stix12ID.split("-", 1)
        if stix20SOName is None:
            type = namespace_type_uuid[0].split(":", 1)
            if str.lower(type[1]) == "ttp" or str.lower(type[1]) == "et":
                error("Unable to determine the STIX 2.0 type for " + stix12ID)
                return None
            else:
                return map_1x_type_to_20(type[1]) + "--" + namespace_type_uuid[1]
        else:
            return stix20SOName + "--" + namespace_type_uuid[1]

#
# identities
#


def get_simple_name_from_identity(identity, bundleInstance, sdoInstance):
    if isinstance(identity, CIQIdentity3_0Instance):
        handle_relationship_to_refs([identity], sdoInstance["id"], bundleInstance, "attributed-to")
    else:
        return identity.name


def get_identity_ref(identity, bundleInstance):
    if identity.idref is not None:
        # fix reference later
        return identity.idref
    else:
        ident20 = convert_identity(identity)
        bundleInstance["identities"].append(ident20)
        return ident20["id"]


def process_information_source(information_source, so, bundleInstance, parent_created_by_ref):
    if information_source is not None and information_source.identity is not None:
        so["created_by_ref"] = get_identity_ref(information_source.identity, bundleInstance)
    else:
        so["created_by_ref"] = parent_created_by_ref
    # TODO: add to description


def convert_timestamp(entity, parent_timestamp=None):
    if hasattr(entity, "timestamp"):
        if entity.timestamp is not None:
            # TODO: make sure its in the correct format
            return entity.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        else:
            warn("Timestamp not available, using current time")
            return str(datetime.now().isoformat()) + "Z"
    elif parent_timestamp is not None:
        info("Using enclosing object timestamp")
        # TODO: make sure its in the correct format
        return parent_timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        warn("Timestamp not available, using current time")
        return str(datetime.now().isoformat()) + "Z"

def cannonicalize_label(t):
    # TODO: stub
    return t

def map_vocabs_to_label(t, vocab_map):
    try:
        return vocab_map[t]
    except KeyError:
        return cannonicalize_label(t)

def convert_controlled_vocabs_to_open_vocabs(stix20_obj, stix20_property_name, stix1x_vocabs, vocab_mapping, only_one):
    stix20_obj[stix20_property_name] = []
    for t in stix1x_vocabs:
        if stix20_obj[stix20_property_name] is None or not only_one:
            stix20_obj[stix20_property_name].append(map_vocabs_to_label(t.value, vocab_mapping))
        else:
            warn("Only one " +  stix20_property_name + " allowed in STIX 2.0 - used first one")
    if stix20_obj[stix20_property_name] == []:
        del stix20_obj[stix20_property_name]


def convert_to_open_vocabs(stix20_obj, stix20_property_name, value, vocab_mapping):
    stix20_obj[stix20_property_name].append(map_vocabs_to_label(value, vocab_mapping))


def process_structured_text_list(text_list):
    full_text = ""
    for text_obj in text_list.sorted:
        full_text += text_obj.value
    return full_text


def process_description_and_short_description(so, entity):
    if entity.descriptions is not None:
        so["description"] += process_structured_text_list(entity.descriptions).encode('unicode_escape')
        if SQUIRREL_GAPS_IN_DESCRIPTIONS and entity.short_description is not None:
            warn("The Short_Description property is no longer supported in STIX.  Added the text to the description property")
            so["description"] += "\nShort Description: \n" + process_structured_text_list(entity.short_descriptions).encode('unicode_escape')
    elif entity.short_description is not None:
        so["description"] = process_structured_text_list(entity.short_descriptions).encode('unicode_escape')


def create_basic_object(stix20_type, stix1x_obj, parent_timestamp=None, parent_id=None):
    instance = {"type": stix20_type}
    instance["id"] = generateSTIX20Id(stix20_type, stix1x_obj.id_ if hasattr(stix1x_obj, "id_") and stix1x_obj.id_ else parent_id)
    instance["version"] = 1  # need to see about versioning
    timestamp = convert_timestamp(stix1x_obj, parent_timestamp)
    instance["created"] = timestamp
    # may need to revisit if we handle 1.x versioning.
    instance["modified"] = timestamp
    instance["description"] = ""
    instance["external_references"] = []
    return instance


def remove_empty_common_values(instance):
    if "description" in instance and instance["description"] == "":
        del instance["description"]
    if instance["external_references"] == []:
        del instance["external_references"]
    if "created_by_ref" in instance and instance["created_by_ref"] is None:
        del instance["created_by_ref"]


def finish_basic_object(old_id, instance, stix1x_obj):
    if old_id is not None:
        record_ids(old_id, instance["id"])
    remove_empty_common_values(instance)
    if hasattr(stix1x_obj, "handling") and stix1x_obj.handling is not None:
        warn("Handling not implemented, yet")
    if hasattr(stix1x_obj, "related_packages") and stix1x_obj.related_packages is not None:
        for p in stix1x_obj.related_packages:
            warn("Related_Packages property no longer supported in STIX")

#
# handle gaps
#


def add_string_property_to_description(sdoInstance, property_name, property_value, isList=False):
    if SQUIRREL_GAPS_IN_DESCRIPTIONS and property_value is not None:
        if isList:
            sdoInstance["description"] += "\n\n" + str.upper(property_name) + ":\n"
            property_values = []
            for v in property_value:
                property_values.append(str(v).encode('unicode_escape'))
            sdoInstance["description"] += ",\n".join(property_values)
        else:
            sdoInstance["description"] += "\n\n" + str.upper(property_name) + ":\n" + str(property_value).encode('unicode_escape')
        warn("Added " + property_name + " to description of " + sdoInstance["id"])

def add_confidence_property_to_description(sdoInstance, confidence):
    if SQUIRREL_GAPS_IN_DESCRIPTIONS:
        if confidence is not None:
            sdoInstance["description"] += "\n\n" + "CONFIDENCE:"
            if confidence.value is not None:
                sdoInstance["description"] += str(confidence.value)
            if confidence.description is not None:
                sdoInstance["description"] += "\n\tDESCRIPTION: " + str(confidence.description)

# Relationships

IDS_TO_NEW_IDS = {}


def record_ids(id, new_id):
    if id in IDS_TO_NEW_IDS:
        warn(id + " is already associated with a new id " + IDS_TO_NEW_IDS[id])
    else:
        # info("associating " + new_id + " with " + id)
        if new_id is None:
            error("Could not associate " + id + " with None")
        IDS_TO_NEW_IDS[id] = new_id


def create_relationship(source_ref, target_ref, verb, rel_obj, parent_timestamp):
    relationshipInstance = create_basic_object("relationship", rel_obj, parent_timestamp)
    relationshipInstance["source_ref"] = source_ref
    relationshipInstance["target_ref"] = target_ref
    relationshipInstance["name"] = verb
    if rel_obj is not None and hasattr(rel_obj, "relationship") and rel_obj.relationship is not None:
        relationshipInstance["description"] = rel_obj.relationship.value
    # handle description
    remove_empty_common_values(relationshipInstance)
    return relationshipInstance


def handle_relationship_to_objs(items, source_id, bundleInstance, verb, parent_timestamp=None):
    for item in items:
        handle_embedded_object(item, bundleInstance)
        bundleInstance["relationships"].append(create_relationship(source_id,
                                                                   item.id_,
                                                                   verb,
                                                                   item,
                                                                   parent_timestamp))


def handle_relationship_to_refs(refs, source_id, bundleInstance, verb, parent_timestamp=None):
    for ref in refs:
        if ref.item.idref is None:
            # embedded
            handle_embedded_object(ref.item, bundleInstance)
            bundleInstance["relationships"].append(create_relationship(source_id,
                                                                       ref.item.id_,
                                                                       verb,
                                                                       ref,
                                                                       parent_timestamp))
        elif ref.item.idref in IDS_TO_NEW_IDS:
            to_ref = IDS_TO_NEW_IDS[ref.item.idref]
            bundleInstance["relationships"].append(create_relationship(source_id,
                                                                       to_ref,
                                                                       verb,
                                                                       ref,
                                                                       parent_timestamp))
        else:
            # a forward reference, fix later
            bundleInstance["relationships"].append(create_relationship(source_id,
                                                                       ref.item.idref,
                                                                       verb,
                                                                       ref,
                                                                       parent_timestamp))


def handle_relationship_from_refs(refs, target_id, bundleInstance, verb, parent_timestamp=None):
    for ref in refs:
        if ref.item.idref is None:
            # embedded
            handle_embedded_object(ref.item, bundleInstance)
            bundleInstance["relationships"].append(create_relationship(ref.item.id_,
                                                                       target_id,
                                                                       verb,
                                                                       ref,
                                                                       parent_timestamp))
        elif ref.item.idref in IDS_TO_NEW_IDS:
            from_ref = IDS_TO_NEW_IDS[ref.item.idref]
            bundleInstance["relationships"].append(create_relationship(from_ref,
                                                                       target_id,
                                                                       verb,
                                                                       ref,
                                                                       parent_timestamp))
        else:
            # a forward reference, fix later
            bundleInstance["relationships"].append(create_relationship(ref.item.idref,
                                                                       target_id,
                                                                       verb,
                                                                       ref,
                                                                       parent_timestamp))


def reference_needs_fixing(ref):
    return ref.find("--") == -1


def fix_relationships(relationships):
    # TODO:  warn if ref not available??
    for ref in relationships:
        if reference_needs_fixing(ref["source_ref"]):
            if not ref["source_ref"] in IDS_TO_NEW_IDS:
                new_id = generateSTIX20Id(None, str.lower(ref["source_ref"]))
                if new_id is None:
                    warn("Dangling source reference " +  ref["source_ref"] + " in " + ref["id"])
                IDS_TO_NEW_IDS[ref["source_ref"]] = new_id
            ref["source_ref"] = IDS_TO_NEW_IDS[ref["source_ref"]]
        if reference_needs_fixing(ref["target_ref"]):
            if not ref["target_ref"] in IDS_TO_NEW_IDS:
                new_id = generateSTIX20Id(None, str.lower(ref["target_ref"]))
                if new_id is None:
                    warn("Dangling target reference " + ref["target_ref"] + " in " + ref["id"])
                IDS_TO_NEW_IDS[ref["target_ref"]] = new_id
            ref["target_ref"] = IDS_TO_NEW_IDS[ref["target_ref"]]
        # TODO: add error messages for missing required properties

# campaign


def convert_campaign(camp, bundleInstance):
    campaignInstance = create_basic_object("campaign", camp)
    process_description_and_short_description(campaignInstance, camp)
    campaignInstance["name"] = camp.title
    if camp.names is not None:
        campaignInstance["aliases"] = []
        for name in camp.names:
            campaignInstance["aliases"].append(name)
        if campaignInstance["aliases"] == []:
            del campaignInstance["aliases"]
    # TODO: add intended effect to description
    add_string_property_to_description(campaignInstance, "status", camp.status)
    if hasattr(camp, "confidence"):
        add_confidence_property_to_description(campaignInstance, camp.confidence)
    # TODO: add attribution to description
    if camp.activity is not None:
        for a in camp.activity:
            warn("Campaign/Activity not supported in STIX 2.0")
    if camp.related_ttps is not None:
        # victims use targets, not uses
        handle_relationship_to_refs(camp.related_ttps, campaignInstance["id"], bundleInstance, "uses")
    if camp.related_incidents is not None:
        handle_relationship_from_refs(camp.related_incidents, campaignInstance["id"], bundleInstance, "attributed-to")
    if camp.related_indicators is not None:
        handle_relationship_from_refs(camp.related_indicators, campaignInstance["id"], bundleInstance, "indicates")
    if camp.attribution is not None:
        for att in camp.attribution:
            handle_relationship_from_refs(att, campaignInstance["id"], bundleInstance, "attributed-to")
    # associated campaigns
    process_information_source(camp.information_source,
                               campaignInstance,
                               bundleInstance,
                               bundleInstance["created_by_ref"] if "created_by_ref" in bundleInstance else None)
    finish_basic_object(camp.id_, campaignInstance, camp)
    # TODO: add error messages for missing required properties
    return campaignInstance

# course of action


def convert_course_of_action(coa, bundleInstance):
    coaInstance = create_basic_object("course_of_action", coa)
    process_description_and_short_description(coaInstance, coa)
    coaInstance["name"] = coa.title
    add_string_property_to_description(coaInstance, "stage", coa.stage)
    convert_controlled_vocabs_to_open_vocabs(coaInstance, "labels", [ coa.type_ ], COA_LABEL_MAP, False)
    # TODO: add objective into description
    # TODO: parameter observables, maybe turn into pattern expressions and put in description???
    if coa.structured_coa:
        warn("Structured COAs are not supported in STIX 2.0")
    # TODO: add impact into description
    # TODO: add cost into description
    # TODO: add efficacy into description
    process_information_source(coa.information_source, coaInstance, bundleInstance,
                               bundleInstance["created_by_ref"] if "created_by_ref" in bundleInstance else None)
    # TODO: related coas
    finish_basic_object(coa.id_, coaInstance, coa)
    # TODO: add error messages for missing required properties
    return coaInstance

# exploit target


def process_et_properties(sdoInstance, et, bundleInstance):
    process_description_and_short_description(sdoInstance, et)
    if "name" in sdoInstance:
        info("title from " + sdoInstance["type"] + " used for name, put exploit_target title in description")
        # TODO: add title to description
    elif et.title is not None:
        sdoInstance["name"] = et.title
    process_information_source(et.information_source, sdoInstance, bundleInstance,
                               bundleInstance["created_by_ref"] if "created_by_ref" in bundleInstance else None)
    if et.potential_coas is not None:
        handle_relationship_from_refs(et.potential_coas, sdoInstance["id"], bundleInstance, "mitigates",
                                      et.timestamp)


def convert_vulnerability(v, et, bundleInstance):
    vulnerabilityInstance = create_basic_object("vulnerability", v, et.timestamp, et.id_)
    if v.title is not None:
        vulnerabilityInstance["name"] = v.title
    process_description_and_short_description(vulnerabilityInstance, v)
    if v.cve_id is not None:
        vulnerabilityInstance["external_references"].append({"source_name": "cve", "external_id": v.cve_id})
    if v.osvdb_id is not None:
        vulnerabilityInstance["external_references"].append({"source_name": "osvdb", "external_id": v.osvdb_id})
    # source?
    # TODO: add CVSS score into description
    # TODO: add date times into description
    # TODO: add affected software into description
    if v.references is not None:
        # TODO: url can't exist alone
        for ref in v.references:
            vulnerabilityInstance["external_references"].append({"url": ref.reference})
    process_et_properties(vulnerabilityInstance, et, bundleInstance)
    finish_basic_object(et.id_, vulnerabilityInstance, v)
    # TODO: add error messages for missing required properties
    return vulnerabilityInstance


def convert_exploit_target(et, bundleInstance):
    if et.vulnerabilities is not None:
        for v in et.vulnerabilities:
            bundleInstance["vulnerabilities"].append(convert_vulnerability(v, et, bundleInstance))
    if et.weaknesses is not None:
        for w in et.weaknesses:
            warn("ExploitTarget/Weaknesses not supported in STIX 2.0")
    if et.configuration is not None:
        for c in et.configuration:
            warn("ExploitTarget/Configurations not supported in STIX 2.0")

# identities


def convert_ciq_addresses(addresses, identityInstance):
    identityInstance["country"] = []
    identityInstance["regions"] = []
    for add in addresses:
        if hasattr(add, "country"):
            for name in add.country.name_elements:
                iso = pycountry.countries.get(name=name.value)
                if iso is not None:
                    identityInstance["country"].append(iso.alpha2)
                else:
                    warn("No ISO code for " + name.value)
                    identityInstance["country"].append(name.value)
        if hasattr(add, "administrative_area"):
            for name in add.administrative_area.name_elements:
                # bug in pycountry - need to make sure that subdivisions are indexed using "name"
                iso = pycountry.subdivisions.get(name=name.value)
                if iso is not None:
                    identityInstance["regions"].append(iso.code)
                else:
                    identityInstance["regions"].append(name.value)


def get_name(name):
    # TODO:  this is much too simple
    return name.name_elements[0].value


def convert_party_name(party_name, identity):
    if not party_name.organisation_names == [] and not party_name.person_names == []:
        error("Identity has organization and person names")
    if not party_name.person_names == []:
        identity["identity_class"] = "individual"
        first_one = True
        for name in party_name.person_names:
            if first_one:
                identity["name"] = get_name(name)
                first_one = False
            else:
                warn("more than one person name for " + identity.id_ + " not allowed in STIX 2.0, used first one")
                # add to description
    elif not party_name.organisation_names == []:
        identity["identity_class"] = "organization"
        first_one = True
        for name in party_name.organisation_names:
            if first_one:
                identity["name"] = get_name(name)
                first_one = False
            else:
                warn("more than one organization name for " + identity["id"] + " not allowed in STIX 2.0, used first one")
                # add to description


def convert_identity(identity, finish=True):
    identityInstance = create_basic_object("identity", identity)
    identityInstance["sectors"] = []
    if identity.name is not None:
        identityInstance["name"] = identity.name
    if isinstance(identity, CIQIdentity3_0Instance):
        if identity.roles is not None:
            convert_controlled_vocabs_to_open_vocabs(identityInstance, "roles", identity.roles, ROLES_MAP, False)
        ciq_info = identity._specification
        if ciq_info.party_name is not None:
            warn("ciq name found in " + identityInstance["id"] + ", possibly overriding other name")
            convert_party_name(ciq_info.party_name, identityInstance)
        if "name" not in identityInstance:
            error(identityInstance["id"] + " must have a name, using 'none'")
            identityInstance["name"] = "None"
        if ciq_info.organisation_info is not None:
            convert_to_open_vocabs(identityInstance, "sectors", ciq_info.organisation_info.industry_type, SECTORS_MAP)
        if ciq_info.addresses is not None:
            convert_ciq_addresses(ciq_info.addresses, identityInstance)
        # add other properties to contact_information
    if finish:
        finish_basic_object(identity.id_, identityInstance, identity)
    # TODO: add error messages for missing required properties
    return identityInstance

# incident


def convert_incident(incident, bundleInstance):
    incidentInstance = create_basic_object("incident", incident)
    process_description_and_short_description(incidentInstance, incident)
    if incident.title is not None:
        incidentInstance["name"] = incident.title
    if incident.external_ids is not None:
        for id in incident.external_ids:
            incidentInstance["external_references"].append({"source_name": id.external_id.source, "external_id": id.external_id.value })
    # time
    convert_controlled_vocabs_to_open_vocabs(incidentInstance, "labels", incident.categories, INCIDENT_LABEL_MAP, False)
    if incident.related_indicators is not None:
        handle_relationship_from_refs(incident.related_indicators, incidentInstance["id"], bundleInstance, "indicates", incident.timestamp)
    if incident.related_observables is not None:
        handle_relationship_from_refs(incident.related_observables, incidentInstance["id"], bundleInstance, "part-of", incident.timestamp)
    if incident.leveraged_ttps is not None:
        warn("Using related-to")
        handle_relationship_to_refs(incident.leveraged_ttps, incidentInstance["id"], bundleInstance, "related-to", incident.timestamp)
    # TODO: add reporter to description
    # TODO: add responder to description
    # TODO: add coordinator to description
    # TODO: add victim to description
    # TODO: add affected_assets to description
    # TODO: add impact_assessment to description
    # TODO: add status to description
    process_information_source(incident.information_source, incidentInstance, bundleInstance,
                               bundleInstance["created_by_ref"] if "created_by_ref" in bundleInstance else None)
    finish_basic_object(incident.id_, incidentInstance, incident)
    # TODO: add error messages for missing required properties
    return incidentInstance

# indicator


def convert_kill_chains(kill_chain_phases, sdoInstance):
    if kill_chain_phases is not None:
        kill_chain_phases_20 = []
        for phase in kill_chain_phases:
            if isinstance(phase, KillChainPhaseReference):
                try:
                    kill_chain_info = KILL_CHAINS_PHASES[phase.phase_id]
                    kill_chain_phases_20.append({"kill_chain_name": kill_chain_info.kill_chain_name, "phase_name": kill_chain_info.name})
                except:
                    kill_chain_phases_20.append(phase.phase_id)
            elif isinstance(phase, KillChainPhase):
                kill_chain_phases_20.append({"kill_chain_name": phase.kill_chain_name, "phase_name": phase.name})
        if kill_chain_phases_20 != []:
            sdoInstance["kill_chain_phases"] = kill_chain_phases_20


def convert_test_mechanism(indicator, indicatorInstance):
    if indicator.test_mechanisms is not None:
        if hasattr(indicatorInstance, "pattern"):
            warn("Only one type pattern can be specified in " + indicatorInstance["id"] + " - using cybox")
        else:
            for tm in indicator.test_mechanisms:
                if hasattr(indicatorInstance, "pattern"):
                    warn("only one alternative test mechanism allowed for " + indicatorInstance["id"] + " in STIX 2.0 - used first one, which was " +
                         indicatorInstance["pattern_lang"])
                else:
                    if isinstance(tm, YaraTestMechanism):
                        indicatorInstance["pattern"] = tm.rule.value.encode('unicode_escape')
                        indicatorInstance["pattern_lang"] = "yara"
                    elif isinstance(tm, SnortTestMechanism):
                        list_of_strings = []
                        for rule in tm.rules:
                             list_of_strings.append(rule.value.encode('unicode_escape'))
                        indicatorInstance["pattern"] = ", ".join(list_of_strings)
                        indicatorInstance["pattern_lang"] = "snort"


def convert_indicator(indicator, bundleInstance):
    indicatorInstance = create_basic_object("indicator", indicator)
    process_description_and_short_description(indicatorInstance, indicator)
    convert_controlled_vocabs_to_open_vocabs(indicatorInstance, "labels", indicator.indicator_types, INDICATOR_LABEL_MAP, False)
    if indicator.title is not None:
        indicatorInstance["name"] = indicator.title
    if indicator.alternative_id is not None:
        for id in indicator.alternative_id:
            indicatorInstance["external_references"].append({"source_name": "alternative_id", "external_id": id})
    if indicator.valid_time_positions is not None:
        for window in indicator.valid_time_positions:
            if "valid_from" not in indicatorInstance:
                indicatorInstance["valid_from"] = window.start_time.value
                indicatorInstance["valid_from_precision"] = window.start_time.precision
                indicatorInstance["valid_until"] = window.end_time.value
                indicatorInstance["valid_until_precision"] = window.end_time.precision
            else:
                warn("Only one valid time window allowed for " + indicatorInstance["id"] + " in STIX 2.0 - used first one")
        if "valid_from" not in indicatorInstance:
            warn("No valid time position information available in " + indicator.id_ + ", using timestamp")
            indicatorInstance["valid_from"] = convert_timestamp(indicator)
    convert_kill_chains(indicator.kill_chain_phases, indicatorInstance)
    # TODO: add likely impact to description
    if hasattr(indicator, "confidence"):
        add_confidence_property_to_description(indicatorInstance, indicator.confidence)
    # TODO: sightings
    if indicator.observable is not None:
        indicatorInstance["pattern"] = convert_observable_to_pattern(indicator.observable, bundleInstance, OBSERVABLE_MAPPING)
        indicatorInstance["pattern_lang"] = "cybox"
    if indicator.composite_indicator_expression is not None:
        warn("composite indicator expressions are not handled - " + indicator.id_)
    convert_test_mechanism(indicator, indicatorInstance)
    process_information_source(indicator.producer, indicatorInstance, bundleInstance,
                               bundleInstance["created_by_ref"] if "created_by_ref" in bundleInstance else None)
    if indicator.suggested_coas is not None:
        warn("Using related-to")
        handle_relationship_to_refs(indicator.suggested_coas, indicatorInstance["id"], bundleInstance, "related-to")
    # TODO: related indicators
    if indicator.related_campaigns is not None:
        handle_relationship_to_refs(indicator.related_campaigns, indicatorInstance["id"], bundleInstance, "attributed-to")
    if indicator.indicated_ttps is not None:
        handle_relationship_to_refs(indicator.indicated_ttps, indicatorInstance["id"], bundleInstance, "indicates")
    finish_basic_object(indicator.id_, indicatorInstance, indicator)
    # TODO: add error messages for missing required properties
    return indicatorInstance

# observables


def convert_observable_data(obs, bundleInstance):
    global OBSERVABLE_MAPPING
    observed_data_instance = create_basic_object("observable-data", obs)
    cyboxContainer = { "type": "cybox-container", "spec_version": "3.0"}
    observed_data_instance["cybox"] = convert_cybox_object(obs.object_, cyboxContainer)
    observed_time = convert_timestamp(obs)
    info("No 'first_observed' data on " + obs.id_ + " - using timestamp")
    observed_data_instance["first_observed"] = observed_time
    info("No 'last_observed' data on " + obs.id_ + " - using timestamp")
    observed_data_instance["last_observed"] = observed_time
    observed_data_instance["number_observed"] = 1 if obs.sighting_count is None else obs.sighting_count
    # created_by
    finish_basic_object(obs.id_, observed_data_instance, obs)
    # remember the original 1.x observable, in case it has to be turned into a pattern later
    OBSERVABLE_MAPPING[obs.id_] = obs
    # TODO: add error messages for missing required properties
    return observed_data_instance

# report


def process_report_contents(report, bundleInstance, reportInstance):
    reportInstance["report_refs"] = []
    if report.campaigns:
        for camp in report.campaigns:
            if camp.id_ is not None:
                camp20 = convert_campaign(camp, bundleInstance)
                bundleInstance["campaigns"].append(camp20)
                reportInstance["report_refs"].append(camp20["id"])
            else:
                reportInstance["report_refs"].append(camp.idref)

    # coas
    if report.courses_of_action:
        for coa in report.courses_of_action:
            if coa.id_ is not None:
                coa20 = convert_course_of_action(coa, bundleInstance)
                bundleInstance["courses_of_action"].append(coa20)
                reportInstance["report_refs"].append(coa20["id"])
            else:
                reportInstance["report_refs"].append(coa.idref)

    # exploit-targets
    if report.exploit_targets:
        for et in report.exploit_targets:
            convert_exploit_target(et, bundleInstance)

    # incidents
    if INCIDENT_IN_20:
        if report.incidents:
            for i in report.incidents:
                if i.id_ is not None:
                    i20 = convert_incident(i, bundleInstance)
                    bundleInstance["incidents"].append(i20)
                    reportInstance["report_refs"].append(i20["id"])
                else:
                    reportInstance["report_refs"].append(i.idref)

    # indicators
    if report.indicators:
        for i in report.indicators:
            if i.id_ is not None:
                i20 = convert_indicator(i, bundleInstance)
                bundleInstance["indicators"].append(i20)
                reportInstance["report_refs"].append(i20["id"])
            else:
                reportInstance["report_refs"].append(i.idref)

    # observables
    if report.observables:
        for o_d in report.observables:
            if o_d.id_ is not None:
                o_d20 = convert_observable_data(o_d, bundleInstance)
                bundleInstance["observed_data"].append(o_d20)
                reportInstance["report_refs"].append(o_d20["id"])
            else:
                reportInstance["report_refs"].append(o_d.idref)

    # threat actors
    if report.threat_actors:
        for ta in report.threat_actors:
            if ta.id_ is not None:
                ta20 = convert_threat_actor(ta, bundleInstance)
                bundleInstance["threat-actors"].append(ta20)
                reportInstance["report_refs"].append(ta20["id"])
            else:
                reportInstance["report_refs"].append(ta.idref)


    # ttps
    if report.ttps:
        for ttp in report.ttps:
            convert_ttp(ttp, bundleInstance)


def convert_report(report, bundleInstance):
    reportInstance = create_basic_object("report", report)
    process_description_and_short_description(reportInstance, report.header)
    process_information_source(report.header.information_source, reportInstance, bundleInstance,
                               bundleInstance["created_by_ref"] if "created_by_ref" in bundleInstance else None)
    add_string_property_to_description(reportInstance, "intent", report.header.intents, True)
    if report.header.title is not None:
        reportInstance["name"] = report.header.title
    process_report_contents(report, bundleInstance, reportInstance)
    finish_basic_object(report.id_, reportInstance, report.header)
    # TODO: add error messages for missing required properties
    return reportInstance

# threat actor


def convert_threat_actor(threat_actor, bundleInstance):
    threat_actorInstance = create_basic_object("threat-actor", threat_actor)
    process_description_and_short_description(threat_actorInstance, threat_actor)
    if threat_actor.identity is not None:
        info("Threat actor identity " + threat_actor.identity.id_ + " being used as basis of attributed-to relationship")
        handle_relationship_to_objs([threat_actor.identity ], threat_actor.id_, bundleInstance, "attributed-to")
    if threat_actor.title is not None:
        info("Threat actor " + threat_actor.id_ + "'s title is used for name property")
        threat_actorInstance["name"] = threat_actor.title
    convert_controlled_vocabs_to_open_vocabs(threat_actorInstance, "labels", threat_actor.types, THREAT_ACTOR_LABEL_MAP, False)
    # TODO: add intended effect to description
    # TODO: add planning_and_operational_support to description
    if hasattr(threat_actor, "confidence"):
        add_confidence_property_to_description(threat_actorInstance, threat_actor.confidence)
    # TODO: motivation is complicated
    convert_controlled_vocabs_to_open_vocabs(threat_actorInstance, "sophistication", threat_actor.sophistications, THREAT_ACTOR_SOPHISTICATION_MAP, True)
    # handle relationships
    if threat_actor.observed_ttps is not None:
        handle_relationship_to_refs(threat_actor.observed_ttps, threat_actorInstance["id"], bundleInstance, "uses")
    if threat_actor.associated_campaigns is not None:
        handle_relationship_from_refs(threat_actor.associated_campaigns, threat_actorInstance["id"], bundleInstance, "attributed_to")
    # TODO: associated_actors
    process_information_source(threat_actor.information_source, threat_actorInstance, bundleInstance,
                               bundleInstance["created_by_ref"] if "created_by_ref" in bundleInstance else None)
    finish_basic_object(threat_actor.id_, threat_actorInstance, threat_actor)
    # TODO: add error messages for missing required properties
    return threat_actorInstance

# TTPs


def process_ttp_properties(sdoInstance, ttp, bundleInstance, kill_chains_available=True):
    # TODO: handle description and short description
    # TODO: handle intended_effect
    # TODO: title
    if ttp.exploit_targets is not None:
        handle_relationship_to_refs(ttp.exploit_targets, sdoInstance["id"], bundleInstance, "targets")
    if kill_chains_available:
        convert_kill_chains(ttp.kill_chain_phases, sdoInstance)
    if ttp.related_packages is not None:
        for p in ttp.related_packages:
            warn("TTP/Related_Packages on " + ttp.id_ + " not supported in STIX 2.0")
    process_information_source(ttp.information_source, sdoInstance, bundleInstance,
                               bundleInstance["created_by_ref"] if "created_by_ref" in bundleInstance else None)


def convert_attack_pattern(ap, ttp, bundleInstance):
    attack_PatternInstance = create_basic_object("attack-pattern", ap, ttp.timestamp, ttp.id_)
    if ap.title is not None:
        attack_PatternInstance["name"] = ap.title
    process_description_and_short_description(attack_PatternInstance, ap)
    if ap.capec_id is not None:
        attack_PatternInstance["external_references"] = [ {"source_name": "capec", "external_id": ap.capec_id}]
    process_ttp_properties(attack_PatternInstance, ttp, bundleInstance)
    finish_basic_object(ttp.id_, attack_PatternInstance, ap)
    # TODO: add error messages for missing required properties
    return attack_PatternInstance


def convert_malware_instance(mal, ttp, bundleInstance):
    malware_instanceInstance = create_basic_object("malware", mal, ttp.timestamp, ttp.id_)
    # TODO: names?
    if mal.title is not None:
        malware_instanceInstance["name"] = mal.title
    process_description_and_short_description(malware_instanceInstance, mal)
    convert_controlled_vocabs_to_open_vocabs(malware_instanceInstance, "labels", mal.types, MALWARE_LABELS_MAP, False)
    if mal.names is not None:
        for n in mal.names:
            if "name" not in malware_instanceInstance:
                malware_instanceInstance["name"] = str(n)
            else:
                warn("Only one name for malware is allowed for " + malware_instanceInstance["id"] + " in STIX 2.0 - used first one")
    # TODO: warning for MAEC content
    process_ttp_properties(malware_instanceInstance, ttp, bundleInstance)
    finish_basic_object(ttp.id_, malware_instanceInstance, mal)
    # TODO: add error messages for missing required properties
    return malware_instanceInstance


def convert_behavior(behavior, ttp, bundleInstance):
    behavior_generated = False
    if behavior.attack_patterns is not None:
        for ap in behavior.attack_patterns:
            bundleInstance["attack_patterns"].append(convert_attack_pattern(ap, ttp, bundleInstance))
            behavior_generated = True
    if behavior.malware_instances is not None:
        for mal in behavior.malware_instances:
            bundleInstance["malware"].append(convert_malware_instance(mal, ttp, bundleInstance))
            behavior_generated = True
    if behavior.exploits is not None:
        for e in behavior.exploits:
            warn("TTP/Behavior/Exploits/Exploit not supported in STIX 2.0")
    return behavior_generated


def convert_tool(tool, ttp, bundleInstance):
    toolInstance = create_basic_object("tool", tool, ttp.timestamp, ttp.id_)
    if tool.name is not None:
        toolInstance["name"] = tool.name
    process_description_and_short_description(toolInstance, tool)
    add_string_property_to_description(toolInstance, "vendor", tool.vendor)
    add_string_property_to_description(toolInstance, "service_pack", tool.service_pack)
    # TODO: add tool_specific_data to descriptor
    # TODO: add tool_hashes to descriptor
    # TODO: add tool_configuration to descriptor
    # TODO: add execution_environment to descriptor
    # TODO: add errors to descriptor
    # TODO: add compensation_model to descriptor
    add_string_property_to_description(toolInstance, "title", tool.title)
    convert_controlled_vocabs_to_open_vocabs(toolInstance,  "labels", tool.types, TOOL_LABELS_MAP, False)
    toolInstance["tool_version"] = tool.version
    process_ttp_properties(toolInstance, ttp, bundleInstance)
    finish_basic_object(ttp.id_, toolInstance, tool)
    # TODO: add error messages for missing required properties
    return toolInstance


def convert_infrastructure(infra, ttp, bundleInstance):
    ttp_timestamp = ttp.timestamp
    infrastructureInstance = create_basic_object("infrastructure", infra, ttp_timestamp)
    if infra.title is not None:
        infrastructureInstance["name"] = infra.title
    process_description_and_short_description(infrastructureInstance, infra)
    convert_controlled_vocabs_to_open_vocabs(infrastructureInstance, "labels", infra.types, {}, False)
    info("No 'first_seen' data on " + (infra.id_ if infra.id_ is not None else ttp.id_) + " - using timestamp")
    infrastructureInstance["first_seen"] = convert_timestamp(infra, ttp_timestamp)
    # TODO: observable_characterizations?
    process_ttp_properties(infrastructureInstance, ttp, bundleInstance)
    finish_basic_object(ttp.id_, infrastructureInstance, infra)
    # TODO: add error messages for missing required properties
    return infrastructureInstance


def convert_resources(resources, ttp, bundleInstance):
    resource_generated = False
    infrastructure_generated = False
    if resources.tools is not None:
        for t in resources.tools:
            bundleInstance["tools"].append(convert_tool(t, ttp, bundleInstance))
            resource_generated = True
    if resources.infrastructure is not None:
        if INFRASTRUCTURE_IN_20:
            bundleInstance["infrastructure"].append(convert_infrastructure(resources.infrastructure, ttp, bundleInstance))
            infrastructure_generated = True
        else:
            warn("Infrastructure is not part of of STIX 2.0 - " + ttp.id_)

    return resource_generated or infrastructure_generated


def convert_identity_for_victim_target(identity, ttp, bundleInstance):
    ttp_timestamp = ttp.timestamp
    identityInstance = convert_identity(identity, False)
    process_ttp_properties(identityInstance, ttp, bundleInstance, False)
    finish_basic_object(ttp.id_, identityInstance, identity)
    return identityInstance


def convert_victim_targeting(victim_targeting, ttp, bundleInstance, ttp_generated):
    if victim_targeting.targeted_systems:
        for v in victim_targeting.targeted_systems:
            warn("Targeted systems on " + ttp.id_ + " are not a victim target in STIX 2.0")
    if victim_targeting.targeted_information:
        for v in victim_targeting.targeted_information:
            warn("targeted information on " + ttp.id_ + " is not a victim target in STIX 2.0")
    if victim_targeting.targeted_technical_details is not None:
        for v in victim_targeting.targeted_technical_details:
            warn("targeted technical details on " + ttp.id_ + " are not a victim target in STIX 2.0")
    if victim_targeting.identity:
        identityInstance = convert_identity_for_victim_target(victim_targeting.identity, ttp, bundleInstance)
        bundleInstance["identities"].append(identityInstance)
        if ttp_generated:
            bundleInstance["relationships"].append(create_relationship(ttp.id_,
                                                                       identityInstance["id"],
                                                                       "targets",
                                                                       None))
            handle_relationship_to_objs([ttp], identityInstance.id_, bundleInstance, "targets")
        warn(ttp.id_ + " generated an identity associated with a victim")
        return True
    else:
        return ttp_generated


def convert_ttp(ttp, bundleInstance):
    ttp_generated = False
    if ttp.behavior is not None:
        ttp_generated = convert_behavior(ttp.behavior, ttp, bundleInstance)
    if ttp.resources is not None:
        ttp_generated = ttp_generated or convert_resources(ttp.resources, ttp, bundleInstance)
    if ttp.kill_chain_phases is not None:
        for phase in ttp.kill_chain_phases:
            warn("Kill chains in TTP on " + ttp.id_ + " are not in STIX 2.0")
    if ttp.victim_targeting is not None:
        ttp_generated = convert_victim_targeting(ttp.victim_targeting, ttp, bundleInstance, ttp_generated)
    if not ttp_generated and ttp.id_ is not None:
        warn(ttp.id_ + " didn't yield any STIX 2.0 object")

# package


def handle_embedded_object(obj, bundleInstance):
    # campaigns
    if isinstance(obj, Campaign):
        camp20 = convert_campaign(obj, bundleInstance)
        bundleInstance["campaigns"].append(camp20)
    # coas
    elif isinstance(obj, CourseOfAction):
        coa20 = convert_course_of_action(obj, bundleInstance)
        bundleInstance["courses_of_action"].append(coa20)
    # exploit-targets
    elif isinstance(obj, ExploitTarget):
        convert_exploit_target(obj, bundleInstance)
    # identities
    elif isinstance(obj, Identity) or isinstance(obj, CIQIdentity3_0Instance):
        ident20 = convert_identity(obj)
        bundleInstance["identities"].append(ident20)
    # incidents
    elif INCIDENT_IN_20 and isinstance(obj, Incident):
        i20 = convert_incident(obj, bundleInstance)
        bundleInstance["incidents"].append(i20)
    # indicators
    elif isinstance(obj, Indicator):
        i20 = convert_indicator(obj, bundleInstance)
        bundleInstance["indicators"].append(i20)
    # observables
    elif isinstance(obj, Observable):
        o_d20 = convert_observable_data(obj, bundleInstance)
        bundleInstance["observed_data"].append(o_d20)
    # reports
    elif isinstance(obj, Report):
        report20 = convert_report(obj, bundleInstance)
        bundleInstance["reports"].append(report20)
    # threat actors
    elif isinstance(obj, ThreatActor):
        ta20 = convert_threat_actor(obj, bundleInstance)
        bundleInstance["threat-actors"].append(ta20)
    # ttps
    elif isinstance(obj, TTP):
        convert_ttp(obj, bundleInstance)


def initialize_bundle_lists(bundleInstance):
    bundleInstance["relationships"] = []
    bundleInstance["campaigns"] = []
    bundleInstance["courses_of_action"] = []
    bundleInstance["vulnerabilities"] = []
    bundleInstance["identities"] = []
    bundleInstance["incidents"] = []
    bundleInstance["indicators"] = []
    bundleInstance["reports"] = []
    bundleInstance["observed_data"] = []
    bundleInstance["threat-actors"] = []
    bundleInstance["attack_patterns"] = []
    bundleInstance["malware"] = []
    bundleInstance["tools"] = []
    bundleInstance["infrastructure"] = []
    bundleInstance["victim_targets"] = []


def finalize_bundle(bundleInstance):
    if KILL_CHAINS_PHASES != {}:
        for ind20 in bundleInstance["indicators"]:
            if "kill_chain_phases" in ind20:
                fixed_kill_chain_phases = []
                for kcp in ind20["kill_chain_phases"]:
                    if isinstance(kcp, str):
                        try:
                            kill_chain_phase_in_20 = KILL_CHAINS_PHASES[kcp]
                            fixed_kill_chain_phases.append(kill_chain_phase_in_20)
                        except:
                            error("Dangling kill chain phase id")
                    else:
                        fixed_kill_chain_phases.append(kcp)
                ind20["kill_chain_phases"] = fixed_kill_chain_phases
    # ttps

    # TODO: fix created_by_ref
    # TODO: fix other embedded relationships
    for r in bundleInstance["reports"]:
        fixed_refs = []
        for ref in r["report_refs"]:
            if reference_needs_fixing(ref):
                if ref in IDS_TO_NEW_IDS:
                    fixed_refs.append(IDS_TO_NEW_IDS[ref])
                else:
                    fixed_refs.append(ref)
        r["report_refs"] = fixed_refs

    if not bundleInstance["campaigns"]:
        del bundleInstance["campaigns"]
    if not bundleInstance["courses_of_action"]:
        del bundleInstance["courses_of_action"]
    if not bundleInstance["vulnerabilities"]:
        del bundleInstance["vulnerabilities"]
    if not bundleInstance["identities"]:
        del bundleInstance["identities"]
    if not bundleInstance["incidents"]:
        del bundleInstance["incidents"]
    if not bundleInstance["indicators"]:
        del bundleInstance["indicators"]
    if not bundleInstance["observed_data"]:
        del bundleInstance["observed_data"]
    if not bundleInstance["reports"]:
        del bundleInstance["reports"]
    if not bundleInstance["threat-actors"]:
        del bundleInstance["threat-actors"]
    if not bundleInstance["attack_patterns"]:
        del bundleInstance["attack_patterns"]
    if not bundleInstance["malware"]:
        del bundleInstance["malware"]
    if not bundleInstance["tools"]:
        del bundleInstance["tools"]
    if not bundleInstance["infrastructure"]:
        del bundleInstance["infrastructure"]
    if not bundleInstance["victim_targets"]:
        del bundleInstance["victim_targets"]

    if not bundleInstance["relationships"]:
        del bundleInstance["relationships"]
    else:
        fix_relationships(bundleInstance["relationships"])

    del bundleInstance["created_by_ref"]


def convert_package(stixPackage):
    bundleInstance = {"type": "bundle"}
    bundleInstance["id"] = generateSTIX20Id("bundle", stixPackage.id_)
    bundleInstance["spec_version"] = "2.0"
    initialize_bundle_lists(bundleInstance)
    if hasattr(stixPackage.stix_header, "information_source") and stixPackage.stix_header.information_source is not None:
        process_information_source(stixPackage.stix_header.information_source, bundleInstance, bundleInstance, None)
    else:
        bundleInstance["created_by_ref"] = None

    # TODO: other header stuff

    # do observables first, especially before indicators!

    # observables
    if stixPackage.observables is not None:
        for o_d in stixPackage.observables:
            o_d20 = convert_observable_data(o_d, bundleInstance)
            bundleInstance["observed_data"].append(o_d20)

    # campaigns
    if stixPackage.campaigns:
        for camp in stixPackage.campaigns:
            camp20 = convert_campaign(camp, bundleInstance)
            bundleInstance["campaigns"].append(camp20)

    # coas
    if stixPackage.courses_of_action:
        for coa in stixPackage.courses_of_action:
            coa20 = convert_course_of_action(coa, bundleInstance)
            bundleInstance["courses_of_action"].append(coa20)

    # exploit-targets
    if stixPackage.exploit_targets:
        for et in stixPackage.exploit_targets:
            convert_exploit_target(et, bundleInstance)



    # incidents
    if INCIDENT_IN_20:
        if stixPackage.incidents:
            for i in stixPackage.incidents:
                i20 = convert_incident(i, bundleInstance)
                bundleInstance["incidents"].append(i20)

    # indicators
    if stixPackage.indicators:
        for i in stixPackage.indicators:
            i20 = convert_indicator(i, bundleInstance)
            bundleInstance["indicators"].append(i20)

    # observables
    if stixPackage.observables:
        for o_d in stixPackage.observables:
            o_d20 = convert_observable_data(o_d, bundleInstance)
            bundleInstance["observed_data"].append(o_d20)

    # reports
    if stixPackage.reports:
        for report in stixPackage.reports:
            report20 = convert_report(report, bundleInstance)
            bundleInstance["reports"].append(report20)

    # threat actors
    if stixPackage.threat_actors:
        for ta in stixPackage.threat_actors:
            ta20 = convert_threat_actor(ta, bundleInstance)
            bundleInstance["threat-actors"].append(ta20)

    # ttps
    if stixPackage.ttps:
        for ttp in stixPackage.ttps:
            convert_ttp(ttp, bundleInstance)

    # kill chains
        if stixPackage.ttps.kill_chains:
            for kc in stixPackage.ttps.kill_chains:
                process_kill_chain(kc)

    # identities

    finalize_bundle(bundleInstance)
    return bundleInstance


def convert_file(inFileName):
    stixPackage = EntityParser().parse_xml(inFileName)
    if isinstance(stixPackage, STIXPackage):
        print json.dumps(convert_package(stixPackage), indent=4, separators=(',', ': '))

if __name__ == '__main__':
    convert_file(sys.argv[1])


