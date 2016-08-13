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
from stix.ttp.attack_pattern import (AttackPattern)
from cybox.core import Observable
from stix.extensions.test_mechanism.yara_test_mechanism import YaraTestMechanism
from stix.extensions.test_mechanism.snort_test_mechanism import SnortTestMechanism

import sys
import python_jsonschema_objects as pjs
import json
from datetime import datetime
import uuid
import base64

from convert_cybox import convert_cybox_object
from convert_pattern import convert_observable_to_pattern
from utils import info, warn, error

SQUIRREL_GAPS_IN_DESCRIPTIONS = True

COA_LABEL_MAP = {}

INCIDENT_LABEL_MAP = {}

INDICATOR_LABEL_MAP = {}

MALWARE_LABELS_MAP = {}

ROLES_MAP = {}

SECTORS_MAP = {}

THREAT_ACTOR_LABEL_MAP = {}

THREAT_ACTOR_SOPHISTICATION_MAP = {}

TOOL_LABELS_MAP = {}

IDENTITIES = {}


# collect kill chains

KILL_CHAINS_PHASES = {}

def process_kill_chain(kc):
    for kcp in kc.kill_chain_phases:
        KILL_CHAINS_PHASES[kcp.phase_id] = { "kill_chain_name" : kc.name, "name": kcp.name}

def generateSTIX20Id(stix20SOName, stix12ID = None):
    if stix12ID is None:
        return stix20SOName + "--" + str(uuid.uuid4())
    else:
        uuidArray = stix12ID.split("-", 1)
        return stix20SOName + "--" + uuidArray[1]

# identities

NOBODY_SOURCE_UUID = "source--ea99d4d4-1ae7-4120-9ebe-67ed4783fb36"

NOBODY_SOURCE = {
    "type": "source",
    "name": "Nobody",
    "id": NOBODY_SOURCE_UUID,
    "entity_class": "individual"
}

NOBODY_USED = False

def get_simple_name_from_identity(identity):
    # create a source object
    return identity.name

def get_regions_from_ciq_addresses(addresses):
    return []

def get_identity_info_from_ciq_for_victim_target(identity, vt):
    if identity.idref is not None:
        # fix ref later
        return identity.idref
    if identity.name is not None:
        vt["name"] = identity.name
    if identity.roles is not None:
        convert_controlled_vocabs_to_open_vocabs(vt, "roles", identity.roles, ROLES_MAP, False)
    ciq_info = identity._specification
    if ciq_info.party_name is not None:
        warn("ciq name found, overriding")
        vt["name"] = ciq_info.party_name
    if not hasattr(vt, "name"):
        error("victim-target must have a name, using 'none'")
        vt["name"] = "None"
    if ciq_info.organisation_info is not None:
        convert_to_open_vocabs(vt, "sectors", ciq_info.organisation_info.industry_type, SECTORS_MAP)
    if ciq_info.addresses is not None:
        vt["regions"] = get_regions_from_ciq_addresses(ciq_info.addresses)

def get_identity_ref(identity):
    pass

def process_information_source(information_source, so):
    if information_source is not None:
        if information_source.identity is not None:
            so["created_by_ref"] = get_identity_ref(information_source.identity)
        else:
            so["created_by_ref"] = NOBODY_SOURCE_UUID
            NOBODY_USED = True
    # add to decription field

def convert_timestamp(entity):
    try:
        if entity.timestamp is not None:
            return str(entity.timestamp)
        else:
            warn("timestamp not available, using current time")
            return str(datetime.now().isoformat())
    except AttributeError:
        warn("no timestamp on this STIX 1.x object, using current time")
        return str(datetime.now().isoformat())

def map_vocabs_to_label(t, vocab_map):
    try:
        return vocab_map[t]
    except KeyError:
        return t

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
        so["description"] += process_structured_text_list(entity.descriptions)
        if SQUIRREL_GAPS_IN_DESCRIPTIONS and entity.short_description is not None:
            warn("The Short_Description property is no longer supported in STIX.  Added the text to the description property")
            so["description"] += "\nShort Description: \n" + process_structured_text_list(entity.short_descriptions)
    elif entity.short_description is not None:
        so["description"] = process_structured_text_list(entity.short_descriptions)

def create_basic_object(stix20_type, stix1x_obj):
    instance = {"type": stix20_type}
    instance["id"] = generateSTIX20Id(stix20_type, stix1x_obj.id_ if hasattr(stix1x_obj, "id_") else None)
    instance["version"] = 1  # need to see about versioning
    instance["created"] = convert_timestamp(stix1x_obj)
    instance["description"] = ""
    instance["external_references"] = []
    return instance

def remove_empty_common_values(instance):
    if "description" in instance and instance["description"] == "":
        del instance["description"]
    if instance["external_references"] == []:
        del instance["external_references"]

def finish_basic_object(old_id, instance, stix1x_obj):
    record_ids(old_id, instance["id"])
    remove_empty_common_values(instance)
    if hasattr(stix1x_obj, "handling") and stix1x_obj.handling is not None:
        warn("Handling not implemented, yet")
    if hasattr(stix1x_obj, "related_packages") and stix1x_obj.related_packages is not None:
        for p in stix1x_obj.related_packages:
            warn("Related_Packages property no longer supported in STIX")

# Relationships

IDS_TO_NEW_IDS = {}

def record_ids(id, new_id):
    if id in IDS_TO_NEW_IDS.keys():
        error(id + " is already associated with a new id")
    else:
        IDS_TO_NEW_IDS[id] = new_id

def create_relationship(source_ref, target_ref, verb, rel_obj):
    relationshipInstance = create_basic_object("relationship", rel_obj)
    relationshipInstance["source_ref"] = source_ref
    relationshipInstance["target_ref"] = target_ref
    relationshipInstance["name"] = verb
    if rel_obj.relationship is not None:
        relationshipInstance["description"] = rel_obj.relationship.value
    # handle description
    remove_empty_common_values(relationshipInstance)
    return relationshipInstance

def handle_relationship_to_refs(refs, source_id, bundleInstance, verb):
    for ref in refs:
        if ref.item.idref is None:
            # embedded
            target_id = handle_embedded_object(ref.item, bundleInstance)
            bundleInstance["relationships"].append(create_relationship(source_id,
                                                                       ref.item.id_,
                                                                       verb,
                                                                       ref))
        elif ref.item.idref in IDS_TO_NEW_IDS.keys():
            to_ref = IDS_TO_NEW_IDS[ref.item.idref]
            bundleInstance["relationships"].append(create_relationship(source_id,
                                                                       to_ref,
                                                                       verb,
                                                                       ref))
        else:
            # a forward reference, fix later
            bundleInstance["relationships"].append(create_relationship(source_id,
                                                                       ref.item.idref,
                                                                       verb,
                                                                       ref))

def handle_relationship_from_refs(refs, target_id, bundleInstance, verb):
    for ref in refs:
        if ref.item.idref is None:
            # embedded
            source_id = handle_embedded_object(ref.item, bundleInstance)
            bundleInstance["relationships"].append(create_relationship(ref.item.id_,
                                                                       target_id,
                                                                       verb,
                                                                       ref))
        elif ref.item.idref in IDS_TO_NEW_IDS.keys():
            from_ref = IDS_TO_NEW_IDS[ref.item.idref]
            bundleInstance["relationships"].append(create_relationship(from_ref,
                                                                       target_id,
                                                                       verb,
                                                                       ref))
        else:
            # a forward reference, fix later
            bundleInstance["relationships"].append(create_relationship(ref.item.idref,
                                                                       target_id,
                                                                       verb,
                                                                       ref))

def reference_needs_fixing(ref):
    return ref.find("--") == -1

def fix_relationships(relationships):
    for ref in relationships:
        if reference_needs_fixing(ref["source_ref"]):
            if ref["source_ref"] in IDS_TO_NEW_IDS.keys():
                ref["source_ref"] = IDS_TO_NEW_IDS[ref["source_ref"]]
            else:
                error("Dangling source reference " +  ref["source_ref"])
        if reference_needs_fixing(ref["target_ref"]):
            if ref["target_ref"] in IDS_TO_NEW_IDS.keys():
                ref["target_ref"] = IDS_TO_NEW_IDS[ref["target_ref"]]
            else:
                error("Dangling target reference " + ref["target_ref"])

# campaign

def convert_campaign(camp, bundleInstance):
    campaignInstance = create_basic_object("campaign", camp)
    process_description_and_short_description(campaignInstance, camp)
    if camp.names is not None:
        campaignInstance["aliases"] = []
        for name in camp.names:
            campaignInstance["aliases"].append(name)
        if campaignInstance["aliases"] == []:
            del campaignInstance["aliases"]
    # add intended effect to description
    # add status to description
    # add confidence
    if camp.activity is not None:
        warn("Campaign/Activity not supported in STIX 2.0")
    if camp.related_ttps is not None:
        handle_relationship_to_refs(camp.related_ttps, campaignInstance["id"], bundleInstance, "uses")
    if camp.related_incidents is not None:
        handle_relationship_from_refs(camp.related_incidents, campaignInstance["id"], bundleInstance, "attributed-to")
    if camp.related_indicators is not None:
        handle_relationship_from_refs(camp.related_indicators, campaignInstance["id"], bundleInstance, "indicates")
    if camp.attribution is not None:
        for att in camp.attribution:
            handle_relationship_from_refs(att, campaignInstance["id"], bundleInstance, "attributed-to")
    # associated campaigns
    process_information_source(camp.information_source, campaignInstance)
    finish_basic_object(camp.id_, campaignInstance, camp)
    return campaignInstance

# course of action

def convert_course_of_action(coa, bundleInstance):
    coaInstance = create_basic_object("course_of_action", coa)
    process_description_and_short_description(coaInstance, coa)
    coaInstance["name"] = coa.title
    # stage
    convert_controlled_vocabs_to_open_vocabs(coaInstance, "labels", [ coa.type_ ], COA_LABEL_MAP, False)
    # objective into description
    # parameter observables?
    if coa.structured_coa:
        warn("Structured COAs are not supported in STIX 2.0")
    # impact into description
    # cost into description
    # efficacy into description
    process_information_source(coa.information_source, coaInstance)
    # related coas
    finish_basic_object(coa.id_, coaInstance, coa)
    return coaInstance

# exploit target

def convert_vulnerability(v, et):
    vulnerabilityInstance = create_basic_object("vulnerability", v)
    process_description_and_short_description(vulnerabilityInstance, v)
    if v.cve_id is not None:
        vulnerabilityInstance["external_references"].append({"source_name": "cve", "external_id": v.cve_id})
    if v.osvdb_id is not None:
        vulnerabilityInstance["external_references"].append({"source_name": "osvdb", "external_id": v.osvdb_id})
    # source?
    # CVSS score into description
    # date times into description
    # affected software into description
    if v.references is not None:
        # this may not work
        for ref in v.references:
            vulnerabilityInstance["external_references"].append({"url": ref.reference})
    # handle et fields
    finish_basic_object(et.id_, vulnerabilityInstance, v)
    return vulnerabilityInstance

def convert_exploit_target(et, bundleInstance):
    if et.vulnerabilities is not None:
        for v in et.vulnerabilities:
            bundleInstance["vulnerabilities"].append(convert_vulnerability(v, et))
    if et.weaknesses is not None:
        for w in et.weaknesses:
            warn("ExploitTarget/Weaknesses not supported in STIX 2.0")
    if et.configuration is not None:
        for c in et.configuration:
            warn("ExploitTarget/Weaknesses not supported in STIX 2.0")

# incident

def convert_incident(incident, bundleInstance):
    incidentInstance = create_basic_object("incident", incident)
    process_description_and_short_description(incidentInstance, incident)
    incidentInstance["name"] = incident.title
    if incident.external_ids is not None:
        for id in incident.external_ids:
            incidentInstance["external_references"].append({"source_name": id.external_id.source, "external_id": id.external_id.value })
    # time
    convert_controlled_vocabs_to_open_vocabs(incidentInstance, "labels", incident.categories, INCIDENT_LABEL_MAP, False)
    if incident.leveraged_ttps is not None:
        warn("Using related-to")
        handle_relationship_to_refs(incident.leveraged_ttps, incidentInstance["id"], bundleInstance, "related-to")

    # reporter
    # responder
    # coordinator
    # victim
    # affected_assets
    # impact_assessment
    # status
    finish_basic_object(incident.id_, incidentInstance, incident)
    return incidentInstance

# indicator

def convert_kill_chains(kill_chain_phases, indicatorInstance):
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
            indicatorInstance["kill_chain_phases"] = kill_chain_phases_20

def convert_test_mechanism(indicator, indicatorInstance):
    if indicator.test_mechanisms is not None:
        if hasattr(indicatorInstance, "pattern"):
            warn("only one type pattern can be specified - using cybox")
        else:
            for tm in indicator.test_mechanisms:
                if hasattr(indicatorInstance, "pattern"):
                    warn("Only one alternative test mechanism allowed in STIX 2.0 - used first one, which was " +
                         indicatorInstance["pattern_lang"])
                else:
                    if isinstance(tm, YaraTestMechanism):
                        indicatorInstance["pattern"] = base64.b64encode(tm.rule.value)
                        indicatorInstance["pattern_lang"] = "yara"
                    elif isinstance(tm, SnortTestMechanism):
                        indicatorInstance["pattern"] = ""
                        first_rule = True
                        for rule in tm.rules:
                            indicatorInstance["pattern"] += (", " if not first_rule else "") + base64.b64encode(rule.value)
                            first_rule = False
                        indicatorInstance["pattern_lang"] = "snort"

def convert_indicator(indicator, bundleInstance):
    indicatorInstance = create_basic_object("indicator", indicator)
    process_description_and_short_description(indicatorInstance, indicator)
    convert_controlled_vocabs_to_open_vocabs(indicatorInstance, "labels", indicator.indicator_types, INDICATOR_LABEL_MAP, False)
    indicatorInstance["name"] = indicator.title
    if indicator.alternative_id is not None:
        for id in indicator.alternative_id:
            indicatorInstance["external_references"].append({"source_name": "alternative_id", "external_id": id})
    if indicator.valid_time_positions is not None:
        for window in indicator.valid_time_positions:
            if indicatorInstance["valid_from"] is None:
                indicatorInstance["valid_from"] = window.start_time.value
                indicatorInstance["valid_from_precision"] = window.start_time.precision
                indicatorInstance["valid_until"] = window.end_time.value
                indicatorInstance["valid_until_precision"] = window.end_time.precision
            else:
                warn("Only one valid time window allowed in STIX 2.0 - used first one")
    convert_kill_chains(indicator.kill_chain_phases, indicatorInstance)
    # indicated ttps
    # likely impact
    # confidence
    # sightings
    if indicator.observable is not None:
        indicatorInstance["pattern"] = convert_observable_to_pattern(indicator.observable)
        indicatorInstance["pattern_lang"] = "cybox"
    convert_test_mechanism(indicator, indicatorInstance)
    process_information_source(indicator.producer, indicatorInstance)
    if indicator.suggested_coas is not None:
        warn("Using related-to")
        handle_relationship_to_refs(indicator.suggested_coas, indicatorInstance["id"], bundleInstance, "related-to")
    # related indicators
    if indicator.related_campaigns is not None:
        handle_relationship_to_refs(indicator.related_campaigns, indicatorInstance["id"], bundleInstance, "attributed-to")
    finish_basic_object(indicator.id_, indicatorInstance, indicator)
    return indicatorInstance

# observables

def convert_observable_data(obs, bundleInstance):
    observed_data_instance = create_basic_object("observable-data", obs)
    cyboxContainer = { "type": "cybox-container", "spec_version": "3.0"}
    observed_data_instance["cybox"] = convert_cybox_object(obs.object_, cyboxContainer)
    finish_basic_object(obs.id_, observed_data_instance, obs)
    return observed_data_instance

# report

def convert_report(report, bundleInstance):
    info("reports not implemented, yet")

# threat actor

def convert_threat_actor(threat_actor, bundleInstance):
    threat_actorInstance = create_basic_object("threat-actor", threat_actor)
    process_description_and_short_description(threat_actorInstance, threat_actor)
    # threat_actorInstance["modified"]
    if threat_actor.identity is not None:
        threat_actorInstance["name"] = get_simple_name_from_identity(threat_actor.identity)
        if threat_actor.title is not None:
            # add title to description
            warn("Threat Actor title and identity both specified - used idenitity")
    elif threat_actor.title is not None:
        threat_actorInstance["name"] = threat_actor.title
    convert_controlled_vocabs_to_open_vocabs(threat_actorInstance, "labels", threat_actor.types, THREAT_ACTOR_LABEL_MAP, False)
    # add intended effect to description
    # add Planning_And_Operational_Support to description
    # add confidence
    if threat_actorInstance["description"] == "":
        del threat_actorInstance["description"]
    # motivation is complicated
    convert_controlled_vocabs_to_open_vocabs(threat_actorInstance, "sophistication", threat_actor.sophistications, THREAT_ACTOR_SOPHISTICATION_MAP, True)
    # handle relationships
    if threat_actor.observed_ttps is not None:
        handle_relationship_to_refs(threat_actor.observed_ttps, threat_actorInstance["id"], bundleInstance, "uses")
    if threat_actor.associated_campaigns is not None:
        handle_relationship_from_refs(threat_actor.associated_campaigns, threat_actorInstance["id"], bundleInstance, "attributed_to")
    # associated_actors
    process_information_source(threat_actor.information_source, threat_actorInstance)
    # handle no information source
    finish_basic_object(threat_actor.id_, threat_actorInstance, threat_actor)
    return threat_actorInstance

# TTPs

def convert_attack_pattern(ap, bundleInstance, ttp):
    attack_PatternInstance = create_basic_object("attack-pattern", ap)
    process_description_and_short_description(attack_PatternInstance, ap)
    if ap.capec_id is not None:
        attack_PatternInstance["external_references"] = [ {"source_name": "capec", "external_id": ap.capec_id}]
    # handle ttp properties
    finish_basic_object(ttp.id_, attack_PatternInstance, ap)
    return attack_PatternInstance

def convert_malware_instance(mal,bundleInstance, ttp):
    malware_instanceInstance = create_basic_object("malware", mal)
    process_description_and_short_description(malware_instanceInstance, mal)
    convert_controlled_vocabs_to_open_vocabs(malware_instanceInstance, "labels", mal.types, MALWARE_LABELS_MAP, False)
    # handle ttp properties
    finish_basic_object(ttp.id_, malware_instanceInstance, mal)
    return malware_instanceInstance

def convert_behavior(behavior, bundleInstance, ttp):
    if behavior.attack_patterns is not None:
        for ap in behavior.attack_patterns:
            bundleInstance["attack_patterns"].append(convert_attack_pattern(ap, bundleInstance, ttp))
    if behavior.malware_instances is not None:
        for mal in behavior.malware_instances:
            bundleInstance["malware"].append(convert_malware_instance(mal, bundleInstance, ttp))
    if behavior.exploits is not None:
        for e in behavior.exploits:
            warn("TTP/Behavior/Exploits/Exploit not supported in STIX 2.0")

def convert_tool(tool, ttp):
    toolInstance = create_basic_object("tool", tool)
    process_description_and_short_description(toolInstance, tool)
    convert_controlled_vocabs_to_open_vocabs(toolInstance,  "labels", tool.types, TOOL_LABELS_MAP, False)
    toolInstance["version"] = tool.version
    # handle ttp properties
    finish_basic_object(ttp.id_, toolInstance, tool)
    return toolInstance

def convert_infrastructure(infra, ttp):
    infrastructureInstance = create_basic_object("infrastructure", infra)
    process_description_and_short_description(infrastructureInstance, infra)
    convert_controlled_vocabs_to_open_vocabs(infrastructureInstance, "labels", infra.types, {}, False)
    # observable_characterizations
    # handle ttp properties
    finish_basic_object(ttp.id_, infrastructureInstance, infra)
    return infrastructureInstance

def convert_resources(resources, bundleInstance, ttp):
    if resources.tools is not None:
        for t in resources.tools:
            bundleInstance["tools"].append(convert_tool(t, ttp))
    if resources.infrastructure is not None:
        bundleInstance["infrastructure"].append(convert_infrastructure(resources.infrastructure, ttp))

def convert_identity_to_victim_target(victim_target, ttp):
    victimInstance = create_basic_object("victim_target", victim_target)
    victimInstance["sectors"] = []
    get_identity_info_from_ciq_for_victim_target(victim_target, victimInstance)
    # handle ttp properties
    finish_basic_object(ttp.id_, victimInstance, victim_target)
    return victimInstance

def convert_victim_targeting(victim_targeting, bundleInstance, ttp):
    if victim_targeting.targeted_systems is not None:
        for v in victim_targeting.targeted_systems:
            warn("targeted systems are not a victim target in STIX 2.0")
    if victim_targeting.targeted_information is not None:
        for v in victim_targeting.targeted_information:
            warn("targeted information is not a victim target in STIX 2.0")
    if victim_targeting.targeted_technical_details is not None:
        for v in victim_targeting.targeted_technical_details:
            warn("targeted technical details are not a victim target in STIX 2.0")
    if victim_targeting.identity is not None:
        bundleInstance["victim_targets"].append(convert_identity_to_victim_target(victim_targeting.identity, ttp))

def convert_ttp(ttp, bundleInstance):
    if ttp.behavior is not None:
        convert_behavior(ttp.behavior, bundleInstance, ttp)
    if ttp.resources is not None:
        convert_resources(ttp.resources, bundleInstance, ttp)
    if ttp.related_packages is not None:
        for p in ttp.related_packages:
            warn("TTP/Related_Packages not supported in STIX 2.0")
    if ttp.kill_chain_phases is not None:
        for phase in ttp.kill_chain_phases:
            warn("kill chains in TTP are not handled yet")
    if ttp.victim_targeting is not None:
        convert_victim_targeting(ttp.victim_targeting, bundleInstance, ttp)

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
    # incidents
    elif isinstance(obj, Incident):
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
            if "kill_chain_phases" in ind20.keys():
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


    if bundleInstance["campaigns"] == []:
        del bundleInstance["campaigns"]
    if bundleInstance["courses_of_action"] == []:
        del bundleInstance["courses_of_action"]
    if bundleInstance["vulnerabilities"] == []:
        del bundleInstance["vulnerabilities"]
    if bundleInstance["incidents"] == []:
        del bundleInstance["incidents"]
    if bundleInstance["indicators"] == []:
        del bundleInstance["indicators"]
    if bundleInstance["observed_data"] == []:
        del bundleInstance["observed_data"]
    if bundleInstance["reports"] == []:
        del bundleInstance["reports"]
    if bundleInstance["threat-actors"] == []:
        del bundleInstance["threat-actors"]
    if bundleInstance["attack_patterns"] == []:
        del bundleInstance["attack_patterns"]
    if bundleInstance["malware"] == []:
        del bundleInstance["malware"]
    if bundleInstance["tools"] == []:
        del bundleInstance["tools"]
    if bundleInstance["infrastructure"] == []:
        del bundleInstance["infrastructure"]
    if bundleInstance["victim_targets"] == []:
        del bundleInstance["victim_targets"]

    if bundleInstance["relationships"] == []:
        del bundleInstance["relationships"]
    else:
        fix_relationships(bundleInstance["relationships"])

    remove_empty_common_values(bundleInstance)

def convert_package(stixPackage):
    bundleInstance = create_basic_object("bundle", stixPackage)
    bundleInstance["spec_version"] = "2.0"
    initialize_bundle_lists(bundleInstance)
    # campaigns
    for camp in stixPackage.campaigns:
        camp20 = convert_campaign(camp, bundleInstance)
        bundleInstance["campaigns"].append(camp20)

    # coas
    for coa in stixPackage.courses_of_action:
        coa20 = convert_course_of_action(coa, bundleInstance)
        bundleInstance["courses_of_action"].append(coa20)

    # exploit-targets
    for et in stixPackage.exploit_targets:
        convert_exploit_target(et, bundleInstance)

    # incidents
    for i in stixPackage.incidents:
        i20 = convert_incident(i, bundleInstance)
        bundleInstance["incidents"].append(i20)

    # indicators
    for i in stixPackage.indicators:
        i20 = convert_indicator(i, bundleInstance)
        bundleInstance["indicators"].append(i20)

    # observables
    if stixPackage.observables is not None:
        for o_d in stixPackage.observables:
            o_d20 = convert_observable_data(o_d, bundleInstance)
            bundleInstance["observed_data"].append(o_d20)

    # reports
    for report in stixPackage.reports:
        report20 = convert_report(report, bundleInstance)
        bundleInstance["reports"].append(report20)

    # sources

    if NOBODY_USED:
        # add Nobody source
        bundleInstance["sources"] = [ NOBODY_SOURCE ]

    # threat actors
    for ta in stixPackage.threat_actors:
        ta20 = convert_threat_actor(ta, bundleInstance)
        bundleInstance["threat-actors"].append(ta20)

    # ttps
    for ttp in stixPackage.ttps:
        convert_ttp(ttp, bundleInstance)

    # kill chains
    if stixPackage.ttps.kill_chains is not None:
        for kc in stixPackage.ttps.kill_chains:
            process_kill_chain(kc)


    finalize_bundle(bundleInstance)
    return bundleInstance

def convert_file(inFileName):
    stixPackage = EntityParser().parse_xml(inFileName)
    if isinstance(stixPackage, STIXPackage):
        print json.dumps(convert_package(stixPackage), indent=4, separators=(',', ': '))

if __name__ == '__main__':
    convert_file(sys.argv[1])


