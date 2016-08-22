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

INFRASTRUCTURE_IN_20 = False

INCIDENT_IN_20 = True

# TODO: specify controlled vocab mappings

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

def map_1x_type_to_20(stix1xType):
    return stix1xType

def generateSTIX20Id(stix20SOName, stix12ID = None):
    if stix12ID is None:
        return stix20SOName + "--" + str(uuid.uuid4())
    else:
        namespace_type_uuid = stix12ID.split("-", 1)
        if stix20SOName is None:
            type = namespace_type_uuid[0].split(":", 1)
            if type[1] == "ttp" or type[1] == "et":
                error("Unable to determine the STIX 2.0 type for " + stix12ID)
            else:
                return map_1x_type_to_20(type[1]) + "--" + namespace_type_uuid[1]
        else:
            return stix20SOName + "--" + namespace_type_uuid[1]

# identities

NOBODY_IDENTITY_UUID = "identity--ea99d4d4-1ae7-4120-9ebe-67ed4783fb36"

NOBODY_IDENTITY = {
    "type": "identity",
    "name": "Nobody",
    "id": NOBODY_IDENTITY_UUID,
    "entity_class": "individual"
}

NOBODY_USED = False

def get_simple_name_from_identity(identity):
    # create a identity object
    return identity.name



def get_identity_ref(identity, bundleInstance):
    if identity.idref is not None:
        # fix later
        return identity.idref
    elif identity.id_ is not None:
        return handle_embedded_object(identity, bundleInstance)

def process_information_source(information_source, so):
    if information_source is not None:
        if information_source.identity is not None:
            so["created_by_ref"] = get_identity_ref(information_source.identity, so)
        else:
            so["created_by_ref"] = NOBODY_IDENTITY_UUID
            NOBODY_USED = True
    else:
        so["created_by_ref"] = NOBODY_IDENTITY_UUID
        NOBODY_USED = True
    # TODO: add to description

def convert_timestamp(entity, parent_timestamp=None):
    if hasattr(entity, "timestamp"):
        if entity.timestamp is not None:
            # TODO: make sure its in the correct format
            return str(entity.timestamp)
        else:
            warn("Timestamp not available, using current time")
            return str(datetime.now().isoformat())
    elif parent_timestamp is not None:
        info("Using enclosing object timestamp")
        # TODO: make sure its in the correct format
        return str(parent_timestamp)
    else:
        warn("Timestamp not available, using current time")
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

def create_basic_object(stix20_type, stix1x_obj, ttp_timestamp=None):
    instance = {"type": stix20_type}
    instance["id"] = generateSTIX20Id(stix20_type, stix1x_obj.id_ if hasattr(stix1x_obj, "id_") else None)
    instance["version"] = 1  # need to see about versioning
    timestamp = convert_timestamp(stix1x_obj, ttp_timestamp)
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
        error(id + " is already associated with a new id " + IDS_TO_NEW_IDS[id])
    else:
        # info("associating " + new_id + " with " + id)
        IDS_TO_NEW_IDS[id] = new_id

def create_relationship(source_ref, target_ref, verb, rel_obj, parent_timestamp):
    relationshipInstance = create_basic_object("relationship", rel_obj, parent_timestamp)
    relationshipInstance["source_ref"] = source_ref
    relationshipInstance["target_ref"] = target_ref
    relationshipInstance["name"] = verb
    if rel_obj.relationship is not None:
        relationshipInstance["description"] = rel_obj.relationship.value
    # handle description
    remove_empty_common_values(relationshipInstance)
    return relationshipInstance

def handle_relationship_to_refs(refs, source_id, bundleInstance, verb, parent_timestamp=None):
    for ref in refs:
        if ref.item.idref is None:
            # embedded
            target_id = handle_embedded_object(ref.item, bundleInstance)
            bundleInstance["relationships"].append(create_relationship(source_id,
                                                                       ref.item.id_,
                                                                       verb,
                                                                       ref,
                                                                       parent_timestamp))
        elif ref.item.idref in IDS_TO_NEW_IDS.keys():
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
            source_id = handle_embedded_object(ref.item, bundleInstance)
            bundleInstance["relationships"].append(create_relationship(ref.item.id_,
                                                                       target_id,
                                                                       verb,
                                                                       ref,
                                                                       parent_timestamp))
        elif ref.item.idref in IDS_TO_NEW_IDS.keys():
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
    for ref in relationships:
        if reference_needs_fixing(ref["source_ref"]):
            if not ref["source_ref"] in IDS_TO_NEW_IDS.keys():
                IDS_TO_NEW_IDS[ref["source_ref"]] = generateSTIX20Id(None, ref["source_ref"])
                error("Dangling source reference " +  ref["source_ref"] + " in " + ref["id"])
            ref["source_ref"] = IDS_TO_NEW_IDS[ref["source_ref"]]
        if reference_needs_fixing(ref["target_ref"]):
            if not ref["target_ref"] in IDS_TO_NEW_IDS.keys():
                IDS_TO_NEW_IDS[ref["target_ref"]] = generateSTIX20Id(None, ref["target_ref"])
                error("Dangling target reference " + ref["target_ref"] + " in " + ref["id"])
            ref["target_ref"] = IDS_TO_NEW_IDS[ref["target_ref"]]

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
    # TODO: add status to description
    # TODO: add confidence to description
    if camp.activity is not None:
        for a in camp.activity:
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
    # TODO: add stage into description
    convert_controlled_vocabs_to_open_vocabs(coaInstance, "labels", [ coa.type_ ], COA_LABEL_MAP, False)
    # TODO: add objective into description
    # TODO: parameter observables, maybe turn into pattern expressions and put in description???
    if coa.structured_coa:
        warn("Structured COAs are not supported in STIX 2.0")
    # TODO: add impact into description
    # TODO: add cost into description
    # TODO: add efficacy into description
    process_information_source(coa.information_source, coaInstance)
    # TODO: related coas
    finish_basic_object(coa.id_, coaInstance, coa)
    return coaInstance

# exploit target

def convert_vulnerability(v, et):
    et_timestamp = et.timestamp
    vulnerabilityInstance = create_basic_object("vulnerability", v, et_timestamp)
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
        # this may not work
        for ref in v.references:
            vulnerabilityInstance["external_references"].append({"url": ref.reference})
    # TODO: add et fields
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
            warn("ExploitTarget/Configurations not supported in STIX 2.0")

# identities

def get_regions_from_ciq_addresses(addresses):
    return []

def convert_identity(identity, bundleInstance, finish=True):
    identityInstance = create_basic_object("identity", identity)
    identityInstance["sectors"] = []
    if identity.name is not None:
        identityInstance["name"] = identity.name
    if identity.roles is not None:
        convert_controlled_vocabs_to_open_vocabs(identityInstance, "roles", identity.roles, ROLES_MAP, False)
    ciq_info = identity._specification
    if ciq_info.party_name is not None:
        warn("ciq name found, overriding")
        identityInstance["name"] = ciq_info.party_name
    if not hasattr(identityInstance, "name"):
        error(identityInstance["id"] + " must have a name, using 'none'")
        identityInstance["name"] = "None"
    if ciq_info.organisation_info is not None:
        convert_to_open_vocabs(identityInstance, "sectors", ciq_info.organisation_info.industry_type, SECTORS_MAP)
    if ciq_info.addresses is not None:
        identityInstance["regions"] = get_regions_from_ciq_addresses(ciq_info.addresses)
    if finish:
        finish_basic_object(identity.id_, identityInstance, identity)
    return identityInstance

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
    process_information_source(incident.information_source, incidentInstance)
    finish_basic_object(incident.id_, incidentInstance, incident)
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
                        indicatorInstance["pattern"] = ""
                        first_rule = True
                        for rule in tm.rules:
                            indicatorInstance["pattern"] += (", " if not first_rule else "") + rule.value.encode('unicode_escape')
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
            if not "valid_from" in indicatorInstance.keys():
                indicatorInstance["valid_from"] = window.start_time.value
                indicatorInstance["valid_from_precision"] = window.start_time.precision
                indicatorInstance["valid_until"] = window.end_time.value
                indicatorInstance["valid_until_precision"] = window.end_time.precision
            else:
                warn("Only one valid time window allowed for " + indicatorInstance["id"] + " in STIX 2.0 - used first one")
        if not "valid_from" in indicatorInstance.keys():
            warn("No valid time position information available in " + indicator.id_ + ", using timestamp")
            indicatorInstance["valid_from"] = convert_timestamp(indicator)
    convert_kill_chains(indicator.kill_chain_phases, indicatorInstance)
    # TODO: add likely impact to description
    # TODO: add confidence to description
    # TODO: sightings
    if indicator.observable is not None:
        indicatorInstance["pattern"] = convert_observable_to_pattern(indicator.observable)
        indicatorInstance["pattern_lang"] = "cybox"
    convert_test_mechanism(indicator, indicatorInstance)
    process_information_source(indicator.producer, indicatorInstance)
    if indicator.suggested_coas is not None:
        warn("Using related-to")
        handle_relationship_to_refs(indicator.suggested_coas, indicatorInstance["id"], bundleInstance, "related-to")
    # TODO: related indicators
    if indicator.related_campaigns is not None:
        handle_relationship_to_refs(indicator.related_campaigns, indicatorInstance["id"], bundleInstance, "attributed-to")
    if indicator.indicated_ttps is not None:
        handle_relationship_to_refs(indicator.indicated_ttps, indicatorInstance["id"], bundleInstance, "indicates")
    finish_basic_object(indicator.id_, indicatorInstance, indicator)
    return indicatorInstance

# observables

def convert_observable_data(obs, bundleInstance):
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
    return observed_data_instance

# report

def process_report_contents(report, bundleInstance, reportInstance):
    reportInstance["report_refs"] = []
    for camp in report.campaigns:
        if camp.id_ is not None:
            camp20 = convert_campaign(camp, bundleInstance)
            bundleInstance["campaigns"].append(camp20)
            reportInstance["report_refs"].append(camp20["id"])
        else:
            reportInstance["report_refs"].append(camp.idref)

    # coas
    for coa in report.courses_of_action:
        if coa.id_ is not None:
            coa20 = convert_course_of_action(coa, bundleInstance)
            bundleInstance["courses_of_action"].append(coa20)
            reportInstance["report_refs"].append(coa20["id"])
        else:
            reportInstance["report_refs"].append(coa.idref)

    # exploit-targets
    for et in report.exploit_targets:
        convert_exploit_target(et, bundleInstance)

    # incidents
    if INCIDENT_IN_20:
        for i in report.incidents:
            if i.id_ is not None:
                i20 = convert_incident(i, bundleInstance)
                bundleInstance["incidents"].append(i20)
                reportInstance["report_refs"].append(i20["id"])
            else:
                reportInstance["report_refs"].append(i.idref)

    # indicators
    for i in report.indicators:
        if i.id_ is not None:
            i20 = convert_indicator(i, bundleInstance)
            bundleInstance["indicators"].append(i20)
            reportInstance["report_refs"].append(i20["id"])
        else:
            reportInstance["report_refs"].append(i.idref)

    # observables
    if report.observables is not None:
        for o_d in report.observables:
            if o_d.id_ is not None:
                o_d20 = convert_observable_data(o_d, bundleInstance)
                bundleInstance["observed_data"].append(o_d20)
                reportInstance["report_refs"].append(o_d20["id"])
            else:
                reportInstance["report_refs"].append(o_d.idref)

    # threat actors
    for ta in report.threat_actors:
        if ta.id_ is not None:
            ta20 = convert_threat_actor(ta, bundleInstance)
            bundleInstance["threat-actors"].append(ta20)
            reportInstance["report_refs"].append(ta20["id"])
        else:
            reportInstance["report_refs"].append(ta.idref)


    # ttps
    for ttp in report.ttps:
        convert_ttp(ttp, bundleInstance)

def convert_report(report, bundleInstance):
    reportInstance = create_basic_object("report", report)
    process_description_and_short_description(reportInstance, report.header)
    process_information_source(report.header.information_source, reportInstance)
    if report.header.title is not None:
        reportInstance["name"] = report.header.title
    process_report_contents(report, bundleInstance, reportInstance)
    finish_basic_object(report.id_, reportInstance, report)
    return reportInstance

# threat actor

def convert_threat_actor(threat_actor, bundleInstance):
    threat_actorInstance = create_basic_object("threat-actor", threat_actor)
    process_description_and_short_description(threat_actorInstance, threat_actor)
    if threat_actor.identity is not None:
        threat_actorInstance["name"] = get_simple_name_from_identity(threat_actor.identity)
        if threat_actor.title is not None:
            # TODO: add title to description
            warn("Title and identity both specified in " + threat_actor.id_ + " - used idenitity")
    elif threat_actor.title is not None:
        threat_actorInstance["name"] = threat_actor.title
    convert_controlled_vocabs_to_open_vocabs(threat_actorInstance, "labels", threat_actor.types, THREAT_ACTOR_LABEL_MAP, False)
    # TODO: add intended effect to description
    # TODO: add Planning_And_Operational_Support to description
    # TODO: add confidence to description
    if threat_actorInstance["description"] == "":
        del threat_actorInstance["description"]
    # TODO: motivation is complicated
    convert_controlled_vocabs_to_open_vocabs(threat_actorInstance, "sophistication", threat_actor.sophistications, THREAT_ACTOR_SOPHISTICATION_MAP, True)
    # handle relationships
    if threat_actor.observed_ttps is not None:
        handle_relationship_to_refs(threat_actor.observed_ttps, threat_actorInstance["id"], bundleInstance, "uses")
    if threat_actor.associated_campaigns is not None:
        handle_relationship_from_refs(threat_actor.associated_campaigns, threat_actorInstance["id"], bundleInstance, "attributed_to")
    # TODO: associated_actors
    process_information_source(threat_actor.information_source, threat_actorInstance)
    finish_basic_object(threat_actor.id_, threat_actorInstance, threat_actor)
    return threat_actorInstance

# TTPs

def process_ttp_properties(sdoInstance, ttp, kill_chains_available=True):
    if kill_chains_available:
        convert_kill_chains(ttp.kill_chain_phases, sdoInstance)
    process_information_source(ttp.information_source, sdoInstance)

def convert_attack_pattern(ap, bundleInstance, ttp):
    ttp_timestamp = ttp.timestamp
    attack_PatternInstance = create_basic_object("attack-pattern", ap, ttp_timestamp)
    process_description_and_short_description(attack_PatternInstance, ap)
    if ap.capec_id is not None:
        attack_PatternInstance["external_references"] = [ {"source_name": "capec", "external_id": ap.capec_id}]
    process_ttp_properties(attack_PatternInstance, ttp)
    finish_basic_object(ttp.id_, attack_PatternInstance, ap)
    return attack_PatternInstance

def convert_malware_instance(mal,bundleInstance, ttp):
    ttp_timestamp = ttp.timestamp
    malware_instanceInstance = create_basic_object("malware", mal, ttp_timestamp)
    process_description_and_short_description(malware_instanceInstance, mal)
    convert_controlled_vocabs_to_open_vocabs(malware_instanceInstance, "labels", mal.types, MALWARE_LABELS_MAP, False)
    if mal.names is not None:
        for n in mal.names:
            if not "name" in malware_instanceInstance.keys():
                malware_instanceInstance["name"] = str(n)
            else:
                warn("Only one name for malware is allowed for " + malware_instanceInstance["id"] + " in STIX 2.0 - used first one")
    process_ttp_properties(malware_instanceInstance, ttp)
    finish_basic_object(ttp.id_, malware_instanceInstance, mal)
    return malware_instanceInstance

def convert_behavior(behavior, bundleInstance, ttp):
    behavior_generated = False
    if behavior.attack_patterns is not None:
        for ap in behavior.attack_patterns:
            bundleInstance["attack_patterns"].append(convert_attack_pattern(ap, bundleInstance, ttp))
            behavior_generated = True
    if behavior.malware_instances is not None:
        for mal in behavior.malware_instances:
            bundleInstance["malware"].append(convert_malware_instance(mal, bundleInstance, ttp))
            behavior_generated = True
    if behavior.exploits is not None:
        for e in behavior.exploits:
            warn("TTP/Behavior/Exploits/Exploit not supported in STIX 2.0")
    return behavior_generated

def convert_tool(tool, ttp):
    ttp_timestamp = ttp.timestamp
    toolInstance = create_basic_object("tool", tool, ttp_timestamp)
    process_description_and_short_description(toolInstance, tool)
    convert_controlled_vocabs_to_open_vocabs(toolInstance,  "labels", tool.types, TOOL_LABELS_MAP, False)
    toolInstance["version"] = tool.version
    process_ttp_properties(toolInstance, ttp)
    finish_basic_object(ttp.id_, toolInstance, tool)
    return toolInstance

def convert_infrastructure(infra, ttp):
    ttp_timestamp = ttp.timestamp
    infrastructureInstance = create_basic_object("infrastructure", infra, ttp_timestamp)
    process_description_and_short_description(infrastructureInstance, infra)
    convert_controlled_vocabs_to_open_vocabs(infrastructureInstance, "labels", infra.types, {}, False)
    info("No 'first_seen' data on " + (infra.id_ if infra.id_ is not None else ttp.id_) + " - using timestamp")
    infrastructureInstance["first_seen"] = convert_timestamp(infra, ttp_timestamp)
    # TODO: observable_characterizations?
    process_ttp_properties(infrastructureInstance, ttp)
    finish_basic_object(ttp.id_, infrastructureInstance, infra)
    return infrastructureInstance

def convert_resources(resources, bundleInstance, ttp):
    resource_generated = False
    infrastructure_generated = False
    if resources.tools is not None:
        for t in resources.tools:
            bundleInstance["tools"].append(convert_tool(t, ttp))
            resource_generated = True
    if INFRASTRUCTURE_IN_20 and resources.infrastructure is not None:
        bundleInstance["infrastructure"].append(convert_infrastructure(resources.infrastructure, ttp))
        infrastructure_generated = True
    return resource_generated or infrastructure_generated

def convert_identity_for_victim_target(identity, bundleInstance, ttp):
    ttp_timestamp = ttp.timestamp
    identityInstance = convert_identity(identity, bundleInstance, False)
    process_ttp_properties(identityInstance, ttp, False)
    finish_basic_object(ttp.id_, identityInstance, identity)
    return identityInstance

def convert_victim_targeting(victim_targeting, bundleInstance, ttp):
    if victim_targeting.targeted_systems is not None:
        for v in victim_targeting.targeted_systems:
            warn("Targeted systems on " + ttp.id_ + " are not a victim target in STIX 2.0")
    if victim_targeting.targeted_information is not None:
        for v in victim_targeting.targeted_information:
            warn("targeted information on " + ttp.id_ + " is not a victim target in STIX 2.0")
    if victim_targeting.targeted_technical_details is not None:
        for v in victim_targeting.targeted_technical_details:
            warn("targeted technical details on " + ttp.id_ + " are not a victim target in STIX 2.0")
    if victim_targeting.identity is not None:
        bundleInstance["identities"].append(convert_identity_for_victim_target(victim_targeting.identity, bundleInstance, ttp))
        return True
    else:
        return False

def convert_ttp(ttp, bundleInstance):
    ttp_generated = False;
    if ttp.behavior is not None:
        ttp_generated = convert_behavior(ttp.behavior, bundleInstance, ttp)
    if ttp.resources is not None:
        ttp_generated = convert_resources(ttp.resources, bundleInstance, ttp)
    if ttp.related_packages is not None:
        for p in ttp.related_packages:
            warn("TTP/Related_Packages on " + ttp.id_ + " not supported in STIX 2.0")
    if ttp.kill_chain_phases is not None:
        for phase in ttp.kill_chain_phases:
            warn("Kill chains in TTP on " + ttp.id_ + " are not handled yet")
    if ttp.victim_targeting is not None:
        ttp_generated = convert_victim_targeting(ttp.victim_targeting, bundleInstance, ttp)
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
    elif isinstance(obj, Identity):
        convert_identity(obj, bundleInstance)
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


    for r in bundleInstance["reports"]:
        fixed_refs = []
        for ref in r["report_refs"]:
            if reference_needs_fixing(ref):
                if ref in IDS_TO_NEW_IDS.keys():
                    fixed_refs.append(IDS_TO_NEW_IDS[ref])
                else:
                    fixed_refs.append(ref)
        r["report_refs"] = fixed_refs

    if bundleInstance["campaigns"] == []:
        del bundleInstance["campaigns"]
    if bundleInstance["courses_of_action"] == []:
        del bundleInstance["courses_of_action"]
    if bundleInstance["vulnerabilities"] == []:
        del bundleInstance["vulnerabilities"]
    if bundleInstance["identities"] == []:
        del bundleInstance["identities"]
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

def convert_package(stixPackage):
    bundleInstance = {"type": "bundle"}
    bundleInstance["id"] = generateSTIX20Id("bundle", stixPackage.id_)
    bundleInstance["spec_version"] = "2.0"
    # header
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

    # identities

    if NOBODY_USED:
        # add Nobody identity
        bundleInstance["identities"] = [NOBODY_IDENTITY]

    # incidents
    if INCIDENT_IN_20:
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


