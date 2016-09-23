# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

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
# from stix.ttp.attack_pattern import (AttackPattern)
from cybox.core import Observable
from stix.extensions.test_mechanism.yara_test_mechanism import YaraTestMechanism
from stix.extensions.test_mechanism.snort_test_mechanism import SnortTestMechanism
from stix.extensions.test_mechanism.open_ioc_2010_test_mechanism import OpenIOCTestMechanism
from stix.extensions.identity.ciq_identity_3_0 import CIQIdentity3_0Instance

import json
from datetime import *
import pycountry
from lxml import etree

from elevator.convert_cybox import convert_cybox_object
from elevator.convert_pattern import convert_observable_to_pattern, fix_pattern
from elevator.ids import *
from elevator.vocab_mappings import *
from elevator.utils import *

SQUIRREL_GAPS_IN_DESCRIPTIONS = True

INFRASTRUCTURE_IN_20 = False

INCIDENT_IN_20 = True

# collect kill chains

KILL_CHAINS_PHASES = {}

OBSERVABLE_MAPPING = {}


def process_kill_chain(kc):
    for kcp in kc.kill_chain_phases:
        # Use object itself as key.
        if kcp.phase_id:
            KILL_CHAINS_PHASES[kcp.phase_id] = {"kill_chain_name": kc.name, "phase_name": kcp.name}
        else:
            KILL_CHAINS_PHASES[kcp] = {"kill_chain_name": kc.name, "phase_name": kcp.name}


#
# identities
#


def get_simple_name_from_identity(identity, bundle_instance, sdo_instance):
    if isinstance(identity, CIQIdentity3_0Instance):
        handle_relationship_to_refs([identity], sdo_instance["id"], bundle_instance, "attributed-to")
    else:
        return identity.name


def get_identity_ref(identity, bundle_instance):
    if identity.idref is not None:
        # fix reference later
        return identity.idref
    else:
        ident20 = convert_identity(identity, bundle_instance)
        bundle_instance["identities"].append(ident20)
        return ident20["id"]


def process_information_source(information_source, so, bundle_instance, parent_created_by_ref):
    if information_source is not None and information_source.identity is not None:
        so["created_by_ref"] = get_identity_ref(information_source.identity, bundle_instance)
    else:
        so["created_by_ref"] = parent_created_by_ref
        # TODO: add to description


def convert_to_open_vocabs(stix20_obj, stix20_property_name, value, vocab_mapping):
    stix20_obj[stix20_property_name].append(map_vocabs_to_label(value, vocab_mapping))


def process_structured_text_list(text_list):
    full_text = ""
    for text_obj in text_list.sorted:
        full_text += text_obj.value
    return full_text


def process_description_and_short_description(so, entity):
    if hasattr(entity, "descriptions") and entity.descriptions is not None:
        so["description"] += convert_to_str(process_structured_text_list(entity.descriptions))
        if SQUIRREL_GAPS_IN_DESCRIPTIONS and entity.short_description is not None:
            warn(
                "The Short_Description property is no longer supported in STIX.  Added the text to the description property")
            so["description"] += "\nShort Description: \n" + convert_to_str(
                process_structured_text_list(entity.short_descriptions))
    elif hasattr(entity, "description") and entity.description is not None:
        so["description"] += convert_to_str(entity.description.value)
    elif hasattr(entity, "short_descriptions") and entity.short_descriptions is not None:
        so["description"] = convert_to_str(process_structured_text_list(entity.short_descriptions))


def create_basic_object(stix20_type, stix1x_obj, parent_timestamp=None, parent_id=None, id_used=False):
    instance = {"type": stix20_type}
    instance["id"] = generateSTIX20Id(stix20_type, stix1x_obj.id_ if stix1x_obj and hasattr(stix1x_obj,
                                                                                            "id_") and stix1x_obj.id_ else parent_id,
                                      id_used)
    instance["version"] = 1  # need to see about versioning
    timestamp = convert_timestamp(stix1x_obj, parent_timestamp)
    instance["created"] = timestamp
    # may need to revisit if we handle 1.x versioning.
    instance["modified"] = timestamp
    instance["description"] = ""
    instance["external_references"] = []
    return instance


def remove_empty_common_values(instance, clear_description=True):
    if "description" in instance and not instance["description"] and clear_description:
        del instance["description"]
    if "external_references" in instance and not instance["external_references"]:
        del instance["external_references"]
    if "created_by_ref" in instance and not instance["created_by_ref"]:
        del instance["created_by_ref"]


def finish_basic_object(old_id, instance, stix1x_obj, clear_description=True):
    if old_id is not None:
        record_ids(old_id, instance["id"])
    remove_empty_common_values(instance, clear_description)
    if hasattr(stix1x_obj, "handling") and stix1x_obj.handling is not None:
        warn("Handling not implemented, yet")
    if hasattr(stix1x_obj, "related_packages") and stix1x_obj.related_packages is not None:
        for p in stix1x_obj.related_packages:
            warn("Related_Packages property no longer supported in STIX")


#
# handle gaps
#


def add_string_property_to_description(sdo_instance, property_name, property_value, isList=False):
    if SQUIRREL_GAPS_IN_DESCRIPTIONS and property_value is not None:
        if isList:
            sdo_instance["description"] += "\n\n" + property_name.upper() + ":\n"
            property_values = []
            for v in property_value:
                property_values.append(convert_to_str(str(v)))
            sdo_instance["description"] += ",\n".join(property_values)
        else:
            sdo_instance["description"] += "\n\n" + property_name.upper() + ":\n\t" + convert_to_str(
                str(property_value))
        warn("Added " + property_name + " to description of " + sdo_instance["id"])


def add_confidence_property_to_description(sdo_instance, confidence):
    if SQUIRREL_GAPS_IN_DESCRIPTIONS:
        if confidence is not None:
            sdo_instance["description"] += "\n\n" + "CONFIDENCE: "
            if confidence.value is not None:
                sdo_instance["description"] += str(confidence.value)
            if confidence.description is not None:
                sdo_instance["description"] += "\n\tDESCRIPTION: " + str(confidence.description)


def add_statement_type_to_description(sdo_instance, statement, property_name):
    if SQUIRREL_GAPS_IN_DESCRIPTIONS:
        sdo_instance["description"] += "\n\n" + property_name.upper() + ":"
        if statement.value:
            sdo_instance["description"] += str(statement.value)
        if statement.descriptions:
            descriptions = []
            for d in statement.descriptions:
                descriptions.append(str(d))
            sdo_instance["description"] += "\n\n\t".join(descriptions)
        # TODO: handle source
        if statement.confidence:
            add_confidence_property_to_description(sdo_instance, statement.confidence)


def add_multiple_statement_types_to_description(sdo_instance, statements, property_name):
    if SQUIRREL_GAPS_IN_DESCRIPTIONS:
        for s in statements:
            add_statement_type_to_description(sdo_instance, s, property_name)


# Relationships


def create_relationship(source_ref, target_ref, verb, rel_obj, parent_timestamp):
    relationship_instance = create_basic_object("relationship", rel_obj, parent_timestamp)
    relationship_instance["source_ref"] = source_ref
    relationship_instance["target_ref"] = target_ref
    relationship_instance["name"] = verb
    if rel_obj is not None and hasattr(rel_obj, "relationship") and rel_obj.relationship is not None:
        relationship_instance["description"] = rel_obj.relationship.value
    # handle description
    remove_empty_common_values(relationship_instance, True)
    return relationship_instance


# Creating and Linking up relationships  (three cases)
# 1.  The object is embedded - create the object, add it to the bundle, return to id so the relationship is complete
# 2.  an idref is given, and it has a corresponding 2.0 id, use it
# 3.  an idref is given, but it has NO corresponding 2.0 id, add 1.x id, and fix at the end in fix_relationships


def handle_relationship_to_objs(items, source_id, bundle_instance, verb, parent_timestamp=None):
    for item in items:
        new20s = handle_embedded_object(item, bundle_instance)
        for new20 in new20s:
            bundle_instance["relationships"].append(create_relationship(source_id,
                                                                        new20["id"] if new20 else None,
                                                                        verb,
                                                                        item,
                                                                        parent_timestamp))


def handle_relationship_to_refs(refs, source_id, bundle_instance, verb, parent_timestamp=None):
    for ref in refs:
        if ref.item.idref is None:
            # embedded
            new20s = handle_embedded_object(ref.item, bundle_instance)
            for new20 in new20s:
                bundle_instance["relationships"].append(create_relationship(source_id,
                                                                            new20["id"] if new20 else None,
                                                                            verb,
                                                                            ref,
                                                                            parent_timestamp))
        elif exists_id_key(ref.item.idref):
            for to_ref in get_id_value(ref.item.idref):
                bundle_instance["relationships"].append(create_relationship(source_id,
                                                                            to_ref,
                                                                            verb,
                                                                            ref,
                                                                            parent_timestamp))
        else:
            # a forward reference, fix later
            bundle_instance["relationships"].append(create_relationship(source_id,
                                                                        ref.item.idref,
                                                                        verb,
                                                                        ref,
                                                                        parent_timestamp))


def handle_relationship_from_refs(refs, target_id, bundle_instance, verb, parent_timestamp=None):
    for ref in refs:
        if ref.item.idref is None:
            # embedded
            new20s = handle_embedded_object(ref.item, bundle_instance)
            for new20 in new20s:
                bundle_instance["relationships"].append(create_relationship(new20["id"] if new20 else None,
                                                                            target_id,
                                                                            verb,
                                                                            ref,
                                                                            parent_timestamp))
        elif exists_id_key(ref.item.idref):
            for from_ref in get_id_value(ref.item.idref):
                bundle_instance["relationships"].append(create_relationship(from_ref,
                                                                            target_id,
                                                                            verb,
                                                                            ref,
                                                                            parent_timestamp))
        else:
            # a forward reference, fix later
            bundle_instance["relationships"].append(create_relationship(ref.item.idref,
                                                                        target_id,
                                                                        verb,
                                                                        ref,
                                                                        parent_timestamp))


def reference_needs_fixing(ref):
    return ref and ref.find("--") == -1


# for ids in source and target refs that are still 1.x ids,
def fix_relationships(relationships, bundle_instance):
    # TODO:  warn if ref not available??
    for ref in relationships:
        if reference_needs_fixing(ref["source_ref"]):
            if not exists_id_key(ref["source_ref"]):
                new_id = generateSTIX20Id(None, str.lower(ref["source_ref"]))
                if new_id is None:
                    warn("Dangling source reference " + ref["source_ref"] + " in " + ref["id"])
                add_id_value(ref["source_ref"], new_id)
            first_one = True
            for m_id in get_id_value(ref["source_ref"]):
                if first_one:
                    ref["source_ref"] = m_id
                else:
                    bundle_instance["relationships"].append(create_relationship(m_id, ref["target_ref"], ref["verb"]))
        if reference_needs_fixing(ref["target_ref"]):
            if not exists_id_key(ref["target_ref"]):
                new_id = generateSTIX20Id(None, str.lower(ref["target_ref"]))
                if new_id is None:
                    warn("Dangling target reference " + ref["target_ref"] + " in " + ref["id"])
                add_id_value(ref["target_ref"], new_id)
            first_one = True
            for m_id in get_id_value(ref["target_ref"]):
                if first_one:
                    ref["target_ref"] = m_id
                else:
                    bundle_instance["relationships"].append(create_relationship(ref["source_ref"], m_id, ref["verb"]))


# Relationships are not in 1.x, so they must be added explicitly to reports.
# This is done after the package has been processed, and the relationships are "fixed", so all relationships are known
#
# For each report:
#   if the source and target are part of the report, add the relationship
#   if the source is part of the report, add the relationship AND then the target, UNLESS the target ref is "dangling"
#   if the target is part of the report, add the relationship AND then the source, UNLESS the source ref is "dangling"


def add_relationships_to_reports(bundle_instance):
    rels_to_include = []
    new_ids = get_id_values()
    for rep in bundle_instance["reports"]:
        refs_in_this_report = rep["object_refs"]
        for rel in bundle_instance["relationships"]:
            if ("source_ref" in rel and rel["source_ref"] in refs_in_this_report) and \
                    ("target_ref" in rel and rel["target_ref"] in refs_in_this_report):
                rels_to_include.append(rel["id"])
            elif "source_ref" in rel and rel["source_ref"] in refs_in_this_report:
                if "target_ref" in rel and rel["target_ref"] and (
                        rel["target_ref"] in new_ids or rel["target_ref"] in SDO_WITH_NO_1X_OBJECT):
                    rels_to_include.append(rel["id"])
                    rels_to_include.append(rel["target_ref"])
                    warn("Including " + rel["id"] + " in " + rep["id"] + " and added the target_ref " + rel[
                        "target_ref"] + " to the report")
                elif not ("target_ref" in rel and rel["target_ref"]):
                    rels_to_include.append(rel["id"])
                    warn("Including " + rel["id"] + " in " + rep["id"] + " although the target_ref is unknown")
                elif not (rel["target_ref"] in new_ids or rel["target_ref"] in SDO_WITH_NO_1X_OBJECT):
                    warn("Not including " + rel["id"] + " in " + rep[
                        "id"] + " because there is no corresponding SDO for " + rel["target_ref"])
            elif "target_ref" in rel and rel["target_ref"] in refs_in_this_report:
                if "source_ref" in rel and rel["source_ref"] and (
                        rel["source_ref"] in new_ids or rel["source_ref"] in SDO_WITH_NO_1X_OBJECT):
                    rels_to_include.append(rel["id"])
                    rels_to_include.append(rel["source_ref"])
                    warn("Including " + rel["id"] + " in " + rep["id"] + " and added the source_ref " + rel[
                        "source_ref"] + " to the report")
                elif not ("source_ref" in rel and rel["source_ref"]):
                    rels_to_include.append(rel["id"])
                    warn("Including " + rel["id"] + " in " + rep["id"] + " although the target_ref is unknown")
                elif not (rel["source_ref"] in new_ids or rel["source_ref"] in SDO_WITH_NO_1X_OBJECT):
                    warn("Not including " + rel["id"] + " in " + rep[
                        "id"] + " because there is no corresponding SDO for " + rel["source_ref"])
        if "object_refs" in rep:
            rep["object_refs"].extend(rels_to_include)
        else:
            rep["object_refs"] = rels_to_include


# campaign


def convert_campaign(camp, bundle_instance):
    campaign_instance = create_basic_object("campaign", camp)
    process_description_and_short_description(campaign_instance, camp)
    campaign_instance["name"] = camp.title
    if camp.names is not None:
        campaign_instance["aliases"] = []
        for name in camp.names:
            campaign_instance["aliases"].append(name)
        if campaign_instance["aliases"] == []:
            del campaign_instance["aliases"]
    add_multiple_statement_types_to_description(campaign_instance, camp.intended_effects, "intended_effect")
    add_string_property_to_description(campaign_instance, "status", camp.status)
    if hasattr(camp, "confidence"):
        add_confidence_property_to_description(campaign_instance, camp.confidence)
    if camp.attribution:
        handle_relationship_to_refs(camp.related_ttps, campaign_instance["id"], bundle_instance, "attributed-to")
    if camp.activity is not None:
        for a in camp.activity:
            warn("Campaign/Activity not supported in STIX 2.0")
    if camp.related_ttps is not None:
        # victims use targets, not uses
        handle_relationship_to_refs(camp.related_ttps, campaign_instance["id"], bundle_instance, "uses")
    if camp.related_incidents is not None:
        handle_relationship_from_refs(camp.related_incidents, campaign_instance["id"], bundle_instance, "attributed-to")
    if camp.related_indicators is not None:
        handle_relationship_from_refs(camp.related_indicators, campaign_instance["id"], bundle_instance, "indicates")
    if camp.attribution is not None:
        for att in camp.attribution:
            handle_relationship_from_refs(att, campaign_instance["id"], bundle_instance, "attributed-to")
    if camp.associated_campaigns:
        warn("All associated campaigns relationships of " + camp.id_ + " are assumed to not represent STIX 1.2 versioning")
        handle_relationship_to_refs(camp.related_coas, camp_instance["id"], bundle_instance,
                                    "related-to")
    process_information_source(camp.information_source,
                               campaign_instance,
                               bundle_instance,
                               bundle_instance["created_by_ref"] if "created_by_ref" in bundle_instance else None)
    finish_basic_object(camp.id_, campaign_instance, camp)
    return campaign_instance


# course of action


def add_objective_property_to_description(sdo_instance, objective):
    if SQUIRREL_GAPS_IN_DESCRIPTIONS:
        if objective is not None:
            sdo_instance["description"] += "\n\n" + "OBJECTIVE: "
            descriptions = []
            for d in objective.descriptions:
                descriptions.append(str(d))
            sdo_instance["description"] += "\n\n\t".join(descriptions)


def convert_course_of_action(coa, bundle_instance):
    coa_instance = create_basic_object("course_of_action", coa)
    process_description_and_short_description(coa_instance, coa)
    coa_instance["name"] = coa.title
    add_string_property_to_description(coa_instance, "stage", coa.stage)
    convert_controlled_vocabs_to_open_vocabs(coa_instance, "labels", [coa.type_], COA_LABEL_MAP, False)
    add_objective_property_to_description(coa_instance, coa.objective)
    # TODO: parameter observables, maybe turn into pattern expressions and put in description???
    if coa.structured_coa:
        warn("Structured COAs are not supported in STIX 2.0")
    add_statement_type_to_description(coa_instance, coa.impact, "impact")
    add_statement_type_to_description(coa_instance, coa.cost, "cost")
    add_statement_type_to_description(coa_instance, coa.efficacy, "efficacy")
    process_information_source(coa.information_source, coa_instance, bundle_instance,
                               bundle_instance["created_by_ref"] if "created_by_ref" in bundle_instance else None)
    if coa.related_coas:
        warn("All related coas relationships of " + coa.id_ + " are assumed to not represent STIX 1.2 versioning")
        handle_relationship_to_refs(coa.related_coas, coa_instance["id"], bundle_instance,
                                    "related-to")
    finish_basic_object(coa.id_, coa_instance, coa)
    return coa_instance


# exploit target


def process_et_properties(sdo_instance, et, bundle_instance):
    process_description_and_short_description(sdo_instance, et)
    if "name" in sdo_instance:
        info("title from " + sdo_instance["type"] + " used for name, put exploit_target title in description")
        add_string_property_to_description(sdo_instance, "title", et.title, False)
    elif et.title is not None:
        sdo_instance["name"] = et.title
    process_information_source(et.information_source, sdo_instance, bundle_instance,
                               bundle_instance["created_by_ref"] if "created_by_ref" in bundle_instance else None)
    if et.potential_coas is not None:
        handle_relationship_from_refs(et.potential_coas, sdo_instance["id"], bundle_instance, "mitigates",
                                      et.timestamp)


def convert_vulnerability(v, et, bundle_instance):
    vulnerability_instance = create_basic_object("vulnerability", v, et.timestamp, et.id_)
    if v.title is not None:
        vulnerability_instance["name"] = v.title
    process_description_and_short_description(vulnerability_instance, v)
    if v.cve_id is not None:
        vulnerability_instance["external_references"].append({"source_name": "cve", "external_id": v.cve_id})
    if v.osvdb_id is not None:
        vulnerability_instance["external_references"].append({"source_name": "osvdb", "external_id": v.osvdb_id})
    # source?
    # TODO: add CVSS score into description
    # TODO: add date times into description
    # TODO: add affected software into description
    if v.references is not None:
        # TODO: url can't exist alone
        for ref in v.references:
            vulnerability_instance["external_references"].append({"url": ref.reference})
    process_et_properties(vulnerability_instance, et, bundle_instance)
    finish_basic_object(et.id_, vulnerability_instance, v)
    return vulnerability_instance


def convert_exploit_target(et, bundle_instance):
    if et.vulnerabilities is not None:
        for v in et.vulnerabilities:
            bundle_instance["vulnerabilities"].append(convert_vulnerability(v, et, bundle_instance))
    if et.weaknesses is not None:
        for w in et.weaknesses:
            warn("ExploitTarget/Weaknesses not supported in STIX 2.0")
    if et.configuration is not None:
        for c in et.configuration:
            warn("ExploitTarget/Configurations not supported in STIX 2.0")


# identities


def convert_ciq_addresses(addresses, identity_instance):
    identity_instance["country"] = []
    identity_instance["regions"] = []
    for add in addresses:
        if hasattr(add, "country"):
            for name in add.country.name_elements:
                iso = pycountry.countries.get(name=name.value)
                if iso is not None:
                    identity_instance["country"].append(iso.alpha2)
                else:
                    warn("No ISO code for " + name.value)
                    identity_instance["country"].append(name.value)
        if hasattr(add, "administrative_area"):
            for name in add.administrative_area.name_elements:
                # bug in pycountry - need to make sure that subdivisions are indexed using "name"
                iso = pycountry.subdivisions.get(name=name.value)
                if iso is not None:
                    identity_instance["regions"].append(iso.code)
                else:
                    identity_instance["regions"].append(name.value)


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
                warn("more than one organization name for " + identity["id"] +
                     " not allowed in STIX 2.0, used first one")
                # add to description


def convert_identity(identity, bundle_instance, parent_timestamp=None, parent_id=None, clear_description=True):
    identity_instance = create_basic_object("identity", identity, parent_timestamp, parent_id)
    identity_instance["sectors"] = []
    if identity.name is not None:
        identity_instance["name"] = identity.name
    if isinstance(identity, CIQIdentity3_0Instance):
        if identity.roles is not None:
            convert_controlled_vocabs_to_open_vocabs(identity_instance, "roles", identity.roles, ROLES_MAP, False)
        ciq_info = identity._specification
        if ciq_info.party_name is not None:
            warn("ciq name found in " + identity_instance["id"] + ", possibly overriding other name")
            convert_party_name(ciq_info.party_name, identity_instance)
        if "name" not in identity_instance:
            error(identity_instance["id"] + " must have a name, using 'none'")
            identity_instance["name"] = "None"
        if ciq_info.organisation_info is not None:
            convert_to_open_vocabs(identity_instance, "sectors", ciq_info.organisation_info.industry_type, SECTORS_MAP)
        if ciq_info.addresses is not None:
            convert_ciq_addresses(ciq_info.addresses, identity_instance)
            # add other properties to contact_information
    if identity.related_identities:
        warn("All related identitiies relationships" + ((" of " + identity.id_) if identity.id_ else "") + " are assumed to not represent STIX 1.2 versioning")
        handle_relationship_to_refs(identity.related_identities, identity_instance["id"], bundle_instance,
                                    "related-to")
    finish_basic_object(identity.id_, identity_instance, identity, clear_description)
    if not identity_instance["sectors"]:
        del identity_instance["sectors"]
    return identity_instance


# incident


def convert_incident(incident, bundle_instance):
    incident_instance = create_basic_object("incident", incident)
    process_description_and_short_description(incident_instance, incident)
    if incident.title is not None:
        incident_instance["name"] = incident.title
    if incident.external_ids is not None:
        for id in incident.external_ids:
            incident_instance["external_references"].append(
                {"source_name": id.external_id.source, "external_id": id.external_id.value})
    # time
    if incident.categories is not None:
        convert_controlled_vocabs_to_open_vocabs(incident_instance, "labels", incident.categories, INCIDENT_LABEL_MAP,
                                                 False)
    if incident.related_indicators is not None:
        handle_relationship_from_refs(incident.related_indicators, incident_instance["id"], bundle_instance,
                                      "indicates", incident.timestamp)
    if incident.related_observables is not None:
        handle_relationship_from_refs(incident.related_observables, incident_instance["id"], bundle_instance, "part-of",
                                      incident.timestamp)
    if incident.leveraged_ttps is not None:
        warn("Using related-to")
        handle_relationship_to_refs(incident.leveraged_ttps, incident_instance["id"], bundle_instance, "related-to",
                                    incident.timestamp)
    # TODO: add reporter to description
    # TODO: add responder to description
    # TODO: add coordinator to description
    # TODO: add victim to description
    # TODO: add affected_assets to description
    # TODO: add impact_assessment to description
    add_string_property_to_description(incident_instance, "status", incident.status)
    process_information_source(incident.information_source, incident_instance, bundle_instance,
                               bundle_instance["created_by_ref"] if "created_by_ref" in bundle_instance else None)
    if incident.related_incidents:
        warn("All related ncidents relationships of " + incident.id_ + " are assumed to not represent STIX 1.2 versioning")
        handle_relationship_to_refs(incident.related_incidents, incident_instance["id"], bundle_instance,
                                    "related-to")
    finish_basic_object(incident.id_, incident_instance, incident)
    return incident_instance


# indicator


def convert_kill_chains(kill_chain_phases, sdo_instance):
    if kill_chain_phases is not None:
        kill_chain_phases_20 = []
        for phase in kill_chain_phases:
            if isinstance(phase, KillChainPhaseReference):
                try:
                    if phase.phase_id:
                        kill_chain_info = KILL_CHAINS_PHASES[phase.phase_id]
                    else:
                        kill_chain_info = KILL_CHAINS_PHASES[phase]
                    kill_chain_phases_20.append({"kill_chain_name": kill_chain_info["kill_chain_name"],
                                                 "phase_name": kill_chain_info["phase_name"]})
                except:
                    kill_chain_phases_20.append(phase.phase_id)
            elif isinstance(phase, KillChainPhase):
                kill_chain_phases_20.append({"kill_chain_name": phase.kill_chain_name, "phase_name": phase.name})
        if kill_chain_phases_20:
            sdo_instance["kill_chain_phases"] = kill_chain_phases_20


def convert_test_mechanism(indicator, indicator_instance):
    if indicator.test_mechanisms is not None:
        if hasattr(indicator_instance, "pattern"):
            warn("Only one type pattern can be specified in " + indicator_instance["id"] + " - using cybox")
        else:
            for tm in indicator.test_mechanisms:
                if hasattr(indicator_instance, "pattern"):
                    warn("only one alternative test mechanism allowed for " + indicator_instance[
                        "id"] + " in STIX 2.0 - used first one, which was " +
                         indicator_instance["pattern_lang"])
                else:
                    if isinstance(tm, YaraTestMechanism):
                        indicator_instance["pattern"] = convert_to_str(tm.rule.value)
                        indicator_instance["pattern_lang"] = "yara"
                    elif isinstance(tm, SnortTestMechanism):
                        list_of_strings = []
                        for rule in tm.rules:
                            list_of_strings.append(convert_to_str(rule.value))
                        indicator_instance["pattern"] = ", ".join(list_of_strings)
                        indicator_instance["pattern_lang"] = "snort"
                    elif isinstance(tm, OpenIOCTestMechanism):
                        indicator_instance["pattern"] = etree.tostring(tm.ioc)
                        indicator_instance["pattern_lang"] = "openioc"


def negate_indicator(indicator):
    return hasattr(indicator, "negate") and indicator.negate


def convert_indicator(indicator, bundle_instance):
    indicator_instance = create_basic_object("indicator", indicator)
    process_description_and_short_description(indicator_instance, indicator)
    convert_controlled_vocabs_to_open_vocabs(indicator_instance, "labels", indicator.indicator_types,
                                             INDICATOR_LABEL_MAP, False)
    if indicator.title is not None:
        indicator_instance["name"] = indicator.title
    if indicator.alternative_id is not None:
        for id in indicator.alternative_id:
            indicator_instance["external_references"].append({"source_name": "alternative_id", "external_id": id})
    if indicator.valid_time_positions is not None:
        for window in indicator.valid_time_positions:
            if "valid_from" not in indicator_instance:
                indicator_instance["valid_from"] = window.start_time.value
                indicator_instance["valid_from_precision"] = window.start_time.precision
                indicator_instance["valid_until"] = window.end_time.value
                indicator_instance["valid_until_precision"] = window.end_time.precision
            else:
                warn("Only one valid time window allowed for " + indicator_instance[
                    "id"] + " in STIX 2.0 - used first one")
        if "valid_from" not in indicator_instance:
            warn("No valid time position information available in " + indicator.id_ + ", using timestamp")
            indicator_instance["valid_from"] = convert_timestamp(indicator)
    convert_kill_chains(indicator.kill_chain_phases, indicator_instance)
    if indicator.likely_impact:
        add_statement_type_to_description(indicator_instance, indicator.likely_impact, "likely_impact")
    if hasattr(indicator, "confidence"):
        add_confidence_property_to_description(indicator_instance, indicator.confidence)
    # TODO: sightings
    if indicator.observable is not None:
        indicator_instance["pattern"] = \
            ("NOT (" if negate_indicator(indicator) else "") + \
            convert_observable_to_pattern(indicator.observable, bundle_instance, OBSERVABLE_MAPPING) + \
            (")" if negate_indicator(indicator) else "")
        indicator_instance["pattern_lang"] = "cybox"
    if indicator.composite_indicator_expression is not None:
        warn("composite indicator expressions are not handled - " + indicator.id_)
    if "pattern" not in indicator_instance:
        # STIX doesn't handle multiple patterns for indicators
        convert_test_mechanism(indicator, indicator_instance)
    process_information_source(indicator.producer, indicator_instance, bundle_instance,
                               bundle_instance["created_by_ref"] if "created_by_ref" in bundle_instance else None)
    if indicator.suggested_coas is not None:
        warn("Using related-to")
        handle_relationship_to_refs(indicator.suggested_coas, indicator_instance["id"], bundle_instance, "related-to")
    if indicator.related_indicators is not None:
        handle_relationship_to_refs(indicator.related_indicators, indicator_instance["id"], bundle_instance,
                                    "related-to")
    if indicator.related_campaigns is not None:
        handle_relationship_to_refs(indicator.related_campaigns, indicator_instance["id"], bundle_instance,
                                    "attributed-to")
    if indicator.indicated_ttps is not None:
        handle_relationship_to_refs(indicator.indicated_ttps, indicator_instance["id"], bundle_instance, "indicates")
    if indicator.related_indicators:
        warn("All related indicators relationships of " + indicator.id_ + " are assumed to not represent STIX 1.2 versioning")
        handle_relationship_to_refs(indicator.related_indicators, indicator_instance["id"], bundle_instance,
                                    "related-to")
    finish_basic_object(indicator.id_, indicator_instance, indicator)
    return indicator_instance


# observables


def convert_observable_data(obs, bundle_instance):
    global OBSERVABLE_MAPPING
    observed_data_instance = create_basic_object("observable-data", obs)
    cybox_container = {"type": "cybox-container", "spec_version": "3.0"}
    observed_data_instance["cybox"] = convert_cybox_object(obs.object_, cybox_container)
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
    return observed_data_instance


# report


def process_report_contents(report, bundle_instance, report_instance):
    report_instance["object_refs"] = []
    if report.campaigns:
        for camp in report.campaigns:
            if camp.id_ is not None:
                camp20 = convert_campaign(camp, bundle_instance)
                bundle_instance["campaigns"].append(camp20)
                report_instance["object_refs"].append(camp20["id"])
            else:
                report_instance["object_refs"].append(camp.idref)

    # coas
    if report.courses_of_action:
        for coa in report.courses_of_action:
            if coa.id_ is not None:
                coa20 = convert_course_of_action(coa, bundle_instance)
                bundle_instance["courses_of_action"].append(coa20)
                report_instance["object_refs"].append(coa20["id"])
            else:
                report_instance["object_refs"].append(coa.idref)

    # exploit-targets
    if report.exploit_targets:
        for et in report.exploit_targets:
            convert_exploit_target(et, bundle_instance)

    # incidents
    if INCIDENT_IN_20:
        if report.incidents:
            for i in report.incidents:
                if i.id_ is not None:
                    i20 = convert_incident(i, bundle_instance)
                    bundle_instance["incidents"].append(i20)
                    report_instance["object_refs"].append(i20["id"])
                else:
                    report_instance["object_refs"].append(i.idref)

    # indicators
    if report.indicators:
        for i in report.indicators:
            if i.id_ is not None:
                i20 = convert_indicator(i, bundle_instance)
                bundle_instance["indicators"].append(i20)
                report_instance["object_refs"].append(i20["id"])
            else:
                report_instance["object_refs"].append(i.idref)

    # observables
    if report.observables:
        for o_d in report.observables:
            if o_d.id_ is not None:
                o_d20 = convert_observable_data(o_d, bundle_instance)
                bundle_instance["observed_data"].append(o_d20)
                report_instance["object_refs"].append(o_d20["id"])
            else:
                report_instance["object_refs"].append(o_d.idref)

    # threat actors
    if report.threat_actors:
        for ta in report.threat_actors:
            if ta.id_ is not None:
                ta20 = convert_threat_actor(ta, bundle_instance)
                bundle_instance["threat-actors"].append(ta20)
                report_instance["object_refs"].append(ta20["id"])
            else:
                report_instance["object_refs"].append(ta.idref)

    # ttps
    if report.ttps:
        for ttp in report.ttps:
            if ttp.id_:
                ttps20 = convert_ttp(ttp, bundle_instance)
                for ttp in ttps20:
                    if ttp["type"] == "malware":
                        bundle_instance["malware"].append(ttp)
                    elif ttp["type"] == "tool":
                        bundle_instance["tools"].append(ttp)
                    elif ttp["type"] == "attack_pattern":
                        bundle_instance["attack_patterns"].append(ttp)
                    report_instance["object_refs"].append(ttp["id"])
            else:
                report_instance["object_refs"].append(ttp.idref)


def convert_report(report, bundle_instance):
    report_instance = create_basic_object("report", report)
    process_description_and_short_description(report_instance, report.header)
    process_information_source(report.header.information_source, report_instance, bundle_instance,
                               bundle_instance["created_by_ref"] if "created_by_ref" in bundle_instance else None)
    add_string_property_to_description(report_instance, "intent", report.header.intents, True)
    if report.header.title is not None:
        report_instance["name"] = report.header.title
    convert_controlled_vocabs_to_open_vocabs(report_instance, "labels", report.header.intents, REPORT_LABELS_MAP, False)
    process_report_contents(report, bundle_instance, report_instance)
    # TODO: related reports?
    finish_basic_object(report.id_, report_instance, report.header)
    return report_instance


# threat actor


def convert_threat_actor(threat_actor, bundle_instance):
    threat_actor_instance = create_basic_object("threat-actor", threat_actor)
    process_description_and_short_description(threat_actor_instance, threat_actor)
    if threat_actor.identity is not None:
        if threat_actor.identity.id_:
            info("Threat actor identity " + threat_actor.identity.id_ + " being used as basis of attributed-to relationship")
        handle_relationship_to_objs([threat_actor.identity], threat_actor.id_, bundle_instance, "attributed-to")
    if threat_actor.title is not None:
        info("Threat actor " + threat_actor.id_ + "'s title is used for name property")
        threat_actor_instance["name"] = threat_actor.title
    convert_controlled_vocabs_to_open_vocabs(threat_actor_instance, "labels", threat_actor.types,
                                             THREAT_ACTOR_LABEL_MAP, False)
    add_multiple_statement_types_to_description(threat_actor_instance, threat_actor.intended_effects, "intended_effect")
    add_multiple_statement_types_to_description(threat_actor_instance, threat_actor.planning_and_operational_supports,
                                                "planning_and_operational_support")
    if hasattr(threat_actor, "confidence"):
        add_confidence_property_to_description(threat_actor_instance, threat_actor.confidence)
    # TODO: motivation is complicated
    convert_controlled_vocabs_to_open_vocabs(threat_actor_instance, "sophistication", threat_actor.sophistications,
                                             THREAT_ACTOR_SOPHISTICATION_MAP, True)
    # handle relationships
    if threat_actor.observed_ttps is not None:
        handle_relationship_to_refs(threat_actor.observed_ttps, threat_actor_instance["id"], bundle_instance, "uses")
    if threat_actor.associated_campaigns is not None:
        handle_relationship_from_refs(threat_actor.associated_campaigns, threat_actor_instance["id"], bundle_instance,
                                      "attributed_to")
    if threat_actor.associated_actors:
        warn(
            "All associated actors relationships of " + threat_actor.id_ + " are assumed to not represent STIX 1.2 versioning")
        handle_relationship_to_refs(threat_actor.associated_actors, threat_actor_instance["id"], bundle_instance,
                                    "related-to")
    process_information_source(threat_actor.information_source, threat_actor_instance, bundle_instance,
                               bundle_instance["created_by_ref"] if "created_by_ref" in bundle_instance else None)
    finish_basic_object(threat_actor.id_, threat_actor_instance, threat_actor)
    return threat_actor_instance


# TTPs


def process_ttp_properties(sdo_instance, ttp, bundle_instance, kill_chains_available=True):
    # TODO: handle description and short description
    add_multiple_statement_types_to_description(sdo_instance, ttp.intended_effects, "intended_effect")
    add_string_property_to_description(sdo_instance, "title", ttp.title, False)
    if ttp.exploit_targets is not None:
        handle_relationship_to_refs(ttp.exploit_targets, sdo_instance["id"], bundle_instance, "targets")
    if kill_chains_available:
        convert_kill_chains(ttp.kill_chain_phases, sdo_instance)
    if ttp.related_ttps:
        warn("All related indicators relationships of " + ttp.id_ + " are assumed to not represent STIX 1.2 versioning")
        handle_relationship_to_refs(ttp.related_ttps, sdo_instance["id"], bundle_instance,
                                    "related-to")
    if ttp.related_packages is not None:
        for p in ttp.related_packages:
            warn("TTP/Related_Packages on " + ttp.id_ + " not supported in STIX 2.0")
    process_information_source(ttp.information_source, sdo_instance, bundle_instance,
                               bundle_instance["created_by_ref"] if "created_by_ref" in bundle_instance else None)


def convert_attack_pattern(ap, ttp, bundle_instance, ttp_id_used):
    attack_Pattern_instance = create_basic_object("attack-pattern", ap, ttp.timestamp, ttp.id_, not ttp_id_used)
    if ap.title is not None:
        attack_Pattern_instance["name"] = ap.title
    process_description_and_short_description(attack_Pattern_instance, ap)
    if ap.capec_id is not None:
        attack_Pattern_instance["external_references"] = [{"source_name": "capec", "external_id": ap.capec_id}]
    process_ttp_properties(attack_Pattern_instance, ttp, bundle_instance)
    finish_basic_object(ttp.id_, attack_Pattern_instance, ap)
    return attack_Pattern_instance


def convert_malware_instance(mal, ttp, bundle_instance, ttp_id_used):
    malware_instance_instance = create_basic_object("malware", mal, ttp.timestamp, ttp.id_, not ttp_id_used)
    # TODO: names?
    if mal.title is not None:
        malware_instance_instance["name"] = mal.title
    process_description_and_short_description(malware_instance_instance, mal)
    convert_controlled_vocabs_to_open_vocabs(malware_instance_instance, "labels", mal.types, MALWARE_LABELS_MAP, False)
    if mal.names is not None:
        for n in mal.names:
            if "name" not in malware_instance_instance:
                malware_instance_instance["name"] = str(n)
            else:
                warn("Only one name for malware is allowed for " + malware_instance_instance[
                    "id"] + " in STIX 2.0 - used first one")
    # TODO: warning for MAEC content
    process_ttp_properties(malware_instance_instance, ttp, bundle_instance)
    finish_basic_object(ttp.id_, malware_instance_instance, mal)
    return malware_instance_instance


def convert_behavior(behavior, ttp, bundle_instance):
    resources_generated = []
    first_one = True
    if behavior.attack_patterns is not None:
        for ap in behavior.attack_patterns:
            new_obj = convert_attack_pattern(ap, ttp, bundle_instance, first_one)
            bundle_instance["attack_patterns"].append(new_obj)
            resources_generated.append(new_obj)
            first_one = False
    if behavior.malware_instances is not None:
        for mal in behavior.malware_instances:
            new_obj = convert_malware_instance(mal, ttp, bundle_instance, first_one)
            bundle_instance["malware"].append(new_obj)
            resources_generated.append(new_obj)
            first_one = False
    if behavior.exploits is not None:
        for e in behavior.exploits:
            warn("TTP/Behavior/Exploits/Exploit not supported in STIX 2.0")
    return resources_generated


def convert_tool(tool, ttp, bundle_instance, first_one):
    tool_instance = create_basic_object("tool", tool, ttp.timestamp, ttp.id_, not first_one)
    if tool.name is not None:
        tool_instance["name"] = tool.name
    process_description_and_short_description(tool_instance, tool)
    add_string_property_to_description(tool_instance, "vendor", tool.vendor)
    add_string_property_to_description(tool_instance, "service_pack", tool.service_pack)
    # TODO: add tool_specific_data to descriptor
    # TODO: add tool_hashes to descriptor
    # TODO: add tool_configuration to descriptor
    # TODO: add execution_environment to descriptor
    # TODO: add errors to descriptor
    # TODO: add compensation_model to descriptor
    add_string_property_to_description(tool_instance, "title", tool.title)
    convert_controlled_vocabs_to_open_vocabs(tool_instance, "labels", tool.type_, TOOL_LABELS_MAP, False)
    tool_instance["tool_version"] = tool.version
    process_ttp_properties(tool_instance, ttp, bundle_instance)
    finish_basic_object(ttp.id_, tool_instance, tool)
    return tool_instance


def convert_infrastructure(infra, ttp, bundle_instance, first_one):
    ttp_timestamp = ttp.timestamp
    infrastructure_instance = create_basic_object("infrastructure", infra, ttp_timestamp, not first_one)
    if infra.title is not None:
        infrastructure_instance["name"] = infra.title
    process_description_and_short_description(infrastructure_instance, infra)
    convert_controlled_vocabs_to_open_vocabs(infrastructure_instance, "labels", infra.types, {}, False)
    info("No 'first_seen' data on " + (infra.id_ if infra.id_ is not None else ttp.id_) + " - using timestamp")
    infrastructure_instance["first_seen"] = convert_timestamp(infra, ttp_timestamp)
    # TODO: observable_characterizations?
    process_ttp_properties(infrastructure_instance, ttp, bundle_instance)
    finish_basic_object(ttp.id_, infrastructure_instance, infra)
    return infrastructure_instance


def convert_resources(resources, ttp, bundle_instance):
    resources_generated = []
    first_one = True
    if resources.tools is not None:
        for t in resources.tools:
            new_obj = convert_tool(t, ttp, bundle_instance, first_one)
            bundle_instance["tools"].append(new_obj)
            resources_generated.append(new_obj)
            first_one = False
    if resources.infrastructure is not None:
        if INFRASTRUCTURE_IN_20:
            new_obj = convert_infrastructure(resources.infrastructure, ttp, bundle_instance, first_one)
            bundle_instance["infrastructure"].append(new_obj)
            resources_generated.append(new_obj)
            first_one = False
        else:
            warn("Infrastructure is not part of of STIX 2.0" + (" - " + ttp.id_ if ttp.id_ else ""))
    return resources_generated


def convert_identity_for_victim_target(identity, ttp, bundle_instance, ttp_generated):
    identity_instance = convert_identity(identity, bundle_instance, ttp.timestamp, ttp.id_ if not ttp_generated else None, False)
    bundle_instance["identities"].append(identity_instance)
    process_ttp_properties(identity_instance, ttp, bundle_instance, False)
    finish_basic_object(ttp.id_, identity_instance, identity)
    return identity_instance


def convert_victim_targeting(victim_targeting, ttp, bundle_instance, ttp_generated):
    if victim_targeting.targeted_systems:
        for v in victim_targeting.targeted_systems:
            warn("Targeted systems on " + ttp.id_ + " are not a victim target in STIX 2.0")
    if victim_targeting.targeted_information:
        for v in victim_targeting.targeted_information:
            warn("targeted information on " + ttp.id_ + " is not a victim target in STIX 2.0")
    if hasattr(victim_targeting, "technical_details") and victim_targeting.targeted_technical_details is not None:
        for v in victim_targeting.targeted_technical_details:
            warn("targeted technical details on " + ttp.id_ + " are not a victim target in STIX 2.0")
    if victim_targeting.identity:
        identity_instance = convert_identity_for_victim_target(victim_targeting.identity, ttp, bundle_instance,
                                                               ttp_generated)
        if identity_instance:
            warn(ttp.id_ + " generated an identity associated with a victim")
            if ttp_generated:
                bundle_instance["relationships"].append(
                    create_relationship(ttp.id_, identity_instance["id"], "targets", None, ttp.timestamp))
                # the relationship has been created, so its not necessary to propagate it up
                None
            else:
                return identity_instance
    # nothing generated
    return None


def convert_ttp(ttp, bundle_instance):
    generated_objs = []
    if ttp.behavior is not None:
        generated_objs.extend(convert_behavior(ttp.behavior, ttp, bundle_instance))
    if ttp.resources is not None:
        generated_objs.extend(convert_resources(ttp.resources, ttp, bundle_instance))
    if ttp.kill_chain_phases is not None:
        for phase in ttp.kill_chain_phases:
            warn("Kill chains are not defined explicitly in STIX 2.0. " + ttp.id_)
    if ttp.victim_targeting is not None:
        victim_target = convert_victim_targeting(ttp.victim_targeting, ttp, bundle_instance, generated_objs)
        if not victim_target:
            warn(ttp.id_ + " didn't yield any STIX 2.0 object")
        else:
            return generated_objs.append(victim_target)
    # victims weren't involved, check existing list
    if not generated_objs and ttp.id_ is not None:
        warn(ttp.id_ + " didn't yield any STIX 2.0 object")
    return generated_objs


# package


def handle_embedded_object(obj, bundle_instance):
    new20 = None
    new20s = None
    # campaigns
    if isinstance(obj, Campaign):
        new20 = convert_campaign(obj, bundle_instance)
        bundle_instance["campaigns"].append(new20)
    # coas
    elif isinstance(obj, CourseOfAction):
        new20 = convert_course_of_action(obj, bundle_instance)
        bundle_instance["courses_of_action"].append(new20)
    # exploit-targets
    elif isinstance(obj, ExploitTarget):
        new20s = convert_exploit_target(obj, bundle_instance)
    # identities
    elif isinstance(obj, Identity) or isinstance(obj, CIQIdentity3_0Instance):
        new20 = convert_identity(obj, bundle_instance)
        bundle_instance["identities"].append(new20)
    # incidents
    elif INCIDENT_IN_20 and isinstance(obj, Incident):
        new20 = convert_incident(obj, bundle_instance)
        bundle_instance["incidents"].append(new20)
    # indicators
    elif isinstance(obj, Indicator):
        new20 = convert_indicator(obj, bundle_instance)
        bundle_instance["indicators"].append(new20)
    # observables
    elif isinstance(obj, Observable):
        new20 = convert_observable_data(obj, bundle_instance)
        bundle_instance["observed_data"].append(new20)
    # reports
    elif isinstance(obj, Report):
        new20 = convert_report(obj, bundle_instance)
        bundle_instance["reports"].append(new20)
    # threat actors
    elif isinstance(obj, ThreatActor):
        new20 = convert_threat_actor(obj, bundle_instance)
        bundle_instance["threat-actors"].append(new20)
    # ttps
    elif isinstance(obj, TTP):
        new20s = convert_ttp(obj, bundle_instance)
    if new20:
        return [ new20 ]
    elif new20s:
        return new20s
    else:
        warn("No STIX 2.0 object generated from embedded object")
        return []


def initialize_bundle_lists(bundle_instance):
    bundle_instance["relationships"] = []
    bundle_instance["campaigns"] = []
    bundle_instance["courses_of_action"] = []
    bundle_instance["vulnerabilities"] = []
    bundle_instance["identities"] = []
    bundle_instance["incidents"] = []
    bundle_instance["indicators"] = []
    bundle_instance["reports"] = []
    bundle_instance["observed_data"] = []
    bundle_instance["threat-actors"] = []
    bundle_instance["attack_patterns"] = []
    bundle_instance["malware"] = []
    bundle_instance["tools"] = []
    bundle_instance["infrastructure"] = []
    bundle_instance["victim_targets"] = []


def finalize_bundle(bundle_instance):
    if KILL_CHAINS_PHASES != {}:
        for ind20 in bundle_instance["indicators"]:
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

    fix_relationships(bundle_instance["relationships"], bundle_instance)

    # TODO: fix created_by_ref
    # TODO: fix other embedded relationships

    add_relationships_to_reports(bundle_instance)

    _TO_MAP = ("id", "idref", "created_by_ref", "external_references",
               "marking_ref", "object_marking_refs", "object_refs",
               "target_ref", "source_ref", "sighting_of_ref",
               "observed_data_refs", "where_sighted_refs")

    for entry in iterpath(bundle_instance):
        path, value = entry
        last_field = path[-1]

        if isinstance(value, (list, dict)):
            continue

        if last_field in _TO_MAP and reference_needs_fixing(value) and exists_id_key(value):
            stix20_id = get_id_value(value)
            set_value_path(bundle_instance, path, stix20_id[0])
            info("Found " + value + " replaced by " + stix20_id[0])

    if not bundle_instance["relationships"]:
        del bundle_instance["relationships"]

    if not bundle_instance["campaigns"]:
        del bundle_instance["campaigns"]
    if not bundle_instance["courses_of_action"]:
        del bundle_instance["courses_of_action"]
    if not bundle_instance["vulnerabilities"]:
        del bundle_instance["vulnerabilities"]
    if not bundle_instance["identities"]:
        del bundle_instance["identities"]
    if not bundle_instance["incidents"]:
        del bundle_instance["incidents"]
    if not bundle_instance["indicators"]:
        del bundle_instance["indicators"]
    if not bundle_instance["observed_data"]:
        del bundle_instance["observed_data"]
    if not bundle_instance["reports"]:
        del bundle_instance["reports"]
    if not bundle_instance["threat-actors"]:
        del bundle_instance["threat-actors"]
    if not bundle_instance["attack_patterns"]:
        del bundle_instance["attack_patterns"]
    if not bundle_instance["malware"]:
        del bundle_instance["malware"]
    if not bundle_instance["tools"]:
        del bundle_instance["tools"]
    if not bundle_instance["infrastructure"]:
        del bundle_instance["infrastructure"]
    if not bundle_instance["victim_targets"]:
        del bundle_instance["victim_targets"]
    del bundle_instance["created_by_ref"]


def convert_package(stixPackage):
    bundle_instance = {"type": "bundle"}
    bundle_instance["id"] = generateSTIX20Id("bundle", stixPackage.id_)
    bundle_instance["spec_version"] = "2.0"
    initialize_bundle_lists(bundle_instance)
    if hasattr(stixPackage.stix_header,
               "information_source") and stixPackage.stix_header.information_source is not None:
        process_information_source(stixPackage.stix_header.information_source, bundle_instance, bundle_instance, None)
    else:
        bundle_instance["created_by_ref"] = None

    # TODO: other header stuff

    # do observables first, especially before indicators!

    # kill chains
    if stixPackage.ttps and stixPackage.ttps.kill_chains:
        for kc in stixPackage.ttps.kill_chains:
            process_kill_chain(kc)

    # observables
    if stixPackage.observables is not None:
        for o_d in stixPackage.observables:
            o_d20 = convert_observable_data(o_d, bundle_instance)
            bundle_instance["observed_data"].append(o_d20)

    # campaigns
    if stixPackage.campaigns:
        for camp in stixPackage.campaigns:
            camp20 = convert_campaign(camp, bundle_instance)
            bundle_instance["campaigns"].append(camp20)

    # coas
    if stixPackage.courses_of_action:
        for coa in stixPackage.courses_of_action:
            coa20 = convert_course_of_action(coa, bundle_instance)
            bundle_instance["courses_of_action"].append(coa20)

    # exploit-targets
    if stixPackage.exploit_targets:
        for et in stixPackage.exploit_targets:
            convert_exploit_target(et, bundle_instance)

    # incidents
    if INCIDENT_IN_20:
        if stixPackage.incidents:
            for i in stixPackage.incidents:
                i20 = convert_incident(i, bundle_instance)
                bundle_instance["incidents"].append(i20)

    # indicators
    if stixPackage.indicators:
        for i in stixPackage.indicators:
            i20 = convert_indicator(i, bundle_instance)
            bundle_instance["indicators"].append(i20)

    # observables
    if stixPackage.observables:
        for o_d in stixPackage.observables:
            o_d20 = convert_observable_data(o_d, bundle_instance)
            bundle_instance["observed_data"].append(o_d20)

    # reports
    if stixPackage.reports:
        for report in stixPackage.reports:
            report20 = convert_report(report, bundle_instance)
            bundle_instance["reports"].append(report20)

    # threat actors
    if stixPackage.threat_actors:
        for ta in stixPackage.threat_actors:
            ta20 = convert_threat_actor(ta, bundle_instance)
            bundle_instance["threat-actors"].append(ta20)

    # ttps
    if stixPackage.ttps:
        for ttp in stixPackage.ttps:
            convert_ttp(ttp, bundle_instance)

    finalize_bundle(bundle_instance)
    return bundle_instance


def convert_file(inFileName):
    clear_id_mapping()
    stixPackage = EntityParser().parse_xml(inFileName)
    if isinstance(stixPackage, STIXPackage):
        return json.dumps(convert_package(stixPackage), indent=4, separators=(',', ': '), sort_keys=True)


if __name__ == '__main__':
    print(convert_file(sys.argv[1]))
