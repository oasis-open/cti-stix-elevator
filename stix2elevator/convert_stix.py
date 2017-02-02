
# external
import pycountry
from six import text_type

from cybox.core import Observable
from lxml import etree

import stix
from stix.campaign import Campaign
from stix.coa import CourseOfAction
from stix.common.identity import Identity
from stix.common.kill_chains import KillChainPhase, KillChainPhaseReference
from stix.exploit_target import ExploitTarget
from stix.extensions.identity.ciq_identity_3_0 import CIQIdentity3_0Instance
from stix.extensions.test_mechanism.open_ioc_2010_test_mechanism import OpenIOCTestMechanism
from stix.extensions.test_mechanism.snort_test_mechanism import SnortTestMechanism
from stix.extensions.test_mechanism.yara_test_mechanism import YaraTestMechanism
from stix.incident import Incident
from stix.indicator import Indicator
from stix.threat_actor import ThreatActor
from stix.ttp import TTP

# internal
from stix2elevator.convert_cybox import convert_cybox_object
from stix2elevator.convert_pattern import (convert_indicator_to_pattern, convert_observable_to_pattern, fix_pattern,
                                           interatively_resolve_placeholder_refs, create_boolean_expression,
                                           add_to_pattern_cache, remove_pattern_objects, ComparisonExpression)
from stix2elevator.ids import *
from stix2elevator.options import get_option_value
from stix2elevator.utils import *
from stix2elevator.vocab_mappings import *

if stix.__version__ >= "1.2.0.0":
    from stix.report import Report
if "1.2.0.0" > stix.__version__ >= "1.1.1.7":
    import stix.extensions.marking.ais

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


def get_identity_ref(identity, bundle_instance, parent_timestamp):
    if identity.idref is not None:
        # fix reference later
        return identity.idref
    else:
        ident20 = convert_identity(identity, bundle_instance, parent_timestamp)
        bundle_instance["objects"].append(ident20)
        return ident20["id"]


def process_information_source(information_source, so, bundle_instance, parent_created_by_ref, parent_timestamp):
    if information_source:
        if information_source.identity is not None:
            so["created_by_ref"] = get_identity_ref(information_source.identity, bundle_instance, parent_timestamp)
        else:
            so["created_by_ref"] = parent_created_by_ref

        if so == bundle_instance:
            warn("Information Source on %s is not representable in STIX 2.0", 401, so["id"])
        else:
            if information_source.description:
                process_description_and_short_description(so, information_source)
            if information_source.references:
                for ref in information_source.references:
                    so["external_references"].append({"url": ref})
            if not get_option_value("no_squirrel_gaps")and information_source.roles:
                for role in information_source.roles:
                    # no vocab to make to in 2.0
                    so["description"] += "\n\n" + "INFORMATION SOURCE ROLE: " + role.value
            if information_source.tools:
                for tool in information_source.tools:
                    add_tool_property_to_description(so, tool)
    else:
        so["created_by_ref"] = parent_created_by_ref
    return so["created_by_ref"]


def convert_to_open_vocabs(stix20_obj, stix20_property_name, value, vocab_mapping):
    stix20_obj[stix20_property_name].append(map_vocabs_to_label(value, vocab_mapping))


def process_structured_text_list(text_list):
    full_text = ""
    for text_obj in text_list.sorted:
        full_text += text_obj.value
    return full_text


def process_description_and_short_description(so, entity, parent_info=False):
    if hasattr(entity, "descriptions") and entity.descriptions is not None:
        description_as_text = text_type(process_structured_text_list(entity.descriptions))
        if description_as_text:
            if parent_info:
                if not get_option_value("no_squirrel_gaps"):
                    if so["description"]:
                        so["description"] += "\nPARENT_DESCRIPTION: \n" + description_as_text
                    else:
                        so["description"] += description_as_text
            else:
                so["description"] += description_as_text
        if (not get_option_value("no_squirrel_gaps") and
                hasattr(entity, "short_descriptions") and
                entity.short_descriptions is not None):
            short_description_as_text = process_structured_text_list(entity.short_descriptions)
            if short_description_as_text:
                warn("The Short_Description property is no longer supported in STIX. The text was appended to the description property of %s", 301, so["id"])
                if parent_info:
                    if so["description"]:
                        so["description"] += "\nPARENT_SHORT_DESCRIPTION: \n" + short_description_as_text
                    else:
                        so["description"] += short_description_as_text
                else:
                    so["description"] += short_description_as_text
    # could be descriptionS or description
    elif hasattr(entity, "description") and entity.description is not None:
        so["description"] += text_type(entity.description.value)
    elif not get_option_value("no_squirrel_gaps") and hasattr(entity, "short_descriptions") and entity.short_descriptions is not None:
        so["description"] = text_type(process_structured_text_list(entity.short_descriptions))


def create_basic_object(stix20_type, stix1x_obj, parent_timestamp=None, parent_id=None, id_used=False):
    instance = {"type": stix20_type}
    instance["id"] = generate_stix20_id(stix20_type, stix1x_obj.id_ if (stix1x_obj and
                                                                        hasattr(stix1x_obj, "id_") and
                                                                        stix1x_obj.id_) else parent_id, id_used)
    timestamp = convert_timestamp(stix1x_obj, parent_timestamp, True)
    instance["created"] = timestamp
    # may need to revisit if we handle 1.x versioning.
    instance["modified"] = timestamp
    instance["description"] = ""
    instance["external_references"] = []
    return instance


def finish_basic_object(old_id, instance, stix1x_obj):
    if old_id is not None:
        record_ids(old_id, instance["id"])
    if hasattr(stix1x_obj, "handling") and stix1x_obj.handling is not None:
        info("Handling not implemented, yet", 801)
    if hasattr(stix1x_obj, "related_packages") and stix1x_obj.related_packages is not None:
        for p in stix1x_obj.related_packages:
            warn("Related_Packages type in %s not supported in STIX 2.0", 402, stix1x_obj.id_)


#
# handle gaps
#


def add_string_property_to_description(sdo_instance, property_name, property_value, is_list=False):
    if not get_option_value("no_squirrel_gaps") and property_value is not None:
        if is_list:
            sdo_instance["description"] += "\n\n" + property_name.upper() + ":\n"
            property_values = []
            for v in property_value:
                property_values.append(text_type(v))
            sdo_instance["description"] += ",\n".join(property_values)
        else:
            sdo_instance["description"] += "\n\n" + property_name.upper() + ":\n\t" + text_type(property_value)
        warn("Appended %s to description of %s", 302, property_name, sdo_instance["id"])


def add_confidence_property_to_description(sdo_instance, confidence):
    if not get_option_value("no_squirrel_gaps"):
        if confidence is not None:
            sdo_instance["description"] += "\n\n" + "CONFIDENCE: "
            if confidence.value is not None:
                sdo_instance["description"] += text_type(confidence.value)
            if confidence.description is not None:
                sdo_instance["description"] += "\n\tDESCRIPTION: " + text_type(confidence.description)
            warn("Appended Confidence type content to description of %s", 304, sdo_instance["id"])


def add_statement_type_to_description(sdo_instance, statement, property_name):
    if statement and not get_option_value("no_squirrel_gaps"):
        sdo_instance["description"] += "\n\n" + property_name.upper() + ":"
        if statement.value:
            sdo_instance["description"] += text_type(statement.value)
        if statement.descriptions:
            descriptions = []
            for d in statement.descriptions:
                descriptions.append(text_type(d.value))
            sdo_instance["description"] += "\n\n\t".join(descriptions)

        if statement.source is not None:
            # FIXME: Handle source
            info("Source in %s is not handled, yet.", 815, sdo_instance["id"])
        if statement.confidence:
            add_confidence_property_to_description(sdo_instance, statement.confidence)
        warn("Appended Statement type content to description of %s", 305, sdo_instance["id"])


def add_multiple_statement_types_to_description(sdo_instance, statements, property_name):
    if not get_option_value("no_squirrel_gaps"):
        for s in statements:
            add_statement_type_to_description(sdo_instance, s, property_name)


def add_tool_property_to_description(sdo_instance, tool):
    if not get_option_value("no_squirrel_gaps"):
        sdo_instance["description"] += "\n\nTOOL SOURCE:"
        if tool.name:
            sdo_instance["description"] += "\n\tname: " + text_type(tool.name)
        warn("Appended Tool type content to description of %s", 306, sdo_instance["id"])


# Relationships


def create_relationship(source_ref, target_ref, verb, rel_obj, parent_timestamp, endpoint_identity_ref):
    relationship_instance = create_basic_object("relationship", rel_obj, parent_timestamp)
    relationship_instance["source_ref"] = source_ref
    relationship_instance["target_ref"] = target_ref
    relationship_instance["relationship_type"] = verb
    relationship_instance["created_by_ref"] = endpoint_identity_ref
    if rel_obj is not None and hasattr(rel_obj, "relationship") and rel_obj.relationship is not None:
        relationship_instance["description"] = rel_obj.relationship.value
    return relationship_instance


# Creating and Linking up relationships  (three cases)
# 1.  The object is embedded - create the object, add it to the bundle, return to id so the relationship is complete
# 2.  an idref is given, and it has a corresponding 2.0 id, use it
# 3.  an idref is given, but it has NO corresponding 2.0 id, add 1.x id, and fix at the end in fix_relationships


def handle_relationship_to_objs(items, source_id, bundle_instance, verb, parent_timestamp=None,
                                source_identity_ref=None):
    for item in items:
        new20s = handle_embedded_object(item, bundle_instance, source_identity_ref, parent_timestamp)
        for new20 in new20s:
            bundle_instance["relationships"].append(create_relationship(source_id,
                                                                        new20["id"] if new20 else None,
                                                                        verb,
                                                                        item,
                                                                        parent_timestamp,
                                                                        source_identity_ref))


def handle_relationship_to_refs(refs, source_id, bundle_instance, verb, parent_timestamp=None,
                                source_identity_ref=None):
    for ref in refs:
        if ref.item.idref is None:
            # embedded
            new20s = handle_embedded_object(ref.item, bundle_instance, source_identity_ref, parent_timestamp)
            for new20 in new20s:
                bundle_instance["relationships"].append(create_relationship(source_id,
                                                                            new20["id"] if new20 else None,
                                                                            verb,
                                                                            ref,
                                                                            parent_timestamp,
                                                                            source_identity_ref))
        elif exists_id_key(ref.item.idref):
            for to_ref in get_id_value(ref.item.idref):
                bundle_instance["relationships"].append(create_relationship(source_id,
                                                                            to_ref,
                                                                            verb,
                                                                            ref,
                                                                            parent_timestamp,
                                                                            source_identity_ref))
        else:
            # a forward reference, fix later
            bundle_instance["relationships"].append(create_relationship(source_id,
                                                                        ref.item.idref,
                                                                        verb,
                                                                        ref,
                                                                        parent_timestamp,
                                                                        source_identity_ref))


def handle_relationship_from_refs(refs, target_id, bundle_instance, verb, parent_timestamp=None,
                                  target_identity_ref=None):
    for ref in refs:
        if ref.item.idref is None:
            # embedded
            new20s = handle_embedded_object(ref.item, bundle_instance, target_identity_ref, parent_timestamp)
            for new20 in new20s:
                bundle_instance["relationships"].append(create_relationship(new20["id"] if new20 else None,
                                                                            target_id,
                                                                            verb,
                                                                            ref,
                                                                            parent_timestamp,
                                                                            target_identity_ref))
        elif exists_id_key(ref.item.idref):
            for from_ref in get_id_value(ref.item.idref):
                bundle_instance["relationships"].append(create_relationship(from_ref,
                                                                            target_id,
                                                                            verb,
                                                                            ref,
                                                                            parent_timestamp,
                                                                            target_identity_ref))
        else:
            # a forward reference, fix later
            bundle_instance["relationships"].append(create_relationship(ref.item.idref,
                                                                        target_id,
                                                                        verb,
                                                                        ref,
                                                                        parent_timestamp,
                                                                        target_identity_ref))


def reference_needs_fixing(ref):
    return ref and ref.find("--") == -1


def determine_appropriate_verb(current_verb, m_id):
    if m_id is not None and current_verb == "uses":
        type_and_uuid = m_id.split("--")
        if type_and_uuid[0] == "identity":
            return "targets"
    return current_verb


# for ids in source and target refs that are still 1.x ids,
def fix_relationships(relationships, bundle_instance):
    for ref in relationships:
        if reference_needs_fixing(ref["source_ref"]):
            if not exists_id_key(ref["source_ref"]):
                new_id = generate_stix20_id(None, str.lower(ref["source_ref"]))
                if new_id is None:
                    warn("Dangling source reference %s in %s", 601, ref["source_ref"], ref["id"])
                add_id_value(ref["source_ref"], new_id)
            first_one = True
            for m_id in get_id_value(ref["source_ref"]):
                if first_one:
                    ref["source_ref"] = m_id
                else:
                    bundle_instance["relationships"].append(create_relationship(m_id, ref["target_ref"], ref["verb"]))
        if reference_needs_fixing(ref["target_ref"]):
            if not exists_id_key(ref["target_ref"]):
                new_id = generate_stix20_id(None, str.lower(ref["target_ref"]))
                if new_id is None:
                    warn("Dangling target reference %s in %s", 602, ref["target_ref"], ref["id"])
                add_id_value(ref["target_ref"], new_id)
            first_one = True
            for m_id in get_id_value(ref["target_ref"]):
                verb = determine_appropriate_verb(ref["relationship_type"], m_id)
                if first_one:
                    ref["target_ref"] = m_id
                    ref["relationship_type"] = verb
                else:
                    bundle_instance["relationships"].append(create_relationship(ref["source_ref"], m_id, verb))


# Relationships are not in 1.x, so they must be added explicitly to reports.
# This is done after the package has been processed, and the relationships are "fixed", so all relationships are known
#
# For each report:
#   For each relationship
#       if the source and target are part of the report, add the relationship
#       if the source is part of the report, add the relationship AND then the target,
#          UNLESS the target ref is "dangling"
#       if the target is part of the report, add the relationship AND then the source,
#          UNLESS the source ref is "dangling"


def add_relationships_to_reports(bundle_instance):
    rels_to_include = []
    new_ids = get_id_values()
    for rep in bundle_instance["reports"]:
        refs_in_this_report = rep["object_refs"]
        for rel in bundle_instance["relationships"]:
            if (("source_ref" in rel and rel["source_ref"] in refs_in_this_report) and
                    ("target_ref" in rel and rel["target_ref"] in refs_in_this_report)):
                rels_to_include.append(rel["id"])
            elif "source_ref" in rel and rel["source_ref"] in refs_in_this_report:
                # and target_ref is not in refs_in_this_report
                if "target_ref" in rel and rel["target_ref"] and (
                        rel["target_ref"] in new_ids or rel["target_ref"] in SDO_WITH_NO_1X_OBJECT):
                    rels_to_include.append(rel["id"])
                    rels_to_include.append(rel["target_ref"])
                    warn("Including %s in %s and added the target_ref %s to the report", 704, rel["id"], rep["id"], rel["target_ref"])
                elif not ("target_ref" in rel and rel["target_ref"]):
                    rels_to_include.append(rel["id"])
                    warn("Including %s in %s although the target_ref is unknown", 706, rel["id"], rep["id"])
                elif not (rel["target_ref"] in new_ids or rel["target_ref"] in SDO_WITH_NO_1X_OBJECT):
                    warn("Not including %s in %s because there is no corresponding SDO for %s", 708, rel["id"], rep["id"], rel["target_ref"])
            elif "target_ref" in rel and rel["target_ref"] in refs_in_this_report:
                if "source_ref" in rel and rel["source_ref"] and (
                        rel["source_ref"] in new_ids or rel["source_ref"] in SDO_WITH_NO_1X_OBJECT):
                    rels_to_include.append(rel["id"])
                    rels_to_include.append(rel["source_ref"])
                    warn("Including %s in %s and added the source_ref %s to the report", 705, rel["id"], rep["id"], rel["source_ref"])
                elif not ("source_ref" in rel and rel["source_ref"]):
                    rels_to_include.append(rel["id"])
                    warn("Including %s in %s although the source_ref is unknown", 707, rel["id"], rep["id"])
                elif not (rel["source_ref"] in new_ids or rel["source_ref"] in SDO_WITH_NO_1X_OBJECT):
                    warn("Not including %s in %s because there is no corresponding SDO for %s", 709, rel["id"], rep["id"], rel["source_ref"])
        if "object_refs" in rep:
            rep["object_refs"].extend(rels_to_include)
        else:
            rep["object_refs"] = rels_to_include


# campaign


def convert_campaign(camp, bundle_instance, parent_created_by_ref, parent_timestamp):
    campaign_instance = create_basic_object("campaign", camp, parent_timestamp)
    process_description_and_short_description(campaign_instance, camp)
    campaign_instance["name"] = camp.title
    if camp.names is not None:
        campaign_instance["aliases"] = []
        for name in camp.names:
            campaign_instance["aliases"].append(name)
    # process information source before any relationships
    campaign_created_by_ref = process_information_source(camp.information_source, campaign_instance,
                                                         bundle_instance, parent_created_by_ref,
                                                         campaign_instance["created"])
    add_multiple_statement_types_to_description(campaign_instance, camp.intended_effects, "intended_effect")
    add_string_property_to_description(campaign_instance, "status", camp.status)
    if hasattr(camp, "confidence"):
        add_confidence_property_to_description(campaign_instance, camp.confidence)

    if camp.activity is not None:
        for a in camp.activity:
            warn("Campaign/Activity type in %s not supported in STIX 2.0", 403, campaign_instance["id"])
    if camp.related_ttps is not None:
        # victims use targets, not uses
        handle_relationship_to_refs(camp.related_ttps,
                                    campaign_instance["id"],
                                    bundle_instance,
                                    "uses",
                                    campaign_instance["created"],
                                    campaign_created_by_ref)
    if camp.related_incidents is not None:
        handle_relationship_from_refs(camp.related_incidents,
                                      campaign_instance["id"],
                                      bundle_instance,
                                      "attributed-to",
                                      campaign_instance["created"],
                                      campaign_created_by_ref)
    if camp.related_indicators is not None:
        handle_relationship_from_refs(camp.related_indicators,
                                      campaign_instance["id"],
                                      bundle_instance,
                                      "indicates",
                                      campaign_instance["created"],
                                      campaign_created_by_ref)
    if camp.attribution is not None:
        for att in camp.attribution:
            handle_relationship_to_refs(att,
                                        campaign_instance["id"],
                                        bundle_instance,
                                        "attributed-to",
                                        campaign_instance["created"],
                                        campaign_created_by_ref)
    if camp.associated_campaigns:
        warn("All associated campaigns relationships of %s are assumed to not represent STIX 1.2 versioning", 710, camp.id_)
        handle_relationship_to_refs(camp.related_coas,
                                    campaign_instance["id"],
                                    bundle_instance,
                                    "related-to",
                                    campaign_instance["created"],
                                    campaign_created_by_ref)
    finish_basic_object(camp.id_, campaign_instance, camp)
    return campaign_instance


# course of action


def add_objective_property_to_description(sdo_instance, objective):
    if not get_option_value("no_squirrel_gaps"):
        if objective is not None:
            sdo_instance["description"] += "\n\n" + "OBJECTIVE: "
            all_text = []

            if objective.descriptions:
                for d in objective.descriptions:
                    all_text.append(text_type(d.value))

            if objective.short_descriptions:
                for sd in objective.short_descriptions:
                    all_text.append(text_type(sd.value))

            sdo_instance["description"] += "\n\n\t".join(all_text)

            if objective.applicability_confidence:
                add_confidence_property_to_description(sdo_instance, objective.applicability_confidence)


def convert_course_of_action(coa, bundle_instance, parent_created_by_ref, parent_timestamp):
    coa_instance = create_basic_object("course-of-action", coa, parent_timestamp)
    process_description_and_short_description(coa_instance, coa)
    coa_instance["name"] = coa.title
    add_string_property_to_description(coa_instance, "stage", coa.stage)
    if coa.type_:
        convert_controlled_vocabs_to_open_vocabs(coa_instance, "labels", [coa.type_], COA_LABEL_MAP, False)
    add_objective_property_to_description(coa_instance, coa.objective)

    if coa.parameter_observables is not None:
        # parameter observables, maybe turn into pattern expressions and put in description???
        warn("Parameter Observables in %s are not handled, yet.", 814, coa_instance["id"])
    if coa.structured_coa:
        warn("Structured COAs type in %s are not supported in STIX 2.0", 404, coa_instance["id"])
    add_statement_type_to_description(coa_instance, coa.impact, "impact")
    add_statement_type_to_description(coa_instance, coa.cost, "cost")
    add_statement_type_to_description(coa_instance, coa.efficacy, "efficacy")
    coa_created_by_ref = process_information_source(coa.information_source,
                                                    coa_instance,
                                                    bundle_instance,
                                                    parent_created_by_ref,
                                                    coa_instance["created"])
    # process information source before any relationships
    if coa.related_coas:
        warn("All associated coas relationships of %s are assumed to not represent STIX 1.2 versioning", 710, coa.id_)
        handle_relationship_to_refs(coa.related_coas, coa_instance["id"], bundle_instance,
                                    "related-to", coa_instance["created"], coa_created_by_ref)
    finish_basic_object(coa.id_, coa_instance, coa)
    return coa_instance


# exploit target


def process_et_properties(sdo_instance, et, bundle_instance, parent_created_by_ref):
    process_description_and_short_description(sdo_instance, et, True)
    if "name" in sdo_instance:
        info("Title %s used for name, appending exploit_target %s title in description property", 303, sdo_instance["type"], sdo_instance["id"])
        add_string_property_to_description(sdo_instance, "title", et.title, False)
    elif et.title is not None:
        sdo_instance["name"] = et.title
    et_created_by_ref = process_information_source(et.information_source, sdo_instance,
                                                   bundle_instance, parent_created_by_ref,
                                                   sdo_instance["created"])
    if et.potential_coas is not None:
        handle_relationship_from_refs(et.potential_coas, sdo_instance["id"], bundle_instance, "mitigates",
                                      sdo_instance["created"], et_created_by_ref)


def convert_vulnerability(v, et, bundle_instance, parent_created_by_ref, parent_timestamp):
    vulnerability_instance = create_basic_object("vulnerability", v, parent_timestamp, et.id_)
    if v.title is not None:
        vulnerability_instance["name"] = v.title
    process_description_and_short_description(vulnerability_instance, v)
    if v.cve_id is not None:
        vulnerability_instance["external_references"].append({"source_name": "cve", "external_id": v.cve_id})
    if v.osvdb_id is not None:
        vulnerability_instance["external_references"].append({"source_name": "osvdb", "external_id": v.osvdb_id})

    if v.source is not None:
        # FIXME: add source.
        info("Source in %s is not handled, yet.", 815, vulnerability_instance["id"])

    if v.cvss_score is not None:
        # FIXME: add CVSS score into description
        info("CVSS Score in %s is not handled, yet.", 815, vulnerability_instance["id"])

    if v.discovered_datetime is not None or v.published_datetime is not None:
        # FIXME: add date times into description
        info("Discoreved_DateTime and Published_DateTime in %s is not handled, yet.", 815, vulnerability_instance["id"])

    if v.affected_software is not None:
        #  FIXME: add affected software into description
        info("Affected_Software in %s is not handled, yet.", 815, vulnerability_instance["id"])

    if v.references is not None:
        for ref in v.references:
            vulnerability_instance["external_references"].append({"source_name": "internet_resource", "url": ref.reference})
    process_et_properties(vulnerability_instance, et, bundle_instance, parent_created_by_ref)
    finish_basic_object(et.id_, vulnerability_instance, v)
    return vulnerability_instance


def convert_exploit_target(et, bundle_instance, parent_created_by_ref, parent_timestamp):
    if hasattr(et, "created") and et.timestamp:
        parent_timestamp = et.timestamp
    if et.vulnerabilities is not None:
        for v in et.vulnerabilities:
            bundle_instance["objects"].append(convert_vulnerability(v, et, bundle_instance,
                                                                    parent_created_by_ref,
                                                                    parent_timestamp))
    if et.weaknesses is not None:
        for w in et.weaknesses:
            warn("ExploitTarget/Weaknesses type in %s not supported in STIX 2.0", 405, et.id_)
    if et.configuration is not None:
        for c in et.configuration:
            warn("ExploitTarget/Configurations type in %s not supported in STIX 2.0", 406, et.id_)


# identities


def convert_ciq_addresses(addresses, identity_instance):
    identity_instance["country"] = []
    identity_instance["regions"] = []
    for add in addresses:
        temp_country = None
        if hasattr(add, "country"):
            for name in add.country.name_elements:
                iso = pycountry.countries.get(name=name.value)
                temp_country = iso.alpha2
                if iso is not None:
                    identity_instance["country"].append(iso.alpha2)
                else:
                    warn("No ISO code for %s in %s", 618, name.value, identifying_info(identity_instance))
                    identity_instance["country"].append(name.value)
        if hasattr(add, "administrative_area"):
            for name in add.administrative_area.name_elements:
                iso = pycountry.subdivisions.get(country_code=temp_country)
                iso = [x for x in iso if x.name == text_type(name.value)]
                if iso:
                    identity_instance["regions"].append(iso[0].code)
                else:
                    identity_instance["regions"].append(name.value)


def get_name(name):
    return name.name_elements[0].value


def convert_party_name(party_name, identity):
    if party_name.organisation_names and party_name.person_names:
        error("Identity %s has organization and person names", 606, identity["id"])
    if party_name.person_names:
        identity["identity_class"] = "individual"
        first_one = True
        for name in party_name.person_names:
            if first_one:
                identity["name"] = get_name(name)
                first_one = False
            else:
                warn("Only one person name allowed for %s in STIX 2.0, used first one", 502, identity["id"])
                # add to description
    elif party_name.organisation_names:
        identity["identity_class"] = "organization"
        first_one = True
        for name in party_name.organisation_names:
            if first_one:
                identity["name"] = get_name(name)
                first_one = False
            else:
                warn("Only one organization name allowed for %s in STIX 2.0, used first one", 503, identity["id"])
                # add to description


def convert_identity(identity, bundle_instance, parent_timestamp=None, parent_id=None):
    identity_instance = create_basic_object("identity", identity, parent_timestamp, parent_id)
    identity_instance["sectors"] = []
    identity_instance["identity_class"] = "unknown"
    if identity.name is not None:
        identity_instance["name"] = identity.name
    if isinstance(identity, CIQIdentity3_0Instance):
        if identity.roles:
            convert_controlled_vocabs_to_open_vocabs(identity_instance, "roles", identity.roles, ROLES_MAP, False)
        ciq_info = identity._specification
        if ciq_info.party_name:
            warn("CIQ name found in %s, possibly overriding other name", 711, identity_instance["id"])
            convert_party_name(ciq_info.party_name, identity_instance)
        if ciq_info.organisation_info:
            identity_instance["identity_class"] = "organization"
            warn("Based on CIQ information, %s is assumed to be an organization", 716, identity_instance["id"])
            if ciq_info.organisation_info.industry_type:
                industry = ciq_info.organisation_info.industry_type.replace(" ,", ",")
                industry = industry.replace(", ", ",")
                industry = industry.split(",")
                convert_controlled_vocabs_to_open_vocabs(identity_instance, "sectors", industry, SECTORS_MAP, False)
        if ciq_info.addresses:
            pass
            # convert_ciq_addresses(ciq_info.addresses, identity_instance)
            # add other properties to contact_information
    if identity.related_identities:
        msg = "All associated identities relationships of %s are assumed to not represent STIX 1.2 versioning"
        warn(msg, 710, identity_instance["id"])
        handle_relationship_to_refs(identity.related_identities, identity_instance["id"], bundle_instance,
                                    "related-to", parent_timestamp)
    finish_basic_object(identity.id_, identity_instance, identity)
    return identity_instance


# incident


def convert_incident(incident, bundle_instance, parent_created_by_ref, parent_timestamp):
    incident_instance = create_basic_object("incident", incident, parent_timestamp)
    process_description_and_short_description(incident_instance, incident)
    if incident.title is not None:
        incident_instance["name"] = incident.title
    if incident.external_ids is not None:
        for ex_id in incident.external_ids:
            incident_instance["external_references"].append(
                {"source_name": ex_id.external_id.source, "external_id": ex_id.external_id.value})
    # time
    if incident.categories is not None:
        convert_controlled_vocabs_to_open_vocabs(incident_instance, "labels", incident.categories, INCIDENT_LABEL_MAP,
                                                 False)
    incident_created_by_ref = process_information_source(incident.information_source, incident_instance,
                                                         bundle_instance, parent_created_by_ref,
                                                         incident_instance["created"])

    add_confidence_property_to_description(incident_instance, incident.confidence)

    # process information source before any relationships
    if incident.related_indicators is not None:
        handle_relationship_from_refs(incident.related_indicators, incident_instance["id"], bundle_instance,
                                      "indicates", incident_instance["created"], incident_created_by_ref)
    if incident.related_observables is not None:
        handle_relationship_from_refs(incident.related_observables, incident_instance["id"], bundle_instance, "part-of",
                                      incident_instance["created"], incident_created_by_ref)
    if incident.leveraged_ttps is not None:
        warn("Using related-to for the leveraged TTPs of %s", 718, incident.id_)
        handle_relationship_to_refs(incident.leveraged_ttps, incident_instance["id"], bundle_instance, "related-to",
                                    incident_instance["created"], incident_created_by_ref)

    if incident.reporter is not None:
        # FIXME: add reporter to description
        info("Incident Reporter in %s is not handled, yet.", 815, incident_instance["id"])

    if incident.responders is not None:
        # FIXME: add responders to description
        info("Incident Responders in %s is not handled, yet.", 815, incident_instance["id"])

    if incident.coordinators is not None:
        # FIXME: add coordinators to description
        info("Incident Coordinators in %s is not handled, yet.", 815, incident_instance["id"])

    if incident.victims is not None:
        # FIXME: add victim to description
        info("Incident Victims in %s is not handled, yet.", 815, incident_instance["id"])

    if incident.affected_assets is not None:
        # FIXME: add affected_assets to description
        info("Incident Affected Assets in %s is not handled, yet.", 815, incident_instance["id"])

    if incident.impact_assessment is not None:
        # FIXME: add impact_assessment to description
        info("Incident Impact Assessment in %s is not handled, yet", 815, incident_instance["id"])
    add_string_property_to_description(incident_instance, "status", incident.status)
    if incident.related_incidents:
        warn("All associated incidents relationships of %s are assumed to not represent STIX 1.2 versioning", 710, incident_instance["id"])
        handle_relationship_to_refs(incident.related_incidents, incident_instance["id"], bundle_instance,
                                    "related-to", incident_instance["created"], incident_created_by_ref)
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
                except KeyError:
                    kill_chain_phases_20.append(phase.phase_id)
            elif isinstance(phase, KillChainPhase):
                kill_chain_phases_20.append({"kill_chain_name": phase.kill_chain_name, "phase_name": phase.name})
        if kill_chain_phases_20:
            sdo_instance["kill_chain_phases"] = kill_chain_phases_20


_ALLOW_YARA_AND_SNORT_PATTENS = False


def convert_test_mechanism(indicator, indicator_instance):
    if indicator.test_mechanisms is not None:
        if not _ALLOW_YARA_AND_SNORT_PATTENS:
            warn("YARA/SNORT patterns on %s not supported in STIX 2.0", 504, indicator_instance["id"])
            return
        if hasattr(indicator_instance, "pattern"):
            # TODO: maybe put in description
            warn("Only one type pattern can be specified in %s - using cybox", 712, indicator_instance["id"])
        else:
            for tm in indicator.test_mechanisms:
                if hasattr(indicator_instance, "pattern"):
                    # TODO: maybe put in description
                    msg = "Only one alternative test mechanism allowed for %s in STIX 2.0 - used first one, which was %s"
                    warn(msg, 506, indicator_instance["id"], indicator_instance["pattern_lang"])
                else:
                    if isinstance(tm, YaraTestMechanism):

                        indicator_instance["pattern"] = text_type(tm.rule.value)
                        indicator_instance["pattern_lang"] = "yara"
                    elif isinstance(tm, SnortTestMechanism):
                        list_of_strings = []
                        for rule in tm.rules:
                            list_of_strings.append(text_type(rule.value))
                        indicator_instance["pattern"] = ", ".join(list_of_strings)
                        indicator_instance["pattern_lang"] = "snort"
                    elif isinstance(tm, OpenIOCTestMechanism):
                        indicator_instance["pattern"] = etree.tostring(tm.ioc)
                        indicator_instance["pattern_lang"] = "openioc"


def negate_indicator(indicator):
    return hasattr(indicator, "negate") and indicator.negate


def convert_indicator(indicator, bundle_instance, parent_created_by_ref, parent_timestamp):
    global SUB_INDICATOR_IDS
    indicator_instance = create_basic_object("indicator", indicator, parent_timestamp)
    process_description_and_short_description(indicator_instance, indicator)
    convert_controlled_vocabs_to_open_vocabs(indicator_instance, "labels", indicator.indicator_types,
                                             INDICATOR_LABEL_MAP, False)
    if indicator.title is not None:
        indicator_instance["name"] = indicator.title
    if indicator.alternative_id is not None:
        for alt_id in indicator.alternative_id:
            indicator_instance["external_references"].append({"source_name": "alternative_id", "external_id": alt_id})
    if indicator.valid_time_positions is not None:
        for window in indicator.valid_time_positions:
            if "valid_from" not in indicator_instance:
                indicator_instance["valid_from"] = \
                    convert_timestamp_string(window.start_time.value, indicator, indicator_instance["created"])
                indicator_instance["valid_until"] = \
                    convert_timestamp_string(window.end_time.value, indicator, indicator_instance["created"])
            else:
                warn("Only one valid time window allowed for %s in STIX 2.0 - used first one", 507, indicator_instance["id"])
        if "valid_from" not in indicator_instance:
            warn("No valid time position information available in %s, using parent timestamp", 903, indicator_instance["id"])
            indicator_instance["valid_from"] = convert_timestamp(indicator, parent_timestamp)
    convert_kill_chains(indicator.kill_chain_phases, indicator_instance)
    if indicator.likely_impact:
        add_statement_type_to_description(indicator_instance, indicator.likely_impact, "likely_impact")
    if indicator.confidence:
        add_confidence_property_to_description(indicator_instance, indicator.confidence)
    if indicator.sightings:
        info("Sighthings in %s are not handled, yet.", 815, indicator_instance["id"])
    if indicator.observable and indicator.composite_indicator_expression or indicator.composite_indicator_expression:
        warn("Indicator %s has an observable or indicator composite expression which is not supported in STIX 2.0", 407, indicator_instance["id"])
    if indicator.observable is not None:
        indicator_instance["pattern"] = convert_observable_to_pattern(indicator.observable, bundle_instance,
                                                                      OBSERVABLE_MAPPING)
        add_to_pattern_cache(indicator.id_, indicator_instance["pattern"])
    if indicator.composite_indicator_expression is not None:
        expressions = []
        if stix.__version__ >= "1.2.0.0":
            sub_indicators = indicator.composite_indicator_expression.indicator
        else:
            sub_indicators = indicator.composite_indicator_expression
        for ind in sub_indicators:
            term = convert_indicator_to_pattern(ind, bundle_instance, OBSERVABLE_MAPPING)
            if term:
                expressions.append(term)
        indicator_instance["pattern"] = create_boolean_expression(indicator.composite_indicator_expression.operator,
                                                                  expressions)
        # add_to_pattern_cache(indicator.id_, indicator_instance["pattern"])
    if "pattern" not in indicator_instance:
        # STIX doesn't handle multiple patterns for indicators
        convert_test_mechanism(indicator, indicator_instance)
    indicator_created_by_ref = process_information_source(indicator.producer, indicator_instance,
                                                          bundle_instance, parent_created_by_ref,
                                                          indicator_instance["created"])
    # process information source before any relationships
    if indicator.suggested_coas is not None:
        warn("Using related-to for the suggested COAs of %s", 718, indicator.id_)
        handle_relationship_to_refs(indicator.suggested_coas, indicator_instance["id"], bundle_instance,
                                    "related-to", indicator_instance["created"], indicator_created_by_ref)
    if indicator.related_campaigns is not None:
        handle_relationship_to_refs(indicator.related_campaigns, indicator_instance["id"], bundle_instance,
                                    "attributed-to", indicator_instance["created"], indicator_created_by_ref)
    if indicator.indicated_ttps is not None:
        handle_relationship_to_refs(indicator.indicated_ttps, indicator_instance["id"], bundle_instance,
                                    "indicates", indicator_instance["created"], indicator_created_by_ref)
    if indicator.related_indicators:
        warn("All associated indicators relationships of %s are assumed to not represent STIX 1.2 versioning", 710, indicator.id_)
        handle_relationship_to_refs(indicator.related_indicators, indicator_instance["id"], bundle_instance,
                                    "related-to", indicator_instance["created"], indicator_created_by_ref)
    finish_basic_object(indicator.id_, indicator_instance, indicator)
    return indicator_instance


# observables


def convert_observed_data(obs, bundle_instance, parent_created_by_ref, parent_timestamp):
    global OBSERVABLE_MAPPING
    observed_data_instance = create_basic_object("observed-data", obs, parent_timestamp)
    # cybox_container = {"type": "cybox-container", "spec_version": "3.0"}
    observed_data_instance["objects"] = convert_cybox_object(obs.object_)
    info("'first_observed' and 'last_observed' data not available directly on %s - using timestamp", 901, obs.id_)
    observed_data_instance["first_observed"] = observed_data_instance["created"]
    observed_data_instance["last_observed"] = observed_data_instance["created"]
    observed_data_instance["number_observed"] = 1 if obs.sighting_count is None else obs.sighting_count
    # created_by
    finish_basic_object(obs.id_, observed_data_instance, obs)
    # remember the original 1.x observable, in case it has to be turned into a pattern later
    OBSERVABLE_MAPPING[obs.id_] = obs
    return observed_data_instance


# report


def process_report_contents(report, bundle_instance, report_instance, parent_created_by_ref, parent_timestamp):
    report_instance["object_refs"] = []
    if report.campaigns:
        for camp in report.campaigns:
            if camp.id_ is not None:
                camp20 = convert_campaign(camp, bundle_instance, parent_created_by_ref, parent_timestamp)
                bundle_instance["objects"].append(camp20)
                report_instance["object_refs"].append(camp20["id"])
            else:
                report_instance["object_refs"].append(camp.idref)

    # coas
    if report.courses_of_action:
        for coa in report.courses_of_action:
            if coa.id_ is not None:
                coa20 = convert_course_of_action(coa, bundle_instance, parent_created_by_ref, parent_timestamp)
                bundle_instance["objects"].append(coa20)
                report_instance["object_refs"].append(coa20["id"])
            else:
                report_instance["object_refs"].append(coa.idref)

    # exploit-targets
    if report.exploit_targets:
        for et in report.exploit_targets:
            convert_exploit_target(et, bundle_instance, parent_created_by_ref, parent_timestamp)

    # incidents
    if get_option_value("incidents"):
        if report.incidents:
            for i in report.incidents:
                if i.id_ is not None:
                    i20 = convert_incident(i, bundle_instance, parent_created_by_ref, parent_timestamp)
                    bundle_instance["incidents"].append(i20)
                    report_instance["object_refs"].append(i20["id"])
                else:
                    report_instance["object_refs"].append(i.idref)

    # indicators
    if report.indicators:
        for i in report.indicators:
            if i.id_ is not None:
                i20 = convert_indicator(i, bundle_instance, parent_created_by_ref, parent_timestamp)
                bundle_instance["objects"].append(i20)
                report_instance["object_refs"].append(i20["id"])
            else:
                report_instance["object_refs"].append(i.idref)

    # observables
    if report.observables:
        for o_d in report.observables:
            if o_d.id_ is not None:
                o_d20 = convert_observed_data(o_d, bundle_instance, parent_created_by_ref, parent_timestamp)
                bundle_instance["observed_data"].append(o_d20)
                report_instance["object_refs"].append(o_d20["id"])
            else:
                report_instance["object_refs"].append(o_d.idref)

    # threat actors
    if report.threat_actors:
        for ta in report.threat_actors:
            if ta.id_ is not None:
                ta20 = convert_threat_actor(ta, bundle_instance, parent_created_by_ref, parent_timestamp)
                bundle_instance["objects"].append(ta20)
                report_instance["object_refs"].append(ta20["id"])
            else:
                report_instance["object_refs"].append(ta.idref)

    # ttps
    if report.ttps:
        for ttp in report.ttps:
            if ttp.id_:
                ttps20 = convert_ttp(ttp, bundle_instance, parent_created_by_ref, parent_timestamp)
                for ttp20 in ttps20:
                    if ttp20["type"] == "malware":
                        bundle_instance["objects"].append(ttp)
                    elif ttp20["type"] == "tool":
                        bundle_instance["objects"].append(ttp)
                    elif ttp20["type"] == "attack_pattern":
                        bundle_instance["objects"].append(ttp)
                    report_instance["object_refs"].append(ttp20["id"])
            else:
                report_instance["object_refs"].append(ttp.idref)


def convert_report(report, bundle_instance, parent_created_by_ref, parent_timestamp):
    report_instance = create_basic_object("report", report, parent_timestamp)
    process_description_and_short_description(report_instance, report.header)
    report_created_by_def = process_information_source(report.header.information_source, report_instance,
                                                       bundle_instance, parent_created_by_ref,
                                                       report_instance["created"])
    # process information source before any relationships
    add_string_property_to_description(report_instance, "intent", report.header.intents, True)
    if report.header.title is not None:
        report_instance["name"] = report.header.title
    convert_controlled_vocabs_to_open_vocabs(report_instance, "labels",
                                             report.header.intents, REPORT_LABELS_MAP, False)
    process_report_contents(report, bundle_instance, report_instance,
                            report_created_by_def, report_instance["created"])

    if report.related_reports is not None:
        # FIXME: related reports?
        info("Report Related_Reports in %s is not handled, yet.", 815, report_instance["id"])
    finish_basic_object(report.id_, report_instance, report.header)
    return report_instance


# threat actor

def add_motivations_to_threat_actor(sdo_instance, motivations):
    info("Using first Threat Actor motivation as primary_motivation. If more, as secondary_motivation", 719)

    if motivations[0].value is not None:
        sdo_instance["primary_motivation"] = map_vocabs_to_label(text_type(motivations[0].value), ATTACK_MOTIVATION_MAP)

    values = []

    if len(motivations) > 1:
        for m in motivations[1:]:
            if m.value is not None:
                values.append(m.value)

        if values:
            convert_controlled_vocabs_to_open_vocabs(sdo_instance, "secondary_motivations", values, ATTACK_MOTIVATION_MAP, False)


def convert_threat_actor(threat_actor, bundle_instance, parent_created_by_ref, parent_timestamp):
    threat_actor_instance = create_basic_object("threat-actor", threat_actor, parent_timestamp)
    process_description_and_short_description(threat_actor_instance, threat_actor)
    threat_actor_created_by_ref = \
        process_information_source(threat_actor.information_source, threat_actor_instance, bundle_instance,
                                   parent_created_by_ref, threat_actor_instance["created"])
    # process information source before any relationships
    if threat_actor.identity is not None:
        if threat_actor.identity.id_:
            info("Threat Actor identity %s being used as basis of attributed-to relationship", 701, threat_actor.identity.id_)
        handle_relationship_to_objs([threat_actor.identity], threat_actor_instance["id"], bundle_instance,
                                    "attributed-to", threat_actor.timestamp, threat_actor_created_by_ref)
    if threat_actor.title is not None:
        info("Threat Actor %s title is used for name property", 717, threat_actor.id_)
        threat_actor_instance["name"] = threat_actor.title
    convert_controlled_vocabs_to_open_vocabs(threat_actor_instance, "labels", threat_actor.types,
                                             THREAT_ACTOR_LABEL_MAP, False)
    add_multiple_statement_types_to_description(threat_actor_instance, threat_actor.intended_effects, "intended_effect")
    add_multiple_statement_types_to_description(threat_actor_instance, threat_actor.planning_and_operational_supports,
                                                "planning_and_operational_support")
    if threat_actor.confidence:
        add_confidence_property_to_description(threat_actor_instance, threat_actor.confidence)

    if threat_actor.motivations:
        add_motivations_to_threat_actor(threat_actor_instance, threat_actor.motivations)

    convert_controlled_vocabs_to_open_vocabs(threat_actor_instance, "sophistication", threat_actor.sophistications,
                                             THREAT_ACTOR_SOPHISTICATION_MAP, True)

    # handle relationships
    if threat_actor.observed_ttps is not None:
        handle_relationship_to_refs(threat_actor.observed_ttps, threat_actor_instance["id"], bundle_instance,
                                    "uses", threat_actor_instance["created"], threat_actor_created_by_ref)
    if threat_actor.associated_campaigns is not None:
        handle_relationship_from_refs(threat_actor.associated_campaigns, threat_actor_instance["id"], bundle_instance,
                                      "attributed-to", threat_actor_instance["created"], threat_actor_created_by_ref)
    if threat_actor.associated_actors:
        warn("All associated actors relationships of %s are assumed to not represent STIX 1.2 versioning", 710, threat_actor.id_)
        handle_relationship_to_refs(threat_actor.associated_actors, threat_actor_instance["id"], bundle_instance,
                                    "related-to", threat_actor_instance["created"], threat_actor_created_by_ref)

    finish_basic_object(threat_actor.id_, threat_actor_instance, threat_actor)
    return threat_actor_instance


# TTPs


def process_ttp_properties(sdo_instance, ttp, bundle_instance, parent_created_by_ref, kill_chains_in_sdo=True):
    process_description_and_short_description(sdo_instance, ttp, True)
    add_multiple_statement_types_to_description(sdo_instance, ttp.intended_effects, "intended_effect")
    if hasattr(ttp, "title"):
        if "name" not in sdo_instance or sdo_instance["name"] is None:
            sdo_instance["name"] = ttp.title
        else:
            add_string_property_to_description(sdo_instance, "title", ttp.title, False)
    if ttp.exploit_targets is not None:
        handle_relationship_to_refs(ttp.exploit_targets, sdo_instance["id"], bundle_instance,
                                    "targets", )
    # only populate kill chain phases if that is a property of the sdo_instance type, as indicated by kill_chains_in_sdo
    if kill_chains_in_sdo and hasattr(ttp, "kill_chain_phases"):
        convert_kill_chains(ttp.kill_chain_phases, sdo_instance)
    ttp_created_by_ref = process_information_source(ttp.information_source, sdo_instance,
                                                    bundle_instance, parent_created_by_ref,
                                                    sdo_instance["created"])
    if ttp.related_ttps:
        warn("All associated indicators relationships of %s are assumed to not represent STIX 1.2 versioning", 710, ttp.id_)
        handle_relationship_to_refs(ttp.related_ttps, sdo_instance["id"], bundle_instance,
                                    "related-to", sdo_instance["created"], ttp_created_by_ref)
    if hasattr(ttp, "related_packages") and ttp.related_packages is not None:
        for p in ttp.related_packages:
            warn("Related_Packages type in %s not supported in STIX 2.0", 402, ttp.id_)


def convert_attack_pattern(ap, ttp, bundle_instance, ttp_id_used, parent_created_by_ref, parent_timestamp):
    attack_Pattern_instance = create_basic_object("attack-pattern", ap, parent_timestamp, ttp.id_, not ttp_id_used)
    if ap.title is not None:
        attack_Pattern_instance["name"] = ap.title
    process_description_and_short_description(attack_Pattern_instance, ap)
    if ap.capec_id is not None:
        attack_Pattern_instance["external_references"] = [{"source_name": "capec", "external_id": ap.capec_id}]
    process_ttp_properties(attack_Pattern_instance, ttp, bundle_instance, parent_created_by_ref)
    finish_basic_object(ttp.id_, attack_Pattern_instance, ap)
    return attack_Pattern_instance


def convert_malware_instance(mal, ttp, bundle_instance, ttp_id_used, parent_created_by_ref, parent_timestamp):
    malware_instance_instance = create_basic_object("malware", mal, parent_timestamp, ttp.id_, not ttp_id_used)
    # TODO: names?
    if mal.title is not None:
        malware_instance_instance["name"] = mal.title
    process_description_and_short_description(malware_instance_instance, mal)
    convert_controlled_vocabs_to_open_vocabs(malware_instance_instance, "labels", mal.types, MALWARE_LABELS_MAP, False)
    if mal.names is not None:
        for n in mal.names:
            if "name" not in malware_instance_instance:
                malware_instance_instance["name"] = text_type(n)
            else:
                # TODO: add to description?
                warn("Only one name for malware is allowed for %s in STIX 2.0 - used first one", 508, malware_instance_instance["id"])
    # TODO: warning for MAEC content
    process_ttp_properties(malware_instance_instance, ttp, bundle_instance, parent_created_by_ref)
    finish_basic_object(ttp.id_, malware_instance_instance, mal)
    return malware_instance_instance


def convert_behavior(behavior, ttp, bundle_instance, parent_created_by_ref, parent_timestamp):
    resources_generated = []
    first_one = True
    if behavior.attack_patterns is not None:
        for ap in behavior.attack_patterns:
            new_obj = convert_attack_pattern(ap, ttp, bundle_instance, first_one, parent_created_by_ref, parent_timestamp)
            bundle_instance["objects"].append(new_obj)
            resources_generated.append(new_obj)
            first_one = False
    if behavior.malware_instances is not None:
        for mal in behavior.malware_instances:
            new_obj = convert_malware_instance(mal, ttp, bundle_instance, first_one, parent_created_by_ref, parent_timestamp)
            bundle_instance["objects"].append(new_obj)
            resources_generated.append(new_obj)
            first_one = False
    if behavior.exploits is not None:
        for e in behavior.exploits:
            warn("TTP/Behavior/Exploits/Exploit in %s not supported in STIX 2.0", 408, ttp.id_)
    return resources_generated


def convert_tool(tool, ttp, bundle_instance, first_one, parent_created_by_ref, parent_timestamp):
    tool_instance = create_basic_object("tool", tool, parent_timestamp, ttp.id_, not first_one)
    if tool.name is not None:
        tool_instance["name"] = tool.name
    process_description_and_short_description(tool_instance, tool)
    add_string_property_to_description(tool_instance, "vendor", tool.vendor)
    add_string_property_to_description(tool_instance, "service_pack", tool.service_pack)
    # TODO: add tool_specific_data to descriptor <-- Not Implemented!

    if tool.tool_hashes is not None:
        # FIXME: add tool_hashes to descriptor
        info("Tool Tool_Hashes in %s is not handled, yet.", 815, tool_instance["id"])

    # TODO: add tool_configuration to descriptor <-- Not Implemented!
    # TODO: add execution_environment to descriptor <-- Not Implemented!
    # TODO: add errors to descriptor <-- Not Implemented!
    # TODO: add compensation_model to descriptor <-- Not Implemented!
    add_string_property_to_description(tool_instance, "title", tool.title)
    convert_controlled_vocabs_to_open_vocabs(tool_instance, "labels", tool.type_, TOOL_LABELS_MAP, False)
    tool_instance["tool_version"] = tool.version
    process_ttp_properties(tool_instance, ttp, bundle_instance, parent_created_by_ref)
    finish_basic_object(ttp.id_, tool_instance, tool)
    return tool_instance


def convert_infrastructure(infra, ttp, bundle_instance, first_one, parent_created_by_ref, parent_timestamp):
    infrastructure_instance = create_basic_object("infrastructure", infra, parent_timestamp, not first_one)
    if infra.title is not None:
        infrastructure_instance["name"] = infra.title
    process_description_and_short_description(infrastructure_instance, infra)
    convert_controlled_vocabs_to_open_vocabs(infrastructure_instance, "labels", infra.types, {}, False)
    info("No 'first_seen' data on %s - using timestamp", 904, infra.id_ if infra.id_ else ttp.id_)
    infrastructure_instance["first_seen"] = convert_timestamp(infra, infrastructure_instance["created"])

    if infra.observable_characterization is not None:
        # FIXME: add observable_characterizations
        info("Infrastructure Observable_Characterization in %s is not handled, yet.", 815, infrastructure_instance["id"])
    process_ttp_properties(infrastructure_instance, ttp, bundle_instance, parent_created_by_ref)
    finish_basic_object(ttp.id_, infrastructure_instance, infra)
    return infrastructure_instance


def convert_resources(resources, ttp, bundle_instance, parent_created_by_ref, parent_timestamp):
    resources_generated = []
    first_one = True
    if resources.tools is not None:
        for t in resources.tools:
            new_obj = convert_tool(t, ttp, bundle_instance, first_one, parent_created_by_ref, parent_timestamp)
            bundle_instance["objects"].append(new_obj)
            resources_generated.append(new_obj)
            first_one = False
    if resources.infrastructure is not None:
        if get_option_value("infrastructure"):
            new_obj = convert_infrastructure(resources.infrastructure, ttp, bundle_instance,
                                             first_one, parent_created_by_ref, parent_timestamp)
            bundle_instance["objects"].append(new_obj)
            resources_generated.append(new_obj)
        else:
            warn("Infrastructure in %s not part of STIX 2.0", 409, ttp.id_ or "")
    return resources_generated


def convert_identity_for_victim_target(identity, ttp, bundle_instance, ttp_generated, parent_timestamp):
    identity_instance = convert_identity(identity, bundle_instance, parent_timestamp,
                                         ttp.id_ if not ttp_generated else None)
    bundle_instance["objects"].append(identity_instance)
    process_ttp_properties(identity_instance, ttp, bundle_instance, None, False)
    finish_basic_object(ttp.id_, identity_instance, identity)
    return identity_instance


def convert_victim_targeting(victim_targeting, ttp, bundle_instance, ttp_generated, parent_created_by_ref, parent_timestamp):
    if victim_targeting.targeted_systems:
        for v in victim_targeting.targeted_systems:
            warn("Targeted systems on %s are not a victim target in STIX 2.0", 410, ttp.id_)
    if victim_targeting.targeted_information:
        for v in victim_targeting.targeted_information:
            warn("Targeted information on %s is not a victim target in STIX 2.0", 411, ttp.id_)
    if hasattr(victim_targeting, "technical_details") and victim_targeting.targeted_technical_details is not None:
        for v in victim_targeting.targeted_technical_details:
            warn("Targeted technical details on %s are not a victim target in STIX 2.0", 412, ttp.id_)
    if victim_targeting.identity:
        identity_instance = convert_identity_for_victim_target(victim_targeting.identity, ttp, bundle_instance,
                                                               ttp_generated, parent_timestamp)
        if identity_instance:
            warn("%s generated an identity associated with a victim", 713, ttp.id_)
            if ttp_generated:
                bundle_instance["relationships"].append(
                    create_relationship(ttp.id_, identity_instance["id"],
                                        "targets", None, parent_timestamp, parent_created_by_ref))
                # the relationship has been created, so its not necessary to propagate it up
                return None
            else:
                return identity_instance
    # nothing generated
    return None


def convert_ttp(ttp, bundle_instance, parent_created_by_ref, parent_timestamp):
    if hasattr(ttp, "created") and ttp.timestamp:
        parent_timestamp = ttp.timestamp
    generated_objs = []
    if ttp.behavior is not None:
        generated_objs.extend(convert_behavior(ttp.behavior, ttp, bundle_instance, parent_created_by_ref, parent_timestamp))
    if ttp.resources is not None:
        generated_objs.extend(convert_resources(ttp.resources, ttp, bundle_instance, parent_created_by_ref, parent_timestamp))
    if hasattr(ttp, "kill_chain_phases") and ttp.kill_chain_phases is not None:
        for phase in ttp.kill_chain_phases:
            warn("Kill Chains type in %s not supported in STIX 2.0", 413, ttp.id_)
    if ttp.victim_targeting is not None:
        victim_target = convert_victim_targeting(ttp.victim_targeting, ttp, bundle_instance,
                                                 generated_objs, parent_created_by_ref,
                                                 parent_timestamp)
        if not victim_target:
            warn("Victim Target in %s did not generate any STIX 2.0 object", 414, ttp.id_)
        else:
            return generated_objs.append(victim_target)
    # victims weren't involved, check existing list
    if not generated_objs and ttp.id_ is not None:
        warn("TTP %s did not generate any STIX 2.0 object", 415, ttp.id_)
    return generated_objs


# package


def handle_embedded_object(obj, bundle_instance, parent_created_by_ref, parent_timestamp):
    new20 = None
    new20s = None
    # campaigns
    if isinstance(obj, Campaign):
        new20 = convert_campaign(obj, bundle_instance, parent_created_by_ref, parent_timestamp)
        bundle_instance["objects"].append(new20)
    # coas
    elif isinstance(obj, CourseOfAction):
        new20 = convert_course_of_action(obj, bundle_instance, parent_created_by_ref, parent_timestamp)
        bundle_instance["objects"].append(new20)
    # exploit-targets
    elif isinstance(obj, ExploitTarget):
        new20s = convert_exploit_target(obj, bundle_instance, parent_created_by_ref, parent_timestamp)
    # identities
    elif isinstance(obj, Identity) or isinstance(obj, CIQIdentity3_0Instance):
        new20 = convert_identity(obj, bundle_instance)
        bundle_instance["objects"].append(new20)
    # incidents
    elif get_option_value("incidents") and isinstance(obj, Incident):
        new20 = convert_incident(obj, bundle_instance, parent_created_by_ref, parent_timestamp)
        bundle_instance["objects"].append(new20)
    # indicators
    elif isinstance(obj, Indicator):
        new20 = convert_indicator(obj, bundle_instance, parent_created_by_ref, parent_timestamp)
        bundle_instance["indicators"].append(new20)
    # observables
    elif isinstance(obj, Observable):
        new20 = convert_observed_data(obj, bundle_instance, parent_created_by_ref, parent_timestamp)
        bundle_instance["observed_data"].append(new20)
    # reports
    elif stix.__version__ >= "1.2.0.0" and isinstance(obj, Report):
        new20 = convert_report(obj, bundle_instance, parent_created_by_ref, parent_timestamp)
        bundle_instance["reports"].append(new20)
    # threat actors
    elif isinstance(obj, ThreatActor):
        new20 = convert_threat_actor(obj, bundle_instance, parent_created_by_ref, parent_timestamp)
        bundle_instance["objects"].append(new20)
    # ttps
    elif isinstance(obj, TTP):
        new20s = convert_ttp(obj, bundle_instance, parent_created_by_ref, parent_timestamp)
    if new20:
        return [new20]
    elif new20s:
        return new20s
    else:
        warn("No STIX 2.0 object generated from embedded object %s", 416, identifying_info(obj))
        return []


def initialize_bundle_lists(bundle_instance):
    bundle_instance["relationships"] = []
    bundle_instance["indicators"] = []
    bundle_instance["reports"] = []
    bundle_instance["observed_data"] = []
    bundle_instance["objects"] = []


def finalize_bundle(bundle_instance):
    if KILL_CHAINS_PHASES != {}:
        for ind20 in bundle_instance["indicators"]:
            if "kill_chain_phases" in ind20:
                fixed_kill_chain_phases = []
                for kcp in ind20["kill_chain_phases"]:
                    if isinstance(kcp, str):
                        # noinspection PyBroadException
                        try:
                            kill_chain_phase_in_20 = KILL_CHAINS_PHASES[kcp]
                            fixed_kill_chain_phases.append(kill_chain_phase_in_20)
                        except KeyError:
                            error("Dangling kill chain phase id in indicator %s", 607, ind20["id"])
                    else:
                        fixed_kill_chain_phases.append(kcp)
                ind20["kill_chain_phases"] = fixed_kill_chain_phases
    # ttps

    fix_relationships(bundle_instance["relationships"], bundle_instance)

    if stix.__version__ >= "1.2.0.0":
        add_relationships_to_reports(bundle_instance)

    # source and target_ref are taken care in fix_relationships(...)
    _TO_MAP = ("id", "idref", "created_by_ref", "external_references",
               "marking_ref", "object_marking_refs", "object_refs",
               "sighting_of_ref", "observed_data_refs", "where_sighted_refs")

    _LOOK_UP = ("", u"", [], None, dict())

    to_remove = []

    if "indicators" in bundle_instance:
        interatively_resolve_placeholder_refs()
        for ind in bundle_instance["indicators"]:
            if "pattern" in ind:
                final_pattern = fix_pattern(ind["pattern"])
                if final_pattern:
                    if final_pattern.contains_placeholder():
                        warn("At least one PLACEHOLDER idref was not resolved in %s", 205, ind["id"])
                    if final_pattern.contains_unconverted_term():
                        warn("At least one observable could not be converted in %s", 206, ind["id"])
                    if isinstance(final_pattern, ComparisonExpression):
                        ind["pattern"] = "[" + final_pattern.to_string() + "]"
                    else:
                        ind["pattern"] = final_pattern.partition_according_to_object_path().to_string()

    bundle_instance["objects"].extend(bundle_instance["indicators"])
    bundle_instance["indicators"] = []
    bundle_instance["objects"].extend(bundle_instance["relationships"])
    bundle_instance["relationships"] = []
    bundle_instance["objects"].extend(bundle_instance["observed_data"])
    bundle_instance["observed_data"] = []
    bundle_instance["objects"].extend(bundle_instance["reports"])
    bundle_instance["reports"] = []

    for entry in iterpath(bundle_instance):
        path, value = entry
        last_field = path[-1]
        iter_field = path[-2] if len(path) >= 2 else ""

        if value in _LOOK_UP:
            to_remove.append(list(path))

        if isinstance(value, (list, dict)):
            continue

        if last_field in _TO_MAP or iter_field in _TO_MAP:
            if reference_needs_fixing(value) and exists_id_key(value):
                stix20_id = get_id_value(value)

                if stix20_id[0] is None:
                    warn("1.X ID: %s was not mapped to STIX 2.0 ID", 603, value)
                    continue

                operation_on_path(bundle_instance, path, stix20_id[0])
                info("Found STIX 1.X ID: %s replaced by %s", 702, value, stix20_id[0])
            elif reference_needs_fixing(value) and not exists_id_key(value):
                warn("1.X ID: %s was not mapped to STIX 2.0 ID", 603, value)

    for item in to_remove:
        operation_on_path(bundle_instance, item, "", op=2)

    if "objects" in bundle_instance:
        remove_pattern_objects(bundle_instance)
    else:
        error("EMPTY BUNDLE -- No objects created from 1.x input document!", 208)


def get_identity_from_package(information_source, bundle_instance, parent_timestamp):
    if information_source:
        if information_source.identity is not None:
            return get_identity_ref(information_source.identity, bundle_instance, parent_timestamp)
    return None


def convert_package(stixPackage, package_created_by_ref=None, default_timestamp=None):
    bundle_instance = {"type": "bundle"}
    bundle_instance["id"] = generate_stix20_id("bundle", stixPackage.id_)
    bundle_instance["spec_version"] = "2.0"
    initialize_bundle_lists(bundle_instance)

    if default_timestamp:
        parent_timestamp = datetime.strptime(default_timestamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    elif hasattr(stixPackage, "created"):
        parent_timestamp = stixPackage.timestamp
    else:
        parent_timestamp = None

    # created_by_idref from the command line is used instead of the one from the package, if given
    if not package_created_by_ref and hasattr(stixPackage.stix_header, "information_source"):
        package_created_by_ref = get_identity_from_package(stixPackage.stix_header.information_source,
                                                           bundle_instance, parent_timestamp)

    # TODO: other header stuff

    # do observables first, especially before indicators!

    # kill chains
    if stixPackage.ttps and stixPackage.ttps.kill_chains:
        for kc in stixPackage.ttps.kill_chains:
            process_kill_chain(kc)

    # observables
    if stixPackage.observables is not None:
        for o_d in stixPackage.observables:
            o_d20 = convert_observed_data(o_d, bundle_instance, package_created_by_ref, parent_timestamp)
            bundle_instance["observed_data"].append(o_d20)

    # campaigns
    if stixPackage.campaigns:
        for camp in stixPackage.campaigns:
            camp20 = convert_campaign(camp, bundle_instance, package_created_by_ref, parent_timestamp)
            bundle_instance["objects"].append(camp20)

    # coas
    if stixPackage.courses_of_action:
        for coa in stixPackage.courses_of_action:
            coa20 = convert_course_of_action(coa, bundle_instance, package_created_by_ref, parent_timestamp)
            bundle_instance["objects"].append(coa20)

    # exploit-targets
    if stixPackage.exploit_targets:
        for et in stixPackage.exploit_targets:
            convert_exploit_target(et, bundle_instance, package_created_by_ref, parent_timestamp)

    # incidents
    if get_option_value("incidents"):
        if stixPackage.incidents:
            for i in stixPackage.incidents:
                i20 = convert_incident(i, bundle_instance, package_created_by_ref, parent_timestamp)
                bundle_instance["objects"].append(i20)

    # indicators
    if stixPackage.indicators:
        for i in stixPackage.indicators:
            i20 = convert_indicator(i, bundle_instance, package_created_by_ref, parent_timestamp)
            bundle_instance["indicators"].append(i20)

    # reports
    if stix.__version__ >= "1.2.0.0" and stixPackage.reports:
        for report in stixPackage.reports:
            report20 = convert_report(report, bundle_instance, package_created_by_ref, parent_timestamp)
            bundle_instance["reports"].append(report20)

    # threat actors
    if stixPackage.threat_actors:
        for ta in stixPackage.threat_actors:
            ta20 = convert_threat_actor(ta, bundle_instance, package_created_by_ref, parent_timestamp)
            bundle_instance["objects"].append(ta20)

    # ttps
    if stixPackage.ttps:
        for ttp in stixPackage.ttps:
            convert_ttp(ttp, bundle_instance, package_created_by_ref, parent_timestamp)

    finalize_bundle(bundle_instance)
    return bundle_instance
