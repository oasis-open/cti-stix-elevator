# Standard Library
from datetime import datetime

# external
from cybox.core import Observable
from lxml import etree
import pycountry
from six import ensure_text, string_types, text_type
import stix
from stix.campaign import Campaign
from stix.coa import CourseOfAction
from stix.common.identity import Identity
from stix.common.kill_chains import KillChainPhase, KillChainPhaseReference
from stix.data_marking import MarkingSpecification, MarkingStructure
from stix.exploit_target import ExploitTarget
from stix.extensions.identity.ciq_identity_3_0 import CIQIdentity3_0Instance
from stix.extensions.malware.maec_4_1_malware import MAECInstance
import stix.extensions.marking.ais
from stix.extensions.marking.ais import AISMarkingStructure
from stix.extensions.marking.simple_marking import SimpleMarkingStructure
from stix.extensions.marking.terms_of_use_marking import (
    TermsOfUseMarkingStructure
)
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.extensions.test_mechanism.open_ioc_2010_test_mechanism import (
    OpenIOCTestMechanism
)
from stix.extensions.test_mechanism.snort_test_mechanism import (
    SnortTestMechanism
)
from stix.extensions.test_mechanism.yara_test_mechanism import (
    YaraTestMechanism
)
from stix.incident import Incident
from stix.indicator import Indicator
from stix.threat_actor import ThreatActor
from stix.ttp import TTP
from stixmarx import navigator

# internal
from stix2elevator.confidence import convert_confidence
from stix2elevator.convert_cybox import (
    convert_cybox_object20, convert_cybox_object21, embedded_property_ref_name,
    fix_cybox_relationships, fix_sco_embedded_refs,
    resolve_object_references20, resolve_object_references21
)
from stix2elevator.convert_pattern import (
    ComparisonExpressionForElevator, CompoundObservationExpressionForElevator,
    ParentheticalExpressionForElevator, UnconvertedTerm,
    add_to_observable_mappings, add_to_pattern_cache,
    convert_indicator_to_pattern, convert_observable_list_to_pattern,
    convert_observable_to_pattern, create_boolean_expression, fix_pattern,
    get_obs_from_mapping, id_in_observable_mappings,
    interatively_resolve_placeholder_refs, remove_pattern_objects
)
from stix2elevator.ids import (
    add_id_of_obs_in_characterizations, add_id_value, exists_id_key,
    exists_ids_with_no_1x_object, generate_stix2x_id, get_id_value,
    get_id_values, get_type_from_id, is_stix1x_id, record_ids
)
from stix2elevator.missing_policy import (
    convert_to_custom_name, handle_missing_confidence_property,
    handle_missing_statement_properties, handle_missing_string_property,
    handle_missing_tool_property, handle_multiple_missing_statement_properties
)
from stix2elevator.options import error, get_option_value, info, warn
from stix2elevator.utils import (
    add_marking_map_entry, check_map_1x_markings_to_2x,
    convert_controlled_vocabs_to_open_vocabs, convert_timestamp_of_stix_object,
    convert_timestamp_to_string, identifying_info, iterpath,
    map_1x_markings_to_2x, map_vocabs_to_label, operation_on_path,
    strftime_with_appropriate_fractional_seconds
)
from stix2elevator.vocab_mappings import (
    ATTACK_MOTIVATION_MAP, COA_LABEL_MAP, INCIDENT_LABEL_MAP,
    INDICATOR_LABEL_MAP, INFRASTRUCTURE_LABELS_MAP, MALWARE_LABELS_MAP,
    REPORT_LABELS_MAP, SECTORS_MAP, THREAT_ACTOR_LABEL_MAP,
    THREAT_ACTOR_SOPHISTICATION_MAP, TOOL_LABELS_MAP
)

if stix.__version__ >= "1.2.0.0":  # isort:skip
    from stix.report import Report  # isort:skip

# collect kill chains
_KILL_CHAINS_PHASES = {}


def clear_kill_chains_phases_mapping():
    global _KILL_CHAINS_PHASES
    _KILL_CHAINS_PHASES = {}


def process_kill_chain(kc):
    for kcp in kc.kill_chain_phases:
        # Use object itself as key.
        if kcp.phase_id:
            _KILL_CHAINS_PHASES[kcp.phase_id] = {"kill_chain_name": kc.name, "phase_name": kcp.name}
        else:
            _KILL_CHAINS_PHASES[kcp] = {"kill_chain_name": kc.name, "phase_name": kcp.name}


# collect locations

_LOCATIONS = {}


def clear_location_objects():
    global _LOCATIONS
    _LOCATIONS = {}


def exists_location_object(key):
    return key in _LOCATIONS


def get_location_object(key):
    if exists_location_object(key):
        return _LOCATIONS[key]
    else:
        return []


def add_location_object(key, location_object):
    global _LOCATIONS
    if not exists_location_object(key):
        _LOCATIONS[key] = location_object
#
# identities
#


# def get_simple_name_from_identity(identity, bundle_instance, sdo_instance):
#     if isinstance(identity, CIQIdentity3_0Instance):
#         handle_relationship_to_refs([identity], sdo_instance["id"], bundle_instance, "attributed-to")
#     else:
#         return identity.name


def get_identity_ref(identity, env, temp_marking_id=None, from_package=False):
    if identity.idref is not None:
        # fix reference later
        return identity.idref
    else:
        ident20 = convert_identity(identity, env, temp_marking_id=temp_marking_id, from_package=from_package)
        env.bundle_instance["objects"].append(ident20)
        return ident20["id"]


def process_information_source(information_source, so, env, temp_marking_id=None):
    if information_source:
        if information_source.identity is not None:
            so["created_by_ref"] = get_identity_ref(information_source.identity, env, temp_marking_id)
        else:
            so["created_by_ref"] = env.created_by_ref

        if so == env.bundle_instance:
            warn("Information Source on %s is not representable in STIX 2.x", 401, so["id"])
        else:
            if information_source.description:
                process_description_and_short_description(so, information_source)
            if information_source.references:
                for ref in information_source.references:
                    so["external_references"].append({"source_name": "unknown", "url": ref})
            if information_source.roles:
                handle_missing_string_property(so, "information_source_role", information_source.roles, True)
            if information_source.tools:
                for tool in information_source.tools:
                    handle_missing_tool_property(so, tool)
    else:
        so["created_by_ref"] = env.created_by_ref
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
            if parent_info and so["description"]:
                so["description"] += "\nPARENT_DESCRIPTION: \n" + description_as_text
            else:
                so["description"] += description_as_text

    # could be short_description or description (in STIX 1.1.1)
    # seems like in STIX 2.x - description and descriptionS are both populated with the same content
    elif hasattr(entity, "description") and entity.description is not None:
        so["description"] += text_type(entity.description.value)
    if hasattr(entity, "short_description") and entity.short_description is not None:
        short_description_as_text = text_type(entity.short_description)
        if short_description_as_text:
            warn("The Short_Description property in %s is not supported in STIX 2.x.", 0, so["id"])
            if get_option_value("missing_policy") == "add-to-description":
                warn("The text was appended to the description property of %s", 301, so["id"])
                if parent_info and so["description"]:
                    so["description"] += "\nPARENT_SHORT_DESCRIPTION: \n" + short_description_as_text
                else:
                    so["description"] += short_description_as_text
            elif get_option_value("missing_policy") == "use_custom_properties":
                warn("Used custom property for short_description of %s", 308, so["id"])
                so[convert_to_custom_name("short_description")] = short_description_as_text
            else:
                warn("Missing property 'short_description' of %s is ignored", 307, so["id"])


def create_basic_object(stix2x_type, stix1x_obj, env, parent_id=None, id_used=False):
    instance = {"type": stix2x_type}
    if get_option_value("spec_version") == "2.1":
        instance["spec_version"] = "2.1"
    instance["id"] = generate_stix2x_id(stix2x_type, stix1x_obj.id_ if (stix1x_obj and
                                                                        hasattr(stix1x_obj, "id_") and
                                                                        stix1x_obj.id_) else parent_id, id_used)
    if stix1x_obj:
        timestamp = convert_timestamp_of_stix_object(stix1x_obj, env.timestamp, True)
    else:
        timestamp = strftime_with_appropriate_fractional_seconds(env.timestamp, True)
    instance["created"] = timestamp
    # may need to revisit if we handle 1.x versioning.
    instance["modified"] = timestamp
    instance["description"] = ""
    instance["external_references"] = []
    return instance


def convert_marking_specification(marking_specification, env):
    return_obj = []

    if marking_specification.marking_structures is not None:
        marking_structures = marking_specification.marking_structures
        for marking_structure in marking_structures:
            if marking_structure.idref or marking_structure.__class__.__name__ == "MarkingStructure":
                if not check_map_1x_markings_to_2x(marking_structure):
                    # Don't print message multiple times if idref has been resolved.
                    warn("Could not resolve Marking Structure. Skipped object %s", 425, identifying_info(marking_structure))
                # Skip empty markings or ones that use the idref approach.
                continue

            marking_definition_instance = create_basic_object("marking-definition", marking_structure, env)

            if isinstance(marking_structure, TLPMarkingStructure):
                if marking_structure.color is not None:
                    color = text_type(marking_structure.color).lower()
                    if color == "white":
                        marking_definition_instance["id"] = "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"
                    elif color == "green":
                        marking_definition_instance["id"] = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
                    elif color == "amber":
                        marking_definition_instance["id"] = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"
                    elif color == "red":
                        marking_definition_instance["id"] = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"

            process_information_source(marking_specification.information_source,
                                       marking_definition_instance,
                                       env,
                                       temp_marking_id=marking_definition_instance["id"])

            if "modified" in marking_definition_instance:
                del marking_definition_instance["modified"]

            if isinstance(marking_structure, TLPMarkingStructure):
                marking_definition_instance["definition_type"] = "tlp"
                marking_definition_instance["created"] = "2017-01-20T00:00:00.000Z"
                definition = {}
                if marking_structure.color is not None:
                    definition["tlp"] = text_type(marking_structure.color).lower()
                marking_definition_instance["definition"] = definition
            elif isinstance(marking_structure, TermsOfUseMarkingStructure):
                marking_definition_instance["definition_type"] = "statement"
                definition = {}
                if marking_structure.terms_of_use is not None:
                    definition["statement"] = text_type(marking_structure.terms_of_use)
                marking_definition_instance["definition"] = definition
            elif isinstance(marking_structure, SimpleMarkingStructure):
                marking_definition_instance["definition_type"] = "statement"
                definition = {}
                if marking_structure.statement is not None:
                    definition["statement"] = text_type(marking_structure.statement)
                marking_definition_instance["definition"] = definition
            elif isinstance(marking_structure, AISMarkingStructure):
                marking_definition_instance["definition_type"] = "ais"
                definition = {}
                if marking_structure.is_proprietary is not None:
                    definition["is_proprietary"] = "true"
                    if (marking_structure.is_proprietary.ais_consent is not None and
                            marking_structure.is_proprietary.ais_consent.consent is not None):
                        definition["consent"] = text_type(marking_structure.is_proprietary.ais_consent.consent).lower()
                    if (marking_structure.is_proprietary.tlp_marking is not None and
                            marking_structure.is_proprietary.tlp_marking.color is not None):
                        definition["tlp"] = text_type(marking_structure.is_proprietary.tlp_marking.color).lower()
                    if marking_structure.is_proprietary.cisa_proprietary is not None:
                        definition["is_cisa_proprietary"] = text_type(marking_structure.is_proprietary.cisa_proprietary).lower()
                elif marking_structure.not_proprietary is not None:
                    definition["is_proprietary"] = "false"
                    if (marking_structure.not_proprietary.ais_consent is not None and
                            marking_structure.not_proprietary.ais_consent.consent is not None):
                        definition["consent"] = text_type(marking_structure.not_proprietary.ais_consent.consent).lower()
                    if (marking_structure.not_proprietary.tlp_marking is not None and
                            marking_structure.not_proprietary.tlp_marking.color is not None):
                        definition["tlp"] = text_type(marking_structure.not_proprietary.tlp_marking.color).lower()
                    if marking_structure.not_proprietary.cisa_proprietary is not None:
                        definition["is_cisa_proprietary"] = text_type(marking_structure.not_proprietary.cisa_proprietary).lower()
                marking_definition_instance["definition"] = definition
            else:
                if marking_structure.__class__.__name__ in get_option_value("markings_allowed"):
                    warn("Could not resolve Marking Structure %s", 425, identifying_info(marking_structure))
                else:
                    error("Could not resolve Marking Structure %s", 425, identifying_info(marking_structure))
                    raise NameError("Could not resolve Marking Structure %s" % identifying_info(marking_structure))

            if "definition_type" in marking_definition_instance:
                val = add_marking_map_entry(marking_structure, marking_definition_instance["id"])
                info("Created Marking Structure for %s", 212, identifying_info(marking_structure))
                if val is not None and not isinstance(val, MarkingStructure):
                    info("Found same marking structure %s, using %s", 625, identifying_info(marking_specification), val)
                else:
                    finish_basic_object(marking_specification.id_, marking_definition_instance, env, marking_structure)
                    return_obj.append(marking_definition_instance)

    return return_obj


def finish_basic_object(old_id, instance, env, stix1x_obj, temp_marking_id=None):
    if old_id is not None:
        record_ids(old_id, instance["id"])
    if hasattr(stix1x_obj, "related_packages") and stix1x_obj.related_packages is not None:
        for p in stix1x_obj.related_packages:
            warn("Related_Packages type in %s not supported in STIX 2.x", 402, stix1x_obj.id_)

    # Attach markings to SDO if present.
    container = get_option_value("marking_container")
    marking_specifications = container.get_markings(stix1x_obj)
    object_marking_refs = []
    for marking_specification in marking_specifications:
        for marking_structure in marking_specification.marking_structures:
            stix2x_marking = map_1x_markings_to_2x(marking_structure)
            if (not isinstance(stix2x_marking, MarkingStructure) and
                    instance["id"] != stix2x_marking and
                    stix2x_marking not in object_marking_refs):
                object_marking_refs.append(stix2x_marking)
            elif temp_marking_id:
                object_marking_refs.append(temp_marking_id)
            elif not check_map_1x_markings_to_2x(marking_structure):
                stix20_markings = convert_marking_specification(marking_specification, env)
                env.bundle_instance["objects"].extend(stix20_markings)
                for m in stix20_markings:
                    if instance["id"] != m["id"] and m["id"] not in object_marking_refs:
                        object_marking_refs.append(m["id"])

    if object_marking_refs:
        instance["object_marking_refs"] = object_marking_refs


#
# handle gaps
#


def handle_free_text_lines(sdo_instance, free_text_lines):
    if get_option_value("missing_policy") == "ignore":
        warn("Missing property 'free_text_lines' of %s is ignored", 307, sdo_instance["id"])
    else:
        lines = ""
        for line in free_text_lines:
            lines += line.value
        if get_option_value("missing_policy") == "add-to-description":
            sdo_instance["description"] = lines
            warn("Appended free text lines to description of %s", 302, sdo_instance["id"])
        else:
            warn("Used custom property for free_text_lines of %s", 308, sdo_instance["id"])
            sdo_instance[convert_to_custom_name("free_text_lines")] = lines


# Sightings


def handle_sightings_observables(related_observables, env):
    refs = []
    for ref in related_observables:
        if ref.item.idref is None:
            # embedded
            new20s = handle_embedded_object(ref.item, env)
            for new20 in new20s:
                refs.append(new20["id"])
        else:
            refs.append(ref.item.idref)
    return refs


def process_information_source_for_sighting(sighting, sighting_instance, env):
    if sighting.source:
        information_source = sighting.source
        if information_source.identity is not None:
            sighting_instance["where_sighted_refs"] = [get_identity_ref(information_source.identity, env)]
            if information_source.description:
                process_description_and_short_description(sighting_instance, sighting)
            if information_source.references:
                for ref in information_source.references:
                    sighting_instance["external_references"].append({"url": ref})
            if information_source.roles:
                handle_missing_string_property(sighting_instance, "information_source_role", information_source.roles, True)
            if information_source.tools:
                for tool in information_source.tools:
                    handle_missing_tool_property(sighting_instance, tool)


def handle_sighting(sighting, sighted_object_id, env):
    sighting_instance = create_basic_object("sighting", sighting, env)
    sighting_instance["count"] = 1
    sighting_instance["sighting_of_ref"] = sighted_object_id
    process_description_and_short_description(sighting_instance, sighting)
    if sighting.related_observables:
        sighting_instance["observed_data_refs"] = handle_sightings_observables(sighting.related_observables, env)
    if sighting.source:
        process_information_source_for_sighting(sighting, sighting_instance, env)
    # assumption is that the observation is a singular, not a summary of observations
    sighting_instance["summary"] = False
    return sighting_instance


# Relationships


def create_relationship(source_ref, target_ref, env, verb, rel_obj=None):
    relationship_instance = create_basic_object("relationship", rel_obj, env)
    relationship_instance["source_ref"] = source_ref
    relationship_instance["target_ref"] = target_ref
    relationship_instance["relationship_type"] = verb
    if env.created_by_ref:
        relationship_instance["created_by_ref"] = env.created_by_ref
    if rel_obj is not None and hasattr(rel_obj, "relationship") and rel_obj.relationship is not None:
        relationship_instance["description"] = rel_obj.relationship.value
    return relationship_instance


# Creating and Linking up relationships  (three cases)
# 1.  The object is embedded - create the object, add it to the bundle, return to id so the relationship is complete
# 2.  an idref is given, and it has a corresponding 2.0 id, use it
# 3.  an idref is given, but it has NO corresponding 2.0 id, add 1.x id, and fix at the end in fix_relationships


def handle_relationship_to_objs(items, source_id, env, verb):
    for item in items:
        new20s = handle_embedded_object(item, env)
        for new20 in new20s:
            env.bundle_instance["relationships"].append(create_relationship(source_id,
                                                                            new20["id"] if new20 else None,
                                                                            env,
                                                                            verb,
                                                                            item))


def handle_embedded_ref(ref, item, id, env, default_verb, to_direction):
    new20s = handle_embedded_object(item, env)
    for new20 in new20s:
        if to_direction:
            source_id = id
            target_id = new20["id"] if new20 else None
        else:
            source_id = new20["id"] if new20 else None
            target_id = id
        env.bundle_instance["relationships"].append(create_relationship(source_id,
                                                                        target_id,
                                                                        env,
                                                                        determine_appropriate_verb(default_verb, target_id),
                                                                        ref))


def handle_existing_ref(ref, ref_id, id, env, default_verb, to_direction):
    source_id = id if to_direction else ref_id
    target_id = ref_id if to_direction else id
    env.bundle_instance["relationships"].append(create_relationship(source_id,
                                                                    target_id,
                                                                    env,
                                                                    default_verb,
                                                                    ref))


def handle_existing_refs(ref, id, env, verb, to_direction):
    for ref_id in get_id_value(ref.item.idref):
        handle_existing_ref(ref, ref_id, id, env, verb, to_direction)


def handle_relationship_ref(ref, item, id, env, default_verb, to_direction=True):
    if item.idref is None:
        handle_embedded_ref(ref, item, id, env, default_verb, to_direction)
    elif exists_id_key(item.idref):
        handle_existing_refs(ref, id, env, default_verb, to_direction)
    else:
        # a forward reference, fix later
        source_id = id if to_direction else item.idref
        target_id = text_type(item.idref) if to_direction else id
        rel_obj = create_relationship(source_id, target_id, env, default_verb, item)
        if hasattr(ref, "relationship") and ref.relationship is not None:
            rel_obj["description"] = ref.relationship.value
        env.bundle_instance["relationships"].append(rel_obj)


def handle_relationship_to_refs(refs, source_id, env, default_verb):
    for ref in refs:
        if hasattr(ref, "item"):
            item = ref.item
        elif hasattr(ref, "course_of_action"):
            item = ref.course_of_action
        handle_relationship_ref(ref, item, source_id, env, default_verb, to_direction=True)


def handle_relationship_from_refs(refs, target_id, env, default_verb):
    for ref in refs:
        if hasattr(ref, "item"):
            item = ref.item
        elif hasattr(ref, "course_of_action"):
            item = ref.course_of_action
        handle_relationship_ref(ref, item, target_id, env, default_verb, to_direction=False)


def handle_observable_information_list_as_pattern(obs_list):
    return convert_observable_list_to_pattern(obs_list)


def handle_observable_information_list(obs_list, source_id, env, verb):
    for o in obs_list:
        if o.idref is None and o.object_ and not o.object_.idref:
            # embedded, so generate scos too
            new_od = convert_observed_data(o, env)
            add_id_of_obs_in_characterizations(new_od["id"])
            for obj_ref in new_od["object_refs"]:
                env.bundle_instance["relationships"].append(create_relationship(source_id,
                                                                                obj_ref,
                                                                                env,
                                                                                verb))
        else:
            if o.idref:
                idref = o.idref
            elif o.idref is None and o.object_ and o.object_.idref:
                idref = generate_stix2x_id("observed-data", o.object_.idref)

            if id_in_observed_data_mappings(idref):
                obs2x = get_observed_data_from_mapping(idref)
                add_id_of_obs_in_characterizations(obs2x["id"])
                for ref in obs2x["object_refs"]:
                    env.bundle_instance["relationships"].append(create_relationship(source_id,
                                                                                    ref,
                                                                                    env,
                                                                                    verb))
            else:
                if id_in_observable_mappings(idref):
                    # handling a reference, scos generated later
                    new_od = convert_observed_data(get_obs_from_mapping(idref), env, keep_scos=False)
                    add_id_of_obs_in_characterizations(new_od["id"])
                    env.bundle_instance["objects"].append(new_od)
                    for ref in new_od["object_refs"]:
                        env.bundle_instance["relationships"].append(create_relationship(source_id,
                                                                                        ref,
                                                                                        env,
                                                                                        verb))
                else:
                    # a forward reference, fix later
                    env.bundle_instance["relationships"].append(create_relationship(source_id,
                                                                                    idref,
                                                                                    env,
                                                                                    verb))


def reference_needs_fixing(ref):
    return ref and ref.find("--") == -1


# this is very simplistic - because STIX 1.x verbs are not consistent.
def determine_appropriate_verb(current_verb, m_id):
    if m_id is not None and current_verb == "uses":
        type_and_uuid = m_id.split("--")
        if type_and_uuid[0] == "identity":
            return u"targets"
    return current_verb


# for ids in source and target refs that are still 1.x ids,
def fix_relationships(env):
    extra_relationships = []
    bundle_instance = env.bundle_instance
    for ref in bundle_instance["relationships"]:
        if is_stix1x_id(ref["source_ref"]):
            if not exists_id_key(ref["source_ref"]):
                new_id = generate_stix2x_id(None, str.lower(ref["source_ref"]))
                if new_id is None:
                    error("Dangling source reference %s in %s", 601, ref["source_ref"], ref["id"])
                add_id_value(ref["source_ref"], new_id)
            mapped_ids = get_id_value(ref["source_ref"])
            if mapped_ids[0] is None:
                error("Dangling source reference %s in %s", 601, ref["source_ref"], ref["id"])
            first_one = True
            for m_id in mapped_ids:
                if first_one:
                    ref["source_ref"] = m_id
                    first_one = False
                else:
                    extra_relationships.append(create_relationship(m_id, ref["target_ref"], env, ref["verb"]))
        if is_stix1x_id(ref["target_ref"]):
            if not exists_id_key(ref["target_ref"]):
                # create one, and add it
                new_id = generate_stix2x_id(None, ref["target_ref"].lower())
                if new_id is None:
                    error("Dangling target reference %s in %s", 602, ref["target_ref"], ref["id"])
                add_id_value(ref["target_ref"], new_id)
            mapped_ids = get_id_value(ref["target_ref"])
            if mapped_ids[0] is None:
                error("Dangling target reference %s in %s", 602, ref["target_ref"], ref["id"])
            first_one = True
            for m_id in mapped_ids:
                verb = determine_appropriate_verb(ref["relationship_type"], m_id)
                if first_one:
                    ref["target_ref"] = m_id
                    ref["relationship_type"] = verb
                    first_one = False
                else:
                    extra_relationships.append(create_relationship(ref["source_ref"], m_id, env, verb))
    bundle_instance["relationships"].extend(extra_relationships)


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
                        rel["target_ref"] in new_ids or exists_ids_with_no_1x_object(rel["target_ref"])):
                    rels_to_include.append(rel["id"])
                    rels_to_include.append(rel["target_ref"])
                    warn("Including %s in %s and added the target_ref %s to the report", 704, rel["id"], rep["id"], rel["target_ref"])
                elif not ("target_ref" in rel and rel["target_ref"]):
                    rels_to_include.append(rel["id"])
                    warn("Including %s in %s although the target_ref is unknown", 706, rel["id"], rep["id"])
                elif not (rel["target_ref"] in new_ids or exists_ids_with_no_1x_object(rel["target_ref"])):
                    warn("Not including %s in %s because there is no corresponding SDO for %s", 708, rel["id"], rep["id"], rel["target_ref"])
            elif "target_ref" in rel and rel["target_ref"] in refs_in_this_report:
                if "source_ref" in rel and rel["source_ref"] and (
                        rel["source_ref"] in new_ids or exists_ids_with_no_1x_object(rel["source_ref"])):
                    rels_to_include.append(rel["id"])
                    rels_to_include.append(rel["source_ref"])
                    warn("Including %s in %s and added the source_ref %s to the report", 705, rel["id"], rep["id"], rel["source_ref"])
                elif not ("source_ref" in rel and rel["source_ref"]):
                    rels_to_include.append(rel["id"])
                    warn("Including %s in %s although the source_ref is unknown", 707, rel["id"], rep["id"])
                elif not (rel["source_ref"] in new_ids or exists_ids_with_no_1x_object(rel["source_ref"])):
                    warn("Not including %s in %s because there is no corresponding SDO for %s", 709, rel["id"], rep["id"], rel["source_ref"])
        if "object_refs" in rep:
            rep["object_refs"].extend(rels_to_include)
        else:
            rep["object_refs"] = rels_to_include


# confidence

def add_confidence_to_object(sdo_instance, confidence):
    if confidence is not None and confidence.value is not None:
        sdo_instance["confidence"] = convert_confidence(confidence, sdo_instance["id"])


# campaign


def convert_campaign(camp, env):
    campaign_instance = create_basic_object("campaign", camp, env)
    process_description_and_short_description(campaign_instance, camp)
    campaign_instance["name"] = camp.title
    if camp.names is not None:
        campaign_instance["aliases"] = []
        for name in camp.names:
            if isinstance(name, string_types):
                campaign_instance["aliases"].append(name)
            else:
                campaign_instance["aliases"].append(name.value)
    if "created_by_ref" in campaign_instance:
        new_env = env.newEnv(timestamp=campaign_instance["created"], created_by_ref=campaign_instance["created_by_ref"])
    else:
        new_env = env.newEnv(timestamp=campaign_instance["created"])
    # process information source before any relationships
    new_env.add_to_env(created_by_ref=process_information_source(camp.information_source, campaign_instance, new_env))

    handle_multiple_missing_statement_properties(campaign_instance, camp.intended_effects, "intended_effect")
    handle_missing_string_property(campaign_instance, "status", camp.status)

    if get_option_value("spec_version") == "2.0":
        handle_missing_confidence_property(campaign_instance, camp.confidence)
    else:  # 2.1
        add_confidence_to_object(campaign_instance, camp.confidence)

    if camp.activity is not None:
        for a in camp.activity:
            warn("Campaign/Activity type in %s not supported in STIX 2.x", 403, campaign_instance["id"])
    if camp.related_ttps is not None:
        # TODO: victims (identity) use targets, not uses
        # TODO: maybe use _TTP_RELATIONSHIP_MAPPING
        handle_relationship_to_refs(camp.related_ttps,
                                    campaign_instance["id"],
                                    new_env,
                                    "uses")
    if camp.related_incidents is not None and get_option_value("incidents"):
        handle_relationship_from_refs(camp.related_incidents,
                                      campaign_instance["id"],
                                      new_env,
                                      "attributed-to")
    if camp.related_indicators is not None:
        handle_relationship_from_refs(camp.related_indicators,
                                      campaign_instance["id"],
                                      new_env,
                                      "indicates")
    if camp.attribution is not None:
        for att in camp.attribution:
            handle_relationship_to_refs(att,
                                        campaign_instance["id"],
                                        new_env,
                                        "attributed-to")
    if camp.associated_campaigns:
        info("All 'associated campaigns' relationships of %s are assumed to not represent STIX 1.2 versioning", 710, camp.id_)
        handle_relationship_to_refs(camp.related_coas,
                                    campaign_instance["id"],
                                    new_env,
                                    "related-to")
    finish_basic_object(camp.id_, campaign_instance, env, camp)
    return campaign_instance


# course of action


def handle_missing_objective_property(sdo_instance, objective):
    if objective is not None:
        if get_option_value("missing_policy") == "ignore":
            warn("Missing property 'objective' of %s is ignored", 307, sdo_instance["id"])
        else:
            all_text = []

            if objective.descriptions:
                for d in objective.descriptions:
                    all_text.append(text_type(d.value))

            if objective.short_descriptions:
                for sd in objective.short_descriptions:
                    all_text.append(text_type(sd.value))

            if get_option_value("missing_policy") == "add-to-description":
                sdo_instance["description"] += "\n\n" + "OBJECTIVE: "
                sdo_instance["description"] += "\n\n\t".join(all_text)
            elif get_option_value("missing_policy") == "use-custom-properties":
                sdo_instance[convert_to_custom_name("objective")] = " ".join(all_text)
                warn("Used custom property for objective of %s", 308, sdo_instance["id"])
            if objective.applicability_confidence:
                handle_missing_confidence_property(sdo_instance, objective.applicability_confidence, "objective")


def convert_course_of_action(coa, env):
    coa_instance = create_basic_object("course-of-action", coa, env)
    new_env = env.newEnv(timestamp=coa_instance["created"])
    process_description_and_short_description(coa_instance, coa)
    coa_instance["name"] = coa.title
    handle_missing_string_property(coa_instance, "stage", coa.stage)
    if coa.type_:
        convert_controlled_vocabs_to_open_vocabs(coa_instance, "labels", [coa.type_], COA_LABEL_MAP, False)
    handle_missing_objective_property(coa_instance, coa.objective)

    if coa.parameter_observables is not None:
        parameter_expression = handle_observable_information_list_as_pattern(coa.parameter_observables)
        handle_missing_string_property(coa_instance, "parameter_expression", parameter_expression)
    if coa.structured_coa:
        warn("Structured COAs type in %s are not supported in STIX 2.x", 404, coa_instance["id"])
    handle_missing_statement_properties(coa_instance, coa.impact, "impact")
    handle_missing_statement_properties(coa_instance, coa.cost, "cost")
    handle_missing_statement_properties(coa_instance, coa.efficacy, "efficacy")
    new_env.add_to_env(created_by_ref=process_information_source(coa.information_source,
                                                                 coa_instance,
                                                                 new_env))
    # process information source before any relationships
    if coa.related_coas:
        info("All 'associated coas' relationships of %s are assumed to not represent STIX 1.2 versioning", 710, coa.id_)
        handle_relationship_to_refs(coa.related_coas, coa_instance["id"], new_env,
                                    "related-to")
    finish_basic_object(coa.id_, coa_instance, env, coa)
    return coa_instance


# exploit target


def process_et_properties(sdo_instance, et, env):
    process_description_and_short_description(sdo_instance, et, True)
    if "name" in sdo_instance:
        info("Title %s used for name, appending exploit_target %s title in description property",
             303, sdo_instance["type"], sdo_instance["id"])
        handle_missing_string_property(sdo_instance, "title", et.title, False)
    elif et.title is not None:
        sdo_instance["name"] = et.title
    new_env = env.newEnv(timestamp=sdo_instance["created"])
    new_env.add_to_env(created_by_ref=process_information_source(et.information_source, sdo_instance, new_env))
    if et.potential_coas is not None:
        handle_relationship_from_refs(et.potential_coas, sdo_instance["id"],
                                      new_env,
                                      "mitigates")


def convert_vulnerability(v, et, env):
    vulnerability_instance = create_basic_object("vulnerability", v, env, et.id_)
    if v.title is not None:
        vulnerability_instance["name"] = v.title
    process_description_and_short_description(vulnerability_instance, v)
    if v.cve_id is not None:
        vulnerability_instance["external_references"].append({"source_name": "cve", "external_id": v.cve_id})
    if v.osvdb_id is not None:
        vulnerability_instance["external_references"].append({"source_name": "osvdb", "external_id": v.osvdb_id})

    if v.source is not None:
        handle_missing_string_property(vulnerability_instance, "source", v.source, False)

    if v.cvss_score is not None:
        # FIXME: add CVSS score into description
        info("CVSS Score in %s is not handled, yet.", 815, vulnerability_instance["id"])

    if v.discovered_datetime is not None:
        handle_missing_string_property(vulnerability_instance,
                                       "discovered_datetime",
                                       v.discovered_datetime.value.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                       False)

    if v.published_datetime is not None:
        handle_missing_string_property(vulnerability_instance,
                                       "published_datetime",
                                       v.published_datetime.value.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                       False)

    if v.affected_software is not None:
        info("Affected Software in %s is not handled, yet.", 815, vulnerability_instance["id"])

    if v.references is not None:
        for ref in v.references:
            vulnerability_instance["external_references"].append({"source_name": "internet_resource", "url": ref})
    process_et_properties(vulnerability_instance, et, env)
    finish_basic_object(et.id_, vulnerability_instance, env, v)
    return vulnerability_instance


def convert_exploit_target(et, env):
    ets = []
    if hasattr(et, "timestamp") and et.timestamp:
        new_env = env.newEnv(timestamp=et.timestamp)
    else:
        new_env = env
    if et.vulnerabilities is not None:
        for v in et.vulnerabilities:
            ets.append(convert_vulnerability(v, et, new_env))
    if et.weaknesses is not None:
        for w in et.weaknesses:
            warn("ExploitTarget/Weaknesses type in %s not supported in STIX 2.x", 405, et.id_)
    if et.configuration is not None:
        for c in et.configuration:
            warn("ExploitTarget/Configurations type in %s not supported in STIX 2.x", 406, et.id_)
    env.bundle_instance["objects"].extend(ets)
    return ets


# identities

def get_name(name):
    return name.name_elements[0].value


def convert_party_name(party_name, obj, is_identity_obj):
    aliases = []
    if party_name.organisation_names and party_name.person_names:
        error("Identity %s has organization and person names", 606, obj["id"])
    if party_name.person_names:
        if is_identity_obj:
            obj["identity_class"] = "individual"
        first_one = True
        for name in party_name.person_names:
            if first_one:
                obj["name"] = get_name(name)
                first_one = False
            else:
                alias_name = get_name(name)
                aliases.append(alias_name)
                warn("Only one person name allowed for %s in STIX 2.x, used %s, %s becomes an alias",
                     502,
                     obj["id"],
                     obj["name"],
                     alias_name)
    elif party_name.organisation_names:
        if is_identity_obj:
            obj["identity_class"] = "organization"
        first_one = True
        for name in party_name.organisation_names:
            if first_one:
                obj["name"] = get_name(name)
                first_one = False
            else:
                alias_name = get_name(name)
                aliases.append(alias_name)
                warn("Only one organization name allowed for %s in STIX 2.x, used %s, %s becomes an alias",
                     503,
                     obj["id"],
                     obj["name"],
                     alias_name)
    return aliases


def determine_country_code(geo):
    if geo.name_code:
        return geo.name_code
    else:
        iso = pycountry.countries.get(name=geo.value)
        if iso:
            return iso.alpha_2
        else:
            if geo.value:
                warn("No ISO code for %s, therefore using full name", 618, geo.value)
                return geo.value
            else:
                return None


# spec doesn't indicate that code is preferred
def determine_aa(geo):
    if geo.name_code:
        return geo.name_code
    elif geo.value:
        return geo.value
    else:
        return None


def convert_ciq_addresses2_1(ciq_info_addresses, identity_instance, env, parent_id=None):
    location_keys = []
    for add in ciq_info_addresses:
        if not add.free_text_address:
            # only reuse if administrative area and country match, and no free text address
            if hasattr(add, "administrative_area") and add.administrative_area and hasattr(add,
                                                                                           "country") and add.country:
                if len(add.country.name_elements) == 1:
                    cc = determine_country_code(add.country.name_elements[0])
                    for aa in add.administrative_area.name_elements:
                        location_keys.append("c:" + text_type(cc) +
                                             "," +
                                             "aa:" + text_type(determine_aa(aa)))
                else:
                    warn("Multiple administrative areas with multiple countries in %s is not handled", 631, None)
            elif hasattr(add, "administrative_area") and add.administrative_area:
                for aa in add.adminstrative_area.name_elements:
                    location_keys.append("aa:" + text_type(determine_aa(aa)))
            elif hasattr(add, "country") and add.country:
                for c in add.country.name_elements:
                    location_keys.append("c:" + text_type(determine_country_code(c)))
        else:
            # only remember locations with no free text address
            warn("Location with free text address in %s not handled yet", 433, identity_instance["id"])
        for key in location_keys:
            if exists_location_object(key):
                location = get_location_object(key)
            else:
                aa = None
                c = None
                location = create_basic_object("location", add, env)
                location["spec_version"] = "2.1"
                if key.find(",") != -1:
                    both_parts = key.split(",")
                    c = both_parts[0].split(":")[1]
                    aa = both_parts[1].split(":")[1]
                else:
                    part = key.split(":")
                    if part[0] == "c":
                        c = part[1]
                    elif part[0] == "aa":
                        aa = part[1]
                if aa:
                    location["administrative_area"] = aa
                if c:
                    location["country"] = c
                add_location_object(key, location)
                warn("Location %s may not contain all aspects of the STIX 1.x address object", 803, location["id"])
                env.bundle_instance["objects"].append(location)
            env.bundle_instance["objects"].append(create_relationship(identity_instance["id"],
                                                                      location["id"],
                                                                      env,
                                                                      "located-at"))


def convert_identity(identity, env, parent_id=None, temp_marking_id=None, from_package=False):
    identity_instance = create_basic_object("identity", identity, env, parent_id)
    identity_instance["sectors"] = []
    spec_version = get_option_value("spec_version")
    if (spec_version == "2.0"):
        identity_instance["identity_class"] = "unknown"
    if identity.name is not None:
        identity_instance["name"] = identity.name
    if isinstance(identity, CIQIdentity3_0Instance):
        if identity.roles:
            handle_missing_string_property(identity_instance, "information_source_role", identity.roles, True)
            warn("Roles is not a property of an identity (%s).  Perhaps the roles are associated with a related Threat Actor",
                 428,
                 identity_instance["id"])
            # convert_controlled_vocabs_to_open_vocabs(identity_instance, "roles", identity.roles, ROLES_MAP, False)
        ciq_info = identity._specification
        if ciq_info.party_name:
            if "name" in identity_instance:
                warn("CIQ name found in %s, overriding other name", 711, identity_instance["id"])
            convert_party_name(ciq_info.party_name, identity_instance, True)
        if ciq_info.organisation_info:
            identity_instance["identity_class"] = "organization"
            warn("Based on CIQ information, %s is assumed to be an organization", 716, identity_instance["id"])
            if ciq_info.organisation_info.industry_type:
                industry = ciq_info.organisation_info.industry_type.replace(" ,", ",")
                industry = industry.replace(", ", ",")
                industry = industry.split(",")
                convert_controlled_vocabs_to_open_vocabs(identity_instance, "sectors", industry, SECTORS_MAP, False)
        if ciq_info.addresses:
            if spec_version == "2.1":
                convert_ciq_addresses2_1(ciq_info.addresses, identity_instance, env, parent_id)
        if ciq_info.free_text_lines:
            handle_free_text_lines(identity_instance, ciq_info.free_text_lines)
    if identity.related_identities:
        msg = "All 'associated identities' relationships of %s are assumed to not represent STIX 1.2 versioning"
        info(msg, 710, identity_instance["id"])
        handle_relationship_to_refs(identity.related_identities, identity_instance["id"], env, "related-to")
    finish_basic_object(identity.id_, identity_instance,
                        env.newEnv(created_by_ref=identity_instance["id"] if from_package else parent_id),
                        identity,
                        temp_marking_id=temp_marking_id)
    return identity_instance


# incident


def convert_incident(incident, env):
    incident_instance = create_basic_object(convert_to_custom_name("incident", separator="-"), incident, env)
    new_env = env.newEnv(timestamp=incident_instance["created"])
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
    # process information source before any relationships
    new_env.add_to_env(created_by_ref=process_information_source(incident.information_source, incident_instance, new_env))

    if get_option_value("spec_version") == "2.0":
        handle_missing_confidence_property(incident_instance, incident.confidence)
    else:  # 2.1
        add_confidence_to_object(incident_instance, incident.confidence)

    # process related observables first
    if incident.related_observables is not None:
        handle_relationship_from_refs(incident.related_observables, incident_instance["id"], new_env, "part-of")
    if incident.related_indicators is not None:
        handle_relationship_from_refs(incident.related_indicators, incident_instance["id"], new_env, "indicates")
    if incident.leveraged_ttps is not None:
        warn("Using %s for the %s of %s", 718, "related-to", "leveraged TTPs", incident.id_)
        handle_relationship_to_refs(incident.leveraged_ttps, incident_instance["id"], new_env, "related-to")
    if incident.coa_taken is not None:
        handle_relationship_to_refs(incident.coa_taken, incident_instance["id"], new_env, "used")

    if incident.contacts is not None:
        for contact in incident.contacts:
            incident_instance["contacts"] = []
            if contact.identity:
                id2x = convert_identity(contact.identity, env)
                env.bundle_instance["objects"].append(id2x)
                incident_instance["contacts"].append(id2x["id"])

    if incident.reporter is not None:
        reporter = incident.reporter
        if reporter.identity:
            id2x = convert_identity(reporter.identity, env)
            env.bundle_instance["objects"].append(id2x)
            incident_instance["reporter"] = id2x["id"]

    if incident.responders is not None:
        for responder in incident.responders:
            incident_instance["responders"] = []
            if responder.identity:
                id2x = convert_identity(responder.identity, env)
                env.bundle_instance["objects"].append(id2x)
                incident_instance["responders"].append(id2x["id"])

    if incident.coordinators is not None:
        for coordinator in incident.coordinators:
            incident_instance["coordinators"] = []
            if coordinator.identity:
                id2x = convert_identity(coordinator.identity, env)
                env.bundle_instance["objects"].append(id2x)
                incident_instance["coordinators"].append(id2x["id"])

    if incident.victims is not None:
        for victim in incident.victims:
            incident_instance["victims"] = []
            if victim.identity:
                id2x = convert_identity(victim.identity, env)
                env.bundle_instance["objects"].append(id2x)
                incident_instance["victims"].append(id2x["id"])

    if incident.affected_assets is not None:
        # FIXME: add affected_assets to description
        info("Incident Affected Assets in %s is not handled, yet.", 815, incident_instance["id"])

    if incident.impact_assessment is not None:
        # FIXME: add impact_assessment to description
        info("Incident Impact Assessment in %s is not handled, yet", 815, incident_instance["id"])

    handle_missing_string_property(incident_instance, "status", incident.status)
    if incident.related_incidents:
        info("All 'associated incidents' relationships of %s are assumed to not represent STIX 1.2 versioning",
             710, incident_instance["id"])
        handle_relationship_to_refs(incident.related_incidents, incident_instance["id"], new_env, "related-to")
    finish_basic_object(incident.id_, incident_instance, env, incident)
    return incident_instance


# indicator

def convert_kill_chain_missing_names(phase, kill_chain_phases_20):
    kill_chain_name = phase.kill_chain_name
    phase_name = phase.name
    if not phase.kill_chain_name and phase.kill_chain_id:
        kill_chain_name = phase.kill_chain_id
    if not phase.name and phase.phase_id:
        phase_name = phase.phase_id
    kill_chain_phases_20.append({"kill_chain_name": kill_chain_name, "phase_name": phase_name})


def convert_kill_chains(kill_chain_phases, sdo_instance):
    if kill_chain_phases is not None:
        kill_chain_phases_20 = []
        for phase in kill_chain_phases:
            if isinstance(phase, KillChainPhaseReference):
                try:
                    if phase.phase_id:
                        kill_chain_info = _KILL_CHAINS_PHASES[phase.phase_id]
                    else:
                        kill_chain_info = _KILL_CHAINS_PHASES[phase]
                    kill_chain_phases_20.append({"kill_chain_name": kill_chain_info["kill_chain_name"],
                                                 "phase_name": kill_chain_info["phase_name"]})
                except KeyError:
                    warn("Unknown phase_id %s in %s", 632, phase.phase_id, sdo_instance["id"])
                    convert_kill_chain_missing_names(phase, kill_chain_phases_20)
            elif isinstance(phase, KillChainPhase):
                convert_kill_chain_missing_names(phase, kill_chain_phases_20)
        if kill_chain_phases_20:
            sdo_instance["kill_chain_phases"] = kill_chain_phases_20


_ALLOW_YARA_AND_SNORT_PATTENS = False


def determine_pattern_type(tm):
    if isinstance(tm, YaraTestMechanism):
        return "yara"
    elif isinstance(tm, SnortTestMechanism):
        return "snort"
    elif isinstance(tm, OpenIOCTestMechanism):
        return "openioc"
    else:
        return "unknown"


def convert_test_mechanism(indicator, indicator_instance):
    if indicator.test_mechanisms is not None:
        if not _ALLOW_YARA_AND_SNORT_PATTENS and get_option_value("spec_version") == "2.0":
            warn("YARA/SNORT/IOC or other patterns are not supported in STIX 2.0. See %s", 504, indicator_instance["id"])
            return
        if hasattr(indicator_instance, "pattern"):
            # TODO: maybe put in description
            warn("Only one type pattern can be specified in %s - using 'stix'", 712, indicator_instance["id"])
        else:
            for tm in indicator.test_mechanisms:
                if hasattr(indicator_instance, "pattern"):
                    msg = "Only one alternative test mechanism allowed for %s in STIX 2.1 - used %s, dropped %s"
                    warn(msg, 506, indicator_instance["id"], indicator_instance["pattern_type"], determine_pattern_type(tm))
                else:
                    if isinstance(tm, YaraTestMechanism):
                        indicator_instance["pattern"] = text_type(tm.rule.value)
                        indicator_instance["pattern_type"] = "yara"
                    elif isinstance(tm, SnortTestMechanism):
                        list_of_strings = []
                        for rule in tm.rules:
                            list_of_strings.append(text_type(rule.value))
                        indicator_instance["pattern"] = ", ".join(list_of_strings)
                        indicator_instance["pattern_type"] = "snort"
                    elif isinstance(tm, OpenIOCTestMechanism):
                        warn("IOC indicator in %s cannot be converted to a STIX pattern", 410, indicator_instance["id"])
                        indicator_instance["pattern"] = ensure_text(etree.tostring(tm.ioc))
                        indicator_instance["pattern_type"] = "openioc"


def negate_indicator(indicator):
    return hasattr(indicator, "negate") and indicator.negate


def convert_indicator(indicator, env):
    spec_version = get_option_value("spec_version")
    indicator_instance = create_basic_object("indicator", indicator, env)

    process_description_and_short_description(indicator_instance, indicator)
    convert_controlled_vocabs_to_open_vocabs(indicator_instance,
                                             "labels" if spec_version == "2.0" else "indicator_types",
                                             indicator.indicator_types,
                                             INDICATOR_LABEL_MAP, False, required=spec_version == "2.0")
    if indicator.title is not None:
        indicator_instance["name"] = indicator.title
    if indicator.alternative_id is not None:
        for alt_id in indicator.alternative_id:
            indicator_instance["external_references"].append({"source_name": "alternative_id", "external_id": alt_id})
    if indicator.valid_time_positions is not None:
        for window in indicator.valid_time_positions:
            if "valid_from" not in indicator_instance:
                if not window.start_time.value:
                    warn("No start time for the first valid time interval is available in %s, other time intervals might be more appropriate",
                         619, indicator_instance["id"])
                indicator_instance["valid_from"] = \
                    convert_timestamp_to_string(window.start_time.value, indicator_instance["created"])
                indicator_instance["valid_until"] = \
                    convert_timestamp_to_string(window.end_time.value, indicator_instance["created"])
            else:
                warn("Only one valid time window allowed for %s in STIX 2.x - used first one",
                     507, indicator_instance["id"])
        if "valid_from" not in indicator_instance:
            warn("No valid time position information available in %s, using parent timestamp",
                 903, indicator_instance["id"])
            indicator_instance["valid_from"] = convert_timestamp_of_stix_object(indicator, env.timestamp)
    convert_kill_chains(indicator.kill_chain_phases, indicator_instance)
    if indicator.likely_impact:
        handle_missing_statement_properties(indicator_instance, indicator.likely_impact, "likely_impact")

    if get_option_value("spec_version") == "2.0":
        handle_missing_confidence_property(indicator_instance, indicator.confidence)
    else:  # 2.1
        add_confidence_to_object(indicator_instance, indicator.confidence)
    if indicator.observable is not None:
        # remember observable in case it is used outside of the indicator
        add_to_observable_mappings(indicator.observable)
        indicator_instance["pattern"] = convert_observable_to_pattern(indicator.observable)
        if get_option_value("spec_version") == "2.1":
            indicator_instance["pattern_type"] = "stix"
        add_to_pattern_cache(indicator.id_, indicator_instance["pattern"])
    if indicator.composite_indicator_expression is not None:
        expressions = []
        if stix.__version__ >= "1.2.0.0":
            sub_indicators = indicator.composite_indicator_expression.indicator
        else:
            sub_indicators = indicator.composite_indicator_expression
        for ind in sub_indicators:
            term = convert_indicator_to_pattern(ind)
            if term:
                expressions.append(term)
        indicator_instance["pattern"] = create_boolean_expression(indicator.composite_indicator_expression.operator,
                                                                  expressions)
        add_to_pattern_cache(indicator.id_, indicator_instance["pattern"])
        if get_option_value("spec_version") == "2.1":
            indicator_instance["pattern_type"] = "stix"
    if indicator.observable and indicator.composite_indicator_expression or indicator.composite_indicator_expression:
        warn("Indicator %s has an observable or indicator composite expression which may not supported \
correctly in STIX 2.x - please check this pattern",
             407, indicator_instance["id"])
        # add_to_pattern_cache(indicator.id_, indicator_instance["pattern"])
    if "pattern" not in indicator_instance:
        # STIX doesn't handle multiple patterns for indicators
        convert_test_mechanism(indicator, indicator_instance)
    env = env.newEnv(timestamp=indicator_instance["created"])
    indicator_created_by_ref = process_information_source(indicator.producer, indicator_instance,
                                                          env)
    env.add_to_env(created_by_ref=indicator_created_by_ref)
    # process information source before any relationships
    if indicator.sightings:
        for s in indicator.sightings:
            env.bundle_instance["objects"].append(handle_sighting(s, indicator_instance["id"], env))
    if indicator.suggested_coas is not None:
        warn("Using %s for the %s of %s", 718, "investigates", "suggested COAs", indicator.id_)
        handle_relationship_from_refs(indicator.suggested_coas, indicator_instance["id"], env,
                                      "investigates")
    if indicator.related_campaigns is not None:
        handle_relationship_to_refs(indicator.related_campaigns, indicator_instance["id"], env,
                                    "attributed-to")
    if indicator.indicated_ttps is not None:
        handle_relationship_to_refs(indicator.indicated_ttps, indicator_instance["id"], env,
                                    "indicates")
    if indicator.related_indicators:
        info("All 'associated indicators' relationships of %s are assumed to not represent STIX 1.2 versioning", 710, indicator.id_)
        handle_relationship_to_refs(indicator.related_indicators, indicator_instance["id"], env,
                                    "related-to")
    finish_basic_object(indicator.id_, indicator_instance, env, indicator)
    return indicator_instance


# observables

def convert_cybox_object(o, env=None):
    if get_option_value("spec_version") == "2.0":
        return convert_cybox_object20(o)
    else:
        return convert_cybox_object21(o, env)


def set_embedded_ref_property_2_1(sco, ro, stix2x_rel_name):
    if stix2x_rel_name.endswith("refs"):
        if stix2x_rel_name not in sco:
            sco[stix2x_rel_name] = list()
        sco[stix2x_rel_name].append(ro["id"])
    else:
        sco[stix2x_rel_name] = ro.id


def set_embedded_ref_property_2_0(sco, co_id, stix2x_rel_name):
    if stix2x_rel_name.endswith("refs"):
        if stix2x_rel_name not in sco:
            sco[stix2x_rel_name] = list()
        sco[stix2x_rel_name].append(co_id)
    else:
        sco[stix2x_rel_name] = co_id


def create_scos(obs, observed_data_instance, env, keep_scos):
    if not obs.object_ and obs.observable_composition:
        warn("%s contains a observable composition, which implies it not an observation, but a pattern and needs " +
             "to be contained within an indicator.",
             635, obs.id_)
    else:
        observed_data_instance["object_refs"] = []
        scos = convert_cybox_object(obs.object_, env)
        if obs.object_.related_objects:
            for o in obs.object_.related_objects:
                if not o.idref:
                    # it is embedded - for idrefs see convert_cybox.py
                    related = convert_cybox_object(o, env)
                    if related:
                        scos.extend(related)
                        property_name = embedded_property_ref_name(obs.object_.properties, o.relationship)
                        if not property_name:
                            env.bundle_instance["objects"].append(
                                create_relationship(scos[0]["id"],
                                                    related[0]["id"],
                                                    env,
                                                    o.relationship.value.lower() if o.relationship and o.relationship.value else "resolves_to"))
                        else:
                            if o.relationship and o.relationship.value:
                                set_embedded_ref_property_2_1(scos[0], related[0], property_name)
        if scos:
            for obj in scos:
                observed_data_instance["object_refs"].append(obj["id"])
                if keep_scos:
                    env.bundle_instance["objects"].append(obj)


def create_cyber_observables(obs, observed_data_instance):
    if not obs.object_ and obs.observable_composition:
        warn("%s contains a observable composition, which implies it not an observation, but a pattern and needs " +
             "to be contained within an indicator",
             635, obs.id_)
    else:
        observed_data_instance["objects"] = convert_cybox_object(obs.object_)
        if not observed_data_instance["objects"]:
            warn("%s did not yield any STIX 2.x object", 417, obs.object_.id_ if obs.object_.id_ else obs.id_)
        else:
            if obs.object_.related_objects:
                for o in obs.object_.related_objects:
                    # create index for stix 2.0 cyber observable
                    current_largest_id = max(observed_data_instance["objects"].keys())
                    related = convert_cybox_object(o)
                    if related:
                        for index, obj in related.items():
                            observed_data_instance["objects"][text_type(int(index) + int(current_largest_id) + 1)] = obj
                        property_name = embedded_property_ref_name(obs.object_.properties, o.relationship)
                        if property_name and o.relationship and o.relationship.value:
                            set_embedded_ref_property_2_0(observed_data_instance["objects"]['0'],
                                                          text_type(int(current_largest_id) + 1),
                                                          property_name)


_OBSERVABLE_TO_OBSERVED_DATA_MAPPINGS = {}


def add_to_observed_data_mappings(obs1x_id, od2x):
    global _OBSERVABLE_TO_OBSERVED_DATA_MAPPINGS

    _OBSERVABLE_TO_OBSERVED_DATA_MAPPINGS[obs1x_id] = od2x


def id_in_observed_data_mappings(id_):
    return id_ in _OBSERVABLE_TO_OBSERVED_DATA_MAPPINGS


def get_observed_data_from_mapping(id_):
    return _OBSERVABLE_TO_OBSERVED_DATA_MAPPINGS[id_]


def clear_observed_data_mappings():
    global _OBSERVABLE_TO_OBSERVED_DATA_MAPPINGS
    _OBSERVABLE_TO_OBSERVED_DATA_MAPPINGS = {}


def convert_observed_data(obs, env, keep_scos=True):
    observed_data_instance = create_basic_object("observed-data", obs, env)
    if get_option_value("spec_version") == "2.0":
        create_cyber_observables(obs, observed_data_instance)
    else:
        create_scos(obs, observed_data_instance, env, keep_scos)
    # remember the original 1.x observable, in case it has to be turned into a pattern later
    add_to_observable_mappings(obs)
    add_to_observed_data_mappings(obs.id_, observed_data_instance)
    if "objects" not in observed_data_instance and "object_refs" not in observed_data_instance:
        return None
    info("'first_observed' and 'last_observed' data not available directly on %s - using timestamp", 901, obs.id_)
    observed_data_instance["first_observed"] = observed_data_instance["created"]
    observed_data_instance["last_observed"] = observed_data_instance["created"]
    observed_data_instance["number_observed"] = 1 if obs.sighting_count is None else obs.sighting_count
    # TODO: created_by
    finish_basic_object(obs.id_, observed_data_instance, env, obs)
    return observed_data_instance


# report


def process_report_contents(report, env, report_instance):
    report_instance["object_refs"] = []
    # campaigns
    if report.campaigns:
        for camp in report.campaigns:
            if camp.id_ is not None:
                camp20 = convert_campaign(camp, env)
                env.bundle_instance["objects"].append(camp20)
                report_instance["object_refs"].append(camp20["id"])
            else:
                report_instance["object_refs"].append(camp.idref)

    # coas
    if report.courses_of_action:
        for coa in report.courses_of_action:
            if coa.id_ is not None:
                coa20 = convert_course_of_action(coa, env)
                env.bundle_instance["objects"].append(coa20)
                report_instance["object_refs"].append(coa20["id"])
            else:
                report_instance["object_refs"].append(coa.idref)

    # exploit-targets
    if report.exploit_targets:
        for et in report.exploit_targets:
            convert_exploit_target(et, env)

    # incidents
    if get_option_value("incidents"):
        if report.incidents:
            for i in report.incidents:
                if i.id_ is not None:
                    i20 = convert_incident(i, env)
                    env.bundle_instance["incidents"].append(i20)
                    report_instance["object_refs"].append(i20["id"])
                else:
                    report_instance["object_refs"].append(i.idref)

    # indicators
    if report.indicators:
        for i in report.indicators:
            if i.id_ is not None:
                i20 = convert_indicator(i, env)
                env.bundle_instance["indicators"].append(i20)
                report_instance["object_refs"].append(i20["id"])
            else:
                report_instance["object_refs"].append(i.idref)

    # locations
    # if report.locations:
    #     for l in report.locations:
    #             if i.id_ is not None:
    #                 i20 = convert_indicator(i, env)
    #                 env.bundle_instance["indicators"].append(i20)
    #                 report_instance["object_refs"].append(i20["id"])
    #             else:
    #                 report_instance["object_refs"].append(i.idref)

    # observables
    if report.observables:
        for o_d in report.observables:
            if o_d.id_ is not None:
                o_d20 = convert_observed_data(o_d, env)
                env.bundle_instance["observed_data"].append(o_d20)
                report_instance["object_refs"].append(o_d20["id"])
            else:
                report_instance["object_refs"].append(o_d.idref)

    # threat actors
    if report.threat_actors:
        for ta in report.threat_actors:
            if ta.id_ is not None:
                ta20 = convert_threat_actor(ta, env)
                env.bundle_instance["objects"].append(ta20)
                report_instance["object_refs"].append(ta20["id"])
            else:
                report_instance["object_refs"].append(ta.idref)

    # ttps
    if report.ttps:
        for ttp in report.ttps:
            if ttp.id_:
                ttps20 = convert_ttp(ttp, env)
                for ttp20 in ttps20:
                    if ttp20["type"] == "malware":
                        env.bundle_instance["objects"].append(ttp)
                    elif ttp20["type"] == "tool":
                        env.bundle_instance["objects"].append(ttp)
                    elif ttp20["type"] == "attack_pattern":
                        env.bundle_instance["objects"].append(ttp)
                    report_instance["object_refs"].append(ttp20["id"])
            else:
                report_instance["object_refs"].append(ttp.idref)


def convert_report(report, env):
    report_instance = create_basic_object("report", report, env)
    info("Report %s contains only the objects explicitly specified in the STIX 1.x report", 726, report_instance["id"])
    process_description_and_short_description(report_instance, report.header)
    new_env = env.newEnv(timestamp=report_instance["created"])
    if report.header:
        header_created_by_ref = process_information_source(report.header.information_source, report_instance, new_env)
        new_env.add_to_env(created_by_ref=header_created_by_ref)
        # process information source before any relationships
        if report.header.title is not None:
            report_instance["name"] = report.header.title
        spec_version = get_option_value("spec_version")
        convert_controlled_vocabs_to_open_vocabs(report_instance,
                                                 "labels" if spec_version == "2.0" else "report_types",
                                                 report.header.intents,
                                                 REPORT_LABELS_MAP,
                                                 False,
                                                 required=spec_version == "2.0")
    else:
        report_instance["labels" if get_option_value("spec_version") == "2.0" else "report_types"] = ["unknown"]
    process_report_contents(report, new_env, report_instance)
    report_instance["published"] = report_instance["created"]
    info("The published property is required for STIX 2.x Report %s, using the created property", 720, report_instance["id"])
    if report.related_reports is not None:
        # FIXME: related reports?
        info("Report Related_Reports in %s is not handled, yet.", 815, report_instance["id"])
    finish_basic_object(report.id_, report_instance, env, report.header)
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


def convert_threat_actor(threat_actor, env):
    threat_actor_instance = create_basic_object("threat-actor", threat_actor, env)
    process_description_and_short_description(threat_actor_instance, threat_actor)
    new_env = env.newEnv(timestamp=threat_actor_instance["created"])
    new_env.add_to_env(created_by_ref=process_information_source(threat_actor.information_source, threat_actor_instance, new_env))
    # process information source before any relationships
    if threat_actor.identity is not None:
        if threat_actor.identity.id_:
            info("Threat Actor identity %s being used as basis of attributed-to relationship", 701, threat_actor.identity.id_)
        handle_relationship_to_objs([threat_actor.identity], threat_actor_instance["id"], new_env, "attributed-to")
    if threat_actor.title is not None:
        info("Threat Actor %s title is used for name property", 717, threat_actor.id_)
        threat_actor_instance["name"] = threat_actor.title
    elif threat_actor.identity.name:
        threat_actor_instance["name"] = threat_actor.identity.name
    elif isinstance(threat_actor.identity, CIQIdentity3_0Instance):
        aliases = convert_party_name(threat_actor.identity._specification.party_name, threat_actor_instance, False)
        if aliases and get_option_value("spec_version") == "2.1":
            threat_actor_instance["aliases"] = aliases
    if threat_actor.intended_effects is not None:
        threat_actor_instance["goals"] = list()
        for g in threat_actor.intended_effects:
            threat_actor_instance["goals"].append(text_type(g.value))
    spec_version = get_option_value("spec_version")
    convert_controlled_vocabs_to_open_vocabs(threat_actor_instance,
                                             "labels" if spec_version == "2.0" else "threat_actor_types",
                                             threat_actor.types,
                                             THREAT_ACTOR_LABEL_MAP,
                                             False,
                                             required=spec_version == "2.0")
    handle_multiple_missing_statement_properties(threat_actor_instance, threat_actor.planning_and_operational_supports,
                                                 "planning_and_operational_support")
    if get_option_value("spec_version") == "2.0":
        handle_missing_confidence_property(threat_actor_instance, threat_actor.confidence)
    else:  # 2.1
        add_confidence_to_object(threat_actor_instance, threat_actor.confidence)

    if threat_actor.motivations:
        add_motivations_to_threat_actor(threat_actor_instance, threat_actor.motivations)

    convert_controlled_vocabs_to_open_vocabs(threat_actor_instance, "sophistication", threat_actor.sophistications,
                                             THREAT_ACTOR_SOPHISTICATION_MAP, True)
    # handle relationships
    if threat_actor.observed_ttps is not None:
        handle_relationship_to_refs(threat_actor.observed_ttps, threat_actor_instance["id"], new_env, "uses")
    if threat_actor.associated_campaigns is not None:
        handle_relationship_from_refs(threat_actor.associated_campaigns, threat_actor_instance["id"], new_env, "attributed-to")
    if threat_actor.associated_actors:
        info("All 'associated actors' relationships of %s are assumed to not represent STIX 1.2 versioning", 710, threat_actor.id_)
        handle_relationship_to_refs(threat_actor.associated_actors, threat_actor_instance["id"], new_env, "related-to")

    finish_basic_object(threat_actor.id_, threat_actor_instance, env, threat_actor)
    return threat_actor_instance


# TTPs

_TTP_RELATIONSHIP_MAPPING = {
    ("malware", "malware", "Variant Of"): ("variant-of", True),
    ("malware", "identity", "Targets"): ("targets", True),
    ("attack-pattern", "identity", "Targets"): ("targets", True)
}


def determine_ttp_relationship_type_and_direction(source_type, target_type, relationship_name):
    if (source_type, target_type, relationship_name) in _TTP_RELATIONSHIP_MAPPING:
        return _TTP_RELATIONSHIP_MAPPING[(source_type, target_type, relationship_name)]
    else:
        return "related-to", True


def process_ttp_properties(sdo_instance, ttp, env, kill_chains_in_sdo=True):
    process_description_and_short_description(sdo_instance, ttp, True)
    handle_multiple_missing_statement_properties(sdo_instance, ttp.intended_effects, "intended_effect")
    if hasattr(ttp, "title"):
        if ("name" not in sdo_instance or sdo_instance["name"] is None):
            sdo_instance["name"] = ttp.title
        else:
            handle_missing_string_property(sdo_instance, "title", ttp.title, False)

    # only populate kill chain phases if that is a property of the sdo_instance type, as indicated by kill_chains_in_sdo
    if kill_chains_in_sdo and hasattr(ttp, "kill_chain_phases"):
        convert_kill_chains(ttp.kill_chain_phases, sdo_instance)
    env = env.newEnv(timestamp=sdo_instance["created"])
    ttp_created_by_ref = process_information_source(ttp.information_source, sdo_instance, env)
    env.add_to_env(created_by_ref=ttp_created_by_ref)
    if ttp.exploit_targets is not None:
        handle_relationship_to_refs(ttp.exploit_targets, sdo_instance["id"], env,
                                    "targets")
    if ttp.related_ttps:
        info("All 'related ttps' relationships of %s are assumed to not represent STIX 1.2 versioning", 710, ttp.id_)
        for rel in ttp.related_ttps:
            source_type = get_type_from_id(sdo_instance["id"])
            if rel.item.idref is None:
                target_type = get_type_from_id(rel.item.id_)
                verb, to_direction = determine_ttp_relationship_type_and_direction(source_type, target_type,
                                                                                   text_type(rel.relationship))
                handle_embedded_ref(rel, rel.item, rel.item.id_, env, verb, to_direction)
            else:
                target_id = rel.item.idref
                stix20_target_ids = get_id_value(target_id)
                if stix20_target_ids != []:
                    for id20 in stix20_target_ids:
                        target_type = get_type_from_id(id20)
                        verb, to_direction = determine_ttp_relationship_type_and_direction(source_type, target_type, text_type(rel.relationship))
                        handle_existing_ref(rel, id20, sdo_instance["id"], env, verb, to_direction)
                else:
                    handle_relationship_ref(rel, rel.item, sdo_instance["id"], env, "related-to", to_direction=True)
    if hasattr(ttp, "related_packages") and ttp.related_packages is not None:
        for p in ttp.related_packages:
            warn("Related_Packages type in %s not supported in STIX 2.x", 402, ttp.id_)


def convert_attack_pattern(ap, ttp, env, ttp_id_used):
    attack_Pattern_instance = create_basic_object("attack-pattern", ap, env, ttp.id_, not ttp_id_used)
    if ap.title is not None:
        attack_Pattern_instance["name"] = ap.title
    process_description_and_short_description(attack_Pattern_instance, ap)
    if ap.capec_id is not None:
        attack_Pattern_instance["external_references"] = [{"source_name": "capec", "external_id": ap.capec_id}]
    process_ttp_properties(attack_Pattern_instance, ttp, env)
    finish_basic_object(ttp.id_, attack_Pattern_instance, env, ap)
    return attack_Pattern_instance


def convert_malware_instance(mal, ttp, env, ttp_id_used):
    malware_instance_instance = create_basic_object("malware", mal, env, ttp.id_, not ttp_id_used)
    if get_option_value("spec_version") == "2.1":
        malware_instance_instance["is_family"] = False
        info("The is_family property of malware instance %s is assumed to be false", 728, malware_instance_instance["id"])
    # TODO: names?
    if mal.title is not None:
        malware_instance_instance["name"] = mal.title
    process_description_and_short_description(malware_instance_instance, mal)
    spec_version = get_option_value("spec_version")
    convert_controlled_vocabs_to_open_vocabs(malware_instance_instance,
                                             "labels" if spec_version == "2.0" else "malware_types",
                                             mal.types,
                                             MALWARE_LABELS_MAP,
                                             False,
                                             required=spec_version == "2.0")
    if mal.names is not None:
        for n in mal.names:
            if "name" not in malware_instance_instance:
                malware_instance_instance["name"] = text_type(n)
            else:
                # TODO: add to description?
                warn("Only one name for malware is allowed for %s in STIX 2.x - used %s, dropped %s",
                     508,
                     malware_instance_instance["id"],
                     malware_instance_instance["name"],
                     text_type(n))
    if isinstance(mal, MAECInstance):
        warn("MAEC content in %s cannot be represented in STIX 2.x", 426, ttp.id_)
    process_ttp_properties(malware_instance_instance, ttp, env)
    finish_basic_object(ttp.id_, malware_instance_instance, env, mal)
    return malware_instance_instance


def convert_behavior(behavior, ttp, env):
    resources_generated = []
    first_one = True
    if behavior.attack_patterns is not None:
        for ap in behavior.attack_patterns:
            new_obj = convert_attack_pattern(ap, ttp, env, first_one)
            env.bundle_instance["objects"].append(new_obj)
            resources_generated.append(new_obj)
            first_one = False
    if behavior.malware_instances is not None:
        for mal in behavior.malware_instances:
            new_obj = convert_malware_instance(mal, ttp, env, first_one)
            env.bundle_instance["objects"].append(new_obj)
            resources_generated.append(new_obj)
            first_one = False
    if behavior.exploits is not None:
        for e in behavior.exploits:
            warn("TTP/Behavior/Exploits/Exploit in %s not supported in STIX 2.x", 408, ttp.id_)
    return resources_generated


def convert_tool(tool, ttp, env, first_one):
    tool_instance = create_basic_object("tool", tool, env, ttp.id_, not first_one)
    if tool.name is not None:
        tool_instance["name"] = tool.name
        if tool.title is not None:
            handle_missing_string_property(tool_instance, "title", tool.title)
    elif tool.title is not None:
        tool_instance["name"] = tool.title
    process_description_and_short_description(tool_instance, tool)
    handle_missing_string_property(tool_instance, "vendor", tool.vendor)
    handle_missing_string_property(tool_instance, "service_pack", tool.service_pack)
    # TODO: add tool_specific_data to descriptor <-- Not Implemented!

    if tool.tool_hashes is not None:
        # FIXME: add tool_hashes to descriptor
        info("Tool Tool_Hashes in %s is not handled, yet.", 815, tool_instance["id"])

    # TODO: add tool_configuration to descriptor <-- Not Implemented!
    # TODO: add execution_environment to descriptor <-- Not Implemented!
    # TODO: add errors to descriptor <-- Not Implemented!
    # TODO: add compensation_model to descriptor <-- Not Implemented!
    spec_version = get_option_value("spec_version")
    convert_controlled_vocabs_to_open_vocabs(tool_instance,
                                             "labels" if spec_version == "2.0" else "tool_types",
                                             tool.type_,
                                             TOOL_LABELS_MAP,
                                             False,
                                             required=spec_version == "2.0")
    tool_instance["tool_version"] = tool.version
    process_ttp_properties(tool_instance, ttp, env)
    finish_basic_object(ttp.id_, tool_instance, env, tool)
    return tool_instance


def convert_infrastructure(infra, ttp, env, first_one):
    infrastructure_instance = create_basic_object("infrastructure", infra, env, parent_id=ttp.id_, id_used=not first_one)
    if infra.title is not None:
        infrastructure_instance["name"] = infra.title
    process_description_and_short_description(infrastructure_instance, infra)
    convert_controlled_vocabs_to_open_vocabs(infrastructure_instance,
                                             "labels" if get_option_value("spec_version") == "2.0" else "infrastructure_types",
                                             infra.types,
                                             INFRASTRUCTURE_LABELS_MAP,
                                             False,
                                             required=False)
    info("No 'first_seen' data on %s - using timestamp", 904, infra.id_ if infra.id_ else ttp.id_)
    infrastructure_instance["first_seen"] = convert_timestamp_of_stix_object(infra, infrastructure_instance["created"])
    if infra.observable_characterization is not None:
        handle_observable_information_list(infra.observable_characterization, infrastructure_instance["id"], env, "consists-of")
    process_ttp_properties(infrastructure_instance, ttp, env)
    finish_basic_object(ttp.id_, infrastructure_instance, env, infra)
    return infrastructure_instance


def convert_resources(resources, ttp, env, generated_ttps):
    resources_generated = []
    first_one = (generated_ttps == [])
    if resources.tools is not None:
        for t in resources.tools:
            new_obj = convert_tool(t, ttp, env, first_one)
            env.bundle_instance["objects"].append(new_obj)
            resources_generated.append(new_obj)
            first_one = False
    if resources.infrastructure is not None:
        if get_option_value("infrastructure") or get_option_value("spec_version") == "2.1":
            new_obj = convert_infrastructure(resources.infrastructure, ttp, env, first_one)
            env.bundle_instance["objects"].append(new_obj)
            resources_generated.append(new_obj)
            first_one = False
        else:
            warn("Infrastructure in %s not part of STIX 2.0", 409, ttp.id_ or "")
    return resources_generated


def convert_identity_for_victim_target(identity, ttp, env, ttp_generated):
    if identity:
        identity_instance = convert_identity(identity, env, parent_id=ttp.id_ if not ttp_generated else None)
    else:
        identity_instance = create_basic_object("identity", None, env, ttp.id_)
        identity_instance["identity_class"] = "unknown"
    env.bundle_instance["objects"].append(identity_instance)
    process_ttp_properties(identity_instance, ttp, env, False)
    finish_basic_object(ttp.id_, identity_instance, identity, env, identity_instance["id"])
    return identity_instance


def convert_victim_targeting(victim_targeting, ttp, env, ttps_generated):
    identity_instance = convert_identity_for_victim_target(victim_targeting.identity, ttp, env, ttps_generated)
    info("%s generated an identity associated with a victim", 713, ttp.id_)
    if victim_targeting.targeted_systems:
        handle_missing_string_property(identity_instance, "targeted_systems", victim_targeting.targeted_systems,
                                       True)
    if victim_targeting.targeted_information:
        handle_missing_string_property(identity_instance, "targeted_information",
                                       victim_targeting.targeted_information, True)
    if hasattr(victim_targeting, "technical_details") and victim_targeting.targeted_technical_details is not None:
        handle_missing_string_property(identity_instance, "technical_details",
                                       victim_targeting.targeted_technical_details, True)
    if ttps_generated:
        for generated_ttp in ttps_generated:
            env.bundle_instance["relationships"].append(
                create_relationship(generated_ttp["id"], identity_instance["id"], env, "targets"))
        # the relationships has been created, so its not necessary to propagate it up
    return identity_instance
    # nothing generated
    # return None


def convert_ttp(ttp, env):
    if hasattr(ttp, "timestamp") and ttp.timestamp:
        new_env = env.newEnv(timestamp=convert_timestamp_of_stix_object(ttp, env.timestamp, True))
    else:
        new_env = env
    generated_objs = []
    if ttp.behavior is not None:
        generated_objs.extend(convert_behavior(ttp.behavior, ttp, new_env))
    if ttp.resources is not None:
        generated_objs.extend(convert_resources(ttp.resources, ttp, new_env, generated_objs))
    if hasattr(ttp, "kill_chain_phases") and ttp.kill_chain_phases is not None:
        for phase in ttp.kill_chain_phases:
            warn("Kill Chains type in %s not supported in STIX 2.x", 413, ttp.id_)
    if ttp.victim_targeting is not None:
        victim_target = convert_victim_targeting(ttp.victim_targeting, ttp, new_env, generated_objs)
        if not victim_target:
            warn("Victim Target in %s did not generate any STIX 2.x object", 414, ttp.id_)
        else:
            generated_objs.append(victim_target)
    # victims weren't involved, check existing list
    if not generated_objs and ttp.id_ is not None:
        error("TTP %s did not generate any STIX 2.x object", 415, ttp.id_)
    return generated_objs


# package


def handle_embedded_object(obj, env):
    new20 = None
    new20s = None
    if exists_id_key(obj.id_):
        # nested embedding
        return []
    # campaigns
    if isinstance(obj, Campaign):
        new20 = convert_campaign(obj, env)
        env.bundle_instance["objects"].append(new20)
    # coas
    elif isinstance(obj, CourseOfAction):
        new20 = convert_course_of_action(obj, env)
        env.bundle_instance["objects"].append(new20)
    # exploit-targets
    elif isinstance(obj, ExploitTarget):
        new20s = convert_exploit_target(obj, env)
    # identities
    elif isinstance(obj, Identity) or isinstance(obj, CIQIdentity3_0Instance):
        new20 = convert_identity(obj, env)
        env.bundle_instance["objects"].append(new20)
    # incidents
    elif get_option_value("incidents") and isinstance(obj, Incident):
        new20 = convert_incident(obj, env)
        env.bundle_instance["objects"].append(new20)
    # indicators
    elif isinstance(obj, Indicator):
        new20 = convert_indicator(obj, env)
        env.bundle_instance["indicators"].append(new20)
    # observables
    elif isinstance(obj, Observable):
        new20 = convert_observed_data(obj, env)
        env.bundle_instance["observed_data"].append(new20)
    # reports
    elif stix.__version__ >= "1.2.0.0" and isinstance(obj, Report):
        new20 = convert_report(obj, env)
        env.bundle_instance["reports"].append(new20)
    # threat actors
    elif isinstance(obj, ThreatActor):
        new20 = convert_threat_actor(obj, env)
        env.bundle_instance["objects"].append(new20)
    # ttps
    elif isinstance(obj, TTP):
        new20s = convert_ttp(obj, env)
    if new20:
        return [new20]
    elif new20s:
        return new20s
    else:
        warn("No STIX 2.x object generated from embedded object %s", 416, identifying_info(obj))
        return []


def initialize_bundle_lists(bundle_instance):
    bundle_instance["relationships"] = []
    bundle_instance["indicators"] = []
    bundle_instance["reports"] = []
    bundle_instance["observed_data"] = []
    bundle_instance["objects"] = []


def finalize_bundle(env):
    bundle_instance = env.bundle_instance
    if _KILL_CHAINS_PHASES != {}:
        for ind20 in bundle_instance["indicators"]:
            if "kill_chain_phases" in ind20:
                fixed_kill_chain_phases = []
                for kcp in ind20["kill_chain_phases"]:
                    if isinstance(kcp, string_types):
                        # noinspection PyBroadException
                        try:
                            kill_chain_phase_in_20 = _KILL_CHAINS_PHASES[kcp]
                            fixed_kill_chain_phases.append(kill_chain_phase_in_20)
                        except KeyError:
                            error("Dangling kill chain phase id in indicator %s", 607, ind20["id"])
                    else:
                        fixed_kill_chain_phases.append(kcp)
                ind20["kill_chain_phases"] = fixed_kill_chain_phases
    # ttps

    fix_relationships(env)

    if get_option_value("spec_version") == "2.0":
        fix_cybox_relationships(bundle_instance["observed_data"])
        resolve_object_references20(bundle_instance["observed_data"])
    else:
        fix_sco_embedded_refs(bundle_instance["objects"])
        resolve_object_references21(bundle_instance["objects"])

    if stix.__version__ >= "1.2.0.0":
        add_relationships_to_reports(bundle_instance)

    # source and target_ref are taken care of in fix_relationships(...)
    _TO_MAP = ("id", "idref", "created_by_ref", "external_references",
               "marking_ref", "object_marking_refs", "object_refs",
               "sighting_of_ref", "observed_data_refs", "where_sighted_refs",
               convert_to_custom_name("link_refs"))

    _LOOK_UP = ("", u"", [], None, dict())

    to_remove = []

    if "indicators" in bundle_instance:
        interatively_resolve_placeholder_refs()
        for ind in bundle_instance["indicators"]:
            if "pattern" in ind:
                pattern = ind["pattern"]
                if isinstance(pattern, string_types):
                    continue
                final_pattern = fix_pattern(pattern)
                if final_pattern:
                    if final_pattern.contains_placeholder():
                        error("At least one PLACEHOLDER idref was not resolved in %s", 205, ind["id"])
                    if final_pattern.contains_unconverted_term():
                        error("At least one observable could not be converted in %s", 206, ind["id"])
                    if (isinstance(final_pattern, ComparisonExpressionForElevator) or
                            isinstance(final_pattern, UnconvertedTerm)):
                        ind["pattern"] = "[%s]" % final_pattern
                    elif isinstance(final_pattern, ParentheticalExpressionForElevator):
                        result = final_pattern.expression.partition_according_to_object_path()
                        if isinstance(result, CompoundObservationExpressionForElevator):
                            ind["pattern"] = "%s" % result
                        else:
                            ind["pattern"] = "[%s]" % result
                    else:
                        ind["pattern"] = text_type(final_pattern.partition_according_to_object_path())

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
            # Used to remove TLP markings from final bundle.
            if "definition_type" in value and value["definition_type"] == "tlp":
                to_remove.append(list(path))
            continue

        if last_field in _TO_MAP or iter_field in _TO_MAP:
            if is_stix1x_id(value) and exists_id_key(value):
                stix20_id = get_id_value(value)

                if stix20_id[0] is None:
                    warn("STIX 1.X ID: %s was not mapped to STIX 2.x ID", 603, value)
                    continue

                operation_on_path(bundle_instance, path, stix20_id[0])
                info("Found STIX 1.X ID: %s replaced by %s", 702, value, stix20_id[0])
            elif is_stix1x_id(value) and not exists_id_key(value):
                warn("1.X ID: %s was not mapped to STIX 2.x ID", 603, value)

    for item in reversed(to_remove):
        operation_on_path(bundle_instance, item, "", op=2)

    if "objects" in bundle_instance:
        remove_pattern_objects(bundle_instance)
    else:
        error("EMPTY BUNDLE -- No objects created from 1.x input document!", 208)


def get_identity_from_package(information_source, env):
    if information_source:
        if information_source.identity is not None:
            return get_identity_ref(information_source.identity, env, from_package=True)
        if information_source.contributing_sources is not None:
            if information_source.contributing_sources.source is not None:
                sources = information_source.contributing_sources.source

                if len(sources) > 1:
                    warn("Only one identity allowed - using first one.", 510)

                for source in sources:
                    if source.identity is not None:
                        return get_identity_ref(source.identity, env, from_package=True)
    return None


def convert_package(stix_package, env):
    bundle_instance = {"type": "bundle"}
    bundle_instance["id"] = generate_stix2x_id("bundle", stix_package.id_)
    env.bundle_instance = bundle_instance
    initialize_bundle_lists(bundle_instance)

    if get_option_value("spec_version") == "2.0":
        bundle_instance["spec_version"] = "2.0"

    if hasattr(stix_package, "timestamp") and stix_package.timestamp:
        env.timestamp = stix_package.timestamp
    elif get_option_value("default_timestamp"):
        env.timestamp = datetime.strptime(get_option_value("default_timestamp"), "%Y-%m-%dT%H:%M:%S.%fZ")
    else:
        # timestamp not given on the command line
        env.timestamp = strftime_with_appropriate_fractional_seconds(datetime.now(), True)
        warn("Timestamp not available for stix 1x package, using current time", 905)

    # created_by_idref from the command line is used instead of the one from the package, if given
    if not env.created_by_ref and hasattr(stix_package.stix_header, "information_source"):
        env.created_by_ref = get_identity_from_package(stix_package.stix_header.information_source, env)

    # Markings are processed in the beginning for handling later for each SDO.
    for marking_specification in navigator.iterwalk(stix_package):
        if isinstance(marking_specification, MarkingSpecification):
            bundle_instance["objects"].extend(convert_marking_specification(marking_specification, env))

    # do observables first, especially before indicators!

    # kill chains
    if stix_package.ttps and stix_package.ttps.kill_chains:
        for kc in stix_package.ttps.kill_chains:
            process_kill_chain(kc)

    # observables
    if stix_package.observables is not None:
        for o_d in stix_package.observables:
            o_d2x = convert_observed_data(o_d, env)
            if o_d2x:
                bundle_instance["observed_data"].append(o_d2x)

    # campaigns
    if stix_package.campaigns:
        for camp in stix_package.campaigns:
            camp2x = convert_campaign(camp, env)
            bundle_instance["objects"].append(camp2x)

    # coas
    if stix_package.courses_of_action:
        for coa in stix_package.courses_of_action:
            coa2x = convert_course_of_action(coa, env)
            bundle_instance["objects"].append(coa2x)

    # exploit-targets
    if stix_package.exploit_targets:
        for et in stix_package.exploit_targets:
            convert_exploit_target(et, env)

    # incidents
    # TODO: error message for ignored incidents?
    if get_option_value("incidents"):
        if stix_package.incidents:
            for i in stix_package.incidents:
                i2x = convert_incident(i, env)
                bundle_instance["objects"].append(i2x)

    # indicators
    if stix_package.indicators:
        for i in stix_package.indicators:
            i2x = convert_indicator(i, env)
            bundle_instance["indicators"].append(i2x)

    # reports
    if stix.__version__ >= "1.2.0.0" and stix_package.reports:
        for report in stix_package.reports:
            report2x = convert_report(report, env)
            bundle_instance["reports"].append(report2x)

    # threat actors
    if stix_package.threat_actors:
        for ta in stix_package.threat_actors:
            ta2x = convert_threat_actor(ta, env)
            bundle_instance["objects"].append(ta2x)

    # ttps
    if stix_package.ttps:
        for ttp in stix_package.ttps.ttp:
            convert_ttp(ttp, env)

    finalize_bundle(env)
    return bundle_instance
