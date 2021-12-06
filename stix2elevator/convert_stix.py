# Standard Library
from datetime import datetime

# external
from cybox.core import Observable
from lxml import etree
import pycountry
import stix
from stix.campaign import Campaign
from stix.coa import CourseOfAction
from stix.common.identity import Identity
from stix.common.kill_chains import KillChainPhase, KillChainPhaseReference
from stix.common.kill_chains.lmco import LMCO_KILL_CHAIN_PHASES
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

try:
    # external
    from stix_edh.isa_markings import ISAMarkings
    from stix_edh.isa_markings_assertions import ISAMarkingsAssertion
    _acs_import = True
except ImportError:
    _acs_import = False

# external
from stixmarx import navigator

# internal
from stix2elevator.confidence import convert_confidence
from stix2elevator.convert_cybox import (
    convert_cybox_object20, convert_cybox_object21, embedded_property_ref_name,
    fix_cybox_relationships, fix_sco_embedded_refs,
    resolve_object_references20, resolve_object_references21
)
from stix2elevator.convert_pattern import (
    BooleanExpressionForElevator, ComparisonExpressionForElevator,
    CompoundObservationExpressionForElevator,
    ParentheticalExpressionForElevator, UnconvertedTerm,
    add_to_observable_mappings, add_to_pattern_cache,
    convert_indicator_to_pattern, convert_observable_list_to_pattern,
    convert_observable_to_pattern, create_boolean_expression, fix_pattern,
    get_obs_from_mapping, id_in_observable_mappings,
    interatively_resolve_placeholder_refs, remove_pattern_objects
)
from stix2elevator.convert_to_acs import convert_edh_marking_to_acs_marking
from stix2elevator.ids import (
    add_id_of_obs_in_characterizations, add_id_value, add_object_id_value,
    exists_id_key, exists_ids_with_no_1x_object, generate_stix2x_id,
    get_id_value, get_id_values, get_type_from_id, is_stix1x_id, record_ids
)
from stix2elevator.missing_policy import (
    check_for_missing_policy, convert_to_custom_name,
    determine_container_for_missing_properties, fill_in_extension_properties,
    handle_missing_confidence_property, handle_missing_statement_properties,
    handle_missing_string_property, handle_missing_timestamp_property,
    handle_missing_tool_property, handle_multiple_missing_statement_properties
)
from stix2elevator.options import error, get_option_value, info, warn
from stix2elevator.utils import (
    add_label, add_marking_map_entry, apply_ais_markings,
    check_map_1x_markings_to_2x, convert_controlled_vocabs_to_open_vocabs,
    convert_timestamp_of_stix_object, convert_timestamp_to_string,
    convert_to_stix_literal, identifying_info, iterpath,
    lookup_marking_reference, map_1x_markings_to_2x, map_vocabs_to_label,
    operation_on_path, set_tlp_reference,
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

_INTENDED_EFFECTS_LITERAL_MAPPING = {
    "Theft - Intellectual Property": "intellectual-property-theft",
    "Theft - Credential Theft": "credential-theft",
    "Theft - Identity Theft": "identity-theft",
    "Theft - Theft of Proprietary Information": "proprietary-information-theft"}


# collect kill chains
_KILL_CHAINS_PHASES = {}


def clear_kill_chains_phases_mapping():
    global _KILL_CHAINS_PHASES
    _KILL_CHAINS_PHASES = {}


# Identifies the Lockheed Martin Kill Chain ids
_LMCO_IDS = {
    "af3e707f-2fb9-49e5-8c37-14026ca0a5ff",
    "786ca8f9-2d9a-4213-b38e-399af4a2e5d6",
    "d6dc32b9-2538-4951-8733-3cb9ef1daae2",
    "e1e4e3f7-be3b-4b39-b80a-a593cfd99a4f",
    "f706e4e7-53d8-44ef-967f-81535c9db7d0",
    "79a0e041-9d5f-49bb-ada4-8322622b162d",
    "445b4827-3cca-42bd-8421-f2e947133c16",
    "af1016d6-a744-4ed7-ac91-00fe2272185a",
}


def check_lmco(kcp):
    lmco_names = {
        "LMCO",
        "LM Cyber Kill Chain",
        "Actions on Objectives",
        "Command and Control",
        "Installation",
        "Exploitation",
        "Delivery",
        "Weaponization",
        "Reconnaissance",
    }

    is_lmco_kcp = False

    if kcp in LMCO_KILL_CHAIN_PHASES:
        is_lmco_kcp = True
    elif kcp.phase_id and any(kcp.phase_id.endswith(x) for x in _LMCO_IDS):
        is_lmco_kcp = True
    elif kcp.name and any(kcp.name == x for x in lmco_names):
        is_lmco_kcp = True

    return is_lmco_kcp


def lmco_id_to_name(phase_id):
    for lmco_id in _LMCO_IDS:
        if phase_id.endswith(lmco_id):
            for kcp in LMCO_KILL_CHAIN_PHASES:
                if kcp.phase_id.endswith(lmco_id):
                    return convert_to_stix_literal(kcp.name)
    return phase_id


def process_kill_chain(kc):

    for kcp in kc.kill_chain_phases:
        # Use object itself as key.
        if check_lmco(kcp):
            kcp_name = convert_to_stix_literal(kcp.name)
            if kcp.phase_id:
                _KILL_CHAINS_PHASES[kcp.phase_id] = {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": kcp_name}
            else:
                _KILL_CHAINS_PHASES[kcp] = {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": kcp_name}
        else:
            if kcp.phase_id:
                _KILL_CHAINS_PHASES[kcp.phase_id] = {"kill_chain_name": kc.name, "phase_name": kcp.name}
            else:
                _KILL_CHAINS_PHASES[kcp] = {"kill_chain_name": kc.name, "phase_name": kcp.name}


# collect locations

_LOCATIONS = {}
_UNFINISHED_OBJS = []


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


def clear_unfinished_marked_objects():
    global _UNFINISHED_OBJS
    _UNFINISHED_OBJS = []


def add_unfinished_marked_object(stix2_object):
    global _UNFINISHED_OBJS
    _UNFINISHED_OBJS.append(stix2_object)


def get_unfinished_marked_objects():
    return _UNFINISHED_OBJS

#
# identities
#


def get_identity(identity, env, created_by_ref_source, temp_marking_id=None):
    if not env.get_identity_called:
        # On some occasions excessive recursion may add identity objects that are not needed
        new_env = env.newEnv(get_identity_called=True)
        ident20 = convert_identity(identity, new_env, created_by_ref_source, temp_marking_id=temp_marking_id)
        env.bundle_instance["objects"].append(ident20)
        return ident20["id"]


def get_identity_ref(identity, env, created_by_ref_source, temp_marking_id=None):
    if identity.idref is not None:
        # fix reference later
        return identity.idref
    else:
        ident20 = convert_identity(
            identity, env, created_by_ref_source,
            temp_marking_id=temp_marking_id)
        env.bundle_instance["objects"].append(ident20)
        return ident20["id"]


def handle_missing_properties_of_information_source(so, information_source):
    # handle missing properties
    container, extension_definition_id = determine_container_for_missing_properties("information_source", so)

    if container is not None:
        if information_source.roles:
            handle_missing_string_property(container, "information_source_roles", information_source.roles, so["id"],
                                           True, is_literal=True)
        if information_source.tools:
            for tool in information_source.tools:
                handle_missing_tool_property(container, tool)
        fill_in_extension_properties(so, container, extension_definition_id)


def process_information_source(information_source, so, env, temp_marking_id=None):
    if information_source:
        if information_source.identity is not None:
            if information_source.identity.idref:
                so["created_by_ref"] = information_source.identity.idref
            else:
                so["created_by_ref"] = get_identity(information_source.identity,
                                                    env,
                                                    "this_identity",
                                                    temp_marking_id)
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
            handle_missing_properties_of_information_source(so, information_source)

    else:
        so["created_by_ref"] = env.created_by_ref
    return so["created_by_ref"]


def convert_to_open_vocabs(stix2x_obj, stix2x_property_name, value, vocab_mapping):
    stix2x_obj[stix2x_property_name].append(map_vocabs_to_label(value, vocab_mapping))


def process_structured_text_list(text_list):
    full_text = ""
    for text_obj in text_list.sorted:
        if text_obj.value:
            full_text += text_obj.value
    return full_text


def process_description_and_short_description(so, entity, parent_info=False):
    if hasattr(entity, "descriptions") and entity.descriptions is not None:
        description_as_text = str(process_structured_text_list(entity.descriptions))
        if description_as_text:
            if parent_info and so["description"]:
                so["description"] += "\nPARENT_DESCRIPTION: \n" + description_as_text
            else:
                so["description"] += description_as_text

    # could be short_description or description (in STIX 1.1.1)
    # seems like in STIX 2.x - description and descriptionS are both populated with the same content
    elif hasattr(entity, "description") and entity.description is not None:
        so["description"] += str(entity.description.value)
    if hasattr(entity, "short_description") and entity.short_description is not None:
        short_description_as_text = str(entity.short_description)
        if short_description_as_text:
            info("The Short_Description property in %s is not supported in STIX 2.x.", 310, so["id"])
            if not check_for_missing_policy("ignore"):
                info("The text was appended to the description property of %s", 301, so["id"])
                if parent_info and so["description"]:
                    so["description"] += "\nPARENT_SHORT_DESCRIPTION: \n" + short_description_as_text
                else:
                    so["description"] += short_description_as_text
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
    if stix2x_type != "marking-definition":
        # marking definitions cannot be changed, so they have no modified property
        instance["modified"] = timestamp
    instance["description"] = ""
    instance["external_references"] = []
    return instance


def convert_marking_specification(marking_specification, env, stix1x_id, isa_marking, isa_marking_assertions):
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
            process_information_source(marking_specification.information_source,
                                       marking_definition_instance,
                                       env)

            if isinstance(marking_structure, TLPMarkingStructure):
                if marking_structure.color is not None:
                    color = str(marking_structure.color).lower()
                    set_tlp_reference(marking_definition_instance, color, "id")

            if isinstance(marking_structure, TLPMarkingStructure):
                marking_definition_instance["definition_type"] = "tlp"
                marking_definition_instance["created"] = "2017-01-20T00:00:00.000Z"
                definition = {}
                if marking_structure.color is not None:
                    definition["tlp"] = str(marking_structure.color).lower()
                marking_definition_instance["definition"] = definition
            elif isinstance(marking_structure, TermsOfUseMarkingStructure):
                marking_definition_instance["definition_type"] = "statement"
                definition = {}
                if marking_structure.terms_of_use is not None:
                    definition["statement"] = str(marking_structure.terms_of_use)
                marking_definition_instance["definition"] = definition
            elif isinstance(marking_structure, SimpleMarkingStructure):
                marking_definition_instance["definition_type"] = "statement"
                definition = {}
                if marking_structure.statement is not None:
                    definition["statement"] = str(marking_structure.statement)
                marking_definition_instance["definition"] = definition
            elif isinstance(marking_structure, AISMarkingStructure):
                marking_definition_instance["definition_type"] = "ais"
                definition = {}

                if marking_structure.is_proprietary is not None:
                    consent_marking = str(marking_structure.is_proprietary.ais_consent.consent).lower()
                    if consent_marking != "everyone":
                        warn("cisa-proprietary is only permitted when ais-consent is everyone, so it has been dropped. See %s", 637, stix1x_id)
                        definition["is_proprietary"] = "false"
                    else:
                        definition["is_proprietary"] = "true"
                    if (marking_structure.is_proprietary.ais_consent is not None and
                            marking_structure.is_proprietary.ais_consent.consent is not None):
                        definition["consent"] = consent_marking
                        consent_label = "ais-consent-" + definition["consent"]
                    if (marking_structure.is_proprietary.tlp_marking is not None and
                            marking_structure.is_proprietary.tlp_marking.color is not None):
                        definition["tlp"] = str(marking_structure.is_proprietary.tlp_marking.color).lower()
                        set_tlp_reference(marking_definition_instance, definition["tlp"], "marking_ref")
                    if definition["is_proprietary"] == "true":
                        consent_label = consent_label + "-cisa-proprietary"
                    add_label(marking_definition_instance, consent_label)
                elif marking_structure.not_proprietary is not None:
                    consent_marking = str(marking_structure.not_proprietary.ais_consent.consent).lower()
                    definition["is_proprietary"] = "false"
                    if (marking_structure.not_proprietary.ais_consent is not None and
                            marking_structure.not_proprietary.ais_consent.consent is not None):
                        definition["consent"] = consent_marking
                        consent_label = "ais-consent-" + definition["consent"]
                        add_label(marking_definition_instance, consent_label)
                    if (marking_structure.not_proprietary.tlp_marking is not None and
                            marking_structure.not_proprietary.tlp_marking.color is not None):
                        definition["tlp"] = str(marking_structure.not_proprietary.tlp_marking.color).lower()
                        set_tlp_reference(marking_definition_instance, definition["tlp"], "marking_ref")
                marking_definition_instance["definition"] = definition
            elif _acs_import and isinstance(marking_structure, ISAMarkings):
                isa_marking = marking_structure
            elif _acs_import and isinstance(marking_structure, ISAMarkingsAssertion):
                isa_marking_assertions.append(marking_structure)

            else:
                if marking_structure.__class__.__name__ in get_option_value("markings_allowed"):
                    warn("Could not resolve Marking Structure %s", 425, identifying_info(marking_structure))
                else:
                    error("Could not resolve Marking Structure %s", 425, identifying_info(marking_structure))
                    raise NameError("Could not resolve Marking Structure %s" % identifying_info(marking_structure))

            if "definition_type" in marking_definition_instance:
                val = add_marking_map_entry(marking_structure, marking_definition_instance)
                if val is not None and not isinstance(val, MarkingStructure):
                    info("Found same marking structure %s, using %s", 625, identifying_info(marking_specification), val)
                else:
                    info("Created Marking Structure for %s", 212, identifying_info(marking_structure))
                    finish_basic_object(marking_specification.id_, marking_definition_instance, env, marking_structure)
                    return_obj.append(marking_definition_instance)

        if not _acs_import and get_option_value("acs"):
            raise ImportError("stix_edh library is required for ACS data markings")
        else:
            if isa_marking_assertions:
                if isa_marking:
                    if get_option_value("acs"):
                        for m in isa_marking_assertions:
                            marking_definition_instance = create_basic_object("marking-definition", m, env)
                            convert_edh_marking_to_acs_marking(marking_definition_instance, isa_marking, m)
                            val = add_marking_map_entry(m, marking_definition_instance)
                            if val is not None and not isinstance(val, MarkingStructure):
                                info("Found same marking structure %s, using %s", 625, identifying_info(m), val)
                            else:
                                info("Created Marking Structure for %s", 212, identifying_info(m))
                                finish_basic_object(marking_specification.id_, marking_definition_instance, env, marking_structure)
                                warn("Used extensions for ACS data markings. See %s", 319, marking_definition_instance["id"])
                                return_obj.append(marking_definition_instance)
                    else:
                        if get_option_value("spec_version") == "2.1":
                            warn("ACS data markings only supported when --acs option is used. See %s", 436, isa_marking.identifier)
                        else:
                            warn("ACS data markings cannot be supported in version 2.0.", 217)
    return return_obj, isa_marking


def get_marking_specifications(stix1_object):
    container = get_option_value("marking_container")
    return container.get_markings(stix1_object)


def get_object_marking_refs(stix1_marking_specifications):
    object_marking_refs = []
    for marking_specification in stix1_marking_specifications or []:
        for marking_structure in marking_specification.marking_structures:
            stix2x_marking = map_1x_markings_to_2x(marking_structure)
            if isinstance(stix2x_marking, dict):
                object_marking_refs.append(stix2x_marking["id"])
            else:
                object_marking_refs.append(stix2x_marking)
    return object_marking_refs


def create_marking_union(*stix1_objects):
    union_object_marking_refs = []
    for stix1_object in stix1_objects:
        stix2_marking_refs = get_object_marking_refs(get_marking_specifications(stix1_object))
        union_object_marking_refs.extend(stix2_marking_refs)
    return list(set(union_object_marking_refs))


def finish_markings(instance, env, marking_specifications, temp_marking_id=None):
    object_marking_refs = []
    isa_marking = None
    isa_marking_assertions = []
    for marking_specification in marking_specifications:
        for marking_structure in marking_specification.marking_structures:
            if not check_map_1x_markings_to_2x(marking_structure):
                stix2x_markings, ignore = convert_marking_specification(marking_specification,
                                                                        env,
                                                                        instance["id"],
                                                                        isa_marking,
                                                                        isa_marking_assertions)
                for m in stix2x_markings:
                    if m["definition_type"] == "ais":
                        apply_ais_markings(instance, m)
                        object_marking_refs.append(m["marking_ref"])
                    elif instance["id"] != m["id"] and m["id"] not in object_marking_refs:
                        object_marking_refs.append(m["id"])
                        env.bundle_instance["objects"].append(m)
                    else:
                        env.bundle_instance["objects"].append(m)
            else:
                stix2x_marking = map_1x_markings_to_2x(marking_structure)
                if (instance["id"] != stix2x_marking["id"] and
                        stix2x_marking["id"] not in object_marking_refs):
                    if "definition_type" in stix2x_marking and stix2x_marking["definition_type"] == "ais":
                        apply_ais_markings(instance, stix2x_marking)
                        object_marking_refs.append(stix2x_marking["marking_ref"])
                    else:
                        object_marking_refs.append(stix2x_marking["id"])
                elif temp_marking_id:
                    object_marking_refs.append(temp_marking_id)

    if env.created_by_ref and instance["id"] != env.created_by_ref:
        instance["created_by_ref"] = env.created_by_ref

    if object_marking_refs:
        instance["object_marking_refs"] = object_marking_refs


def finish_basic_object(old_id, instance, env, stix1x_obj, temp_marking_id=None):
    if old_id is not None:
        record_ids(old_id, instance["id"])
    if hasattr(stix1x_obj, "related_packages") and stix1x_obj.related_packages is not None:
        for p in stix1x_obj.related_packages:
            warn("Related_Packages type in %s not supported in STIX 2.x", 402, stix1x_obj.id_)

    # Attach markings to SDO if present.
    marking_specifications = get_marking_specifications(stix1x_obj)
    finish_markings(instance, env, marking_specifications, temp_marking_id=None)


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
            sighting_instance["where_sighted_refs"] = [get_identity_ref(information_source.identity, env, created_by_ref_source="this_identity")]
            if information_source.description:
                process_description_and_short_description(sighting_instance, sighting)
            if information_source.references:
                for ref in information_source.references:
                    sighting_instance["external_references"].append({"url": ref})
            if information_source.roles:
                handle_missing_string_property(sighting_instance, "information_source_roles", information_source.roles,
                                               True, is_literal=True)
            if information_source.tools:
                for tool in information_source.tools:
                    handle_missing_tool_property(sighting_instance, tool)


def handle_sighting(sighting, sighted_object_id, env):
    sighting_instance = create_basic_object("sighting", sighting, env)
    sighting_instance["count"] = 1
    sighting_instance["created_by_ref"] = env.created_by_ref
    sighting_instance["sighting_of_ref"] = sighted_object_id
    process_description_and_short_description(sighting_instance, sighting)
    if sighting.related_observables:
        sighting_instance["observed_data_refs"] = handle_sightings_observables(sighting.related_observables, env)
    if sighting.source:
        process_information_source_for_sighting(sighting, sighting_instance, env)
    # assumption is that the observation is a singular, not a summary of observations
    sighting_instance["summary"] = False
    finish_basic_object(None, sighting_instance, env, sighting)
    return sighting_instance


# Relationships


def finish_markings_for_relationship(instance, marking_refs, temp_marking_id=None):
    object_marking_refs = []
    for marking_ref in marking_refs:
        stix2x_marking = lookup_marking_reference(marking_ref)
        if stix2x_marking:
            if (instance["id"] != stix2x_marking["id"] and
                    stix2x_marking["id"] not in object_marking_refs):
                if "definition_type" in stix2x_marking and stix2x_marking["definition_type"] == "ais":
                    apply_ais_markings(instance, stix2x_marking)
                    object_marking_refs.append(stix2x_marking["marking_ref"])
                else:
                    object_marking_refs.append(stix2x_marking["id"])
            elif temp_marking_id:
                object_marking_refs.append(temp_marking_id)
        else:
            object_marking_refs.append(marking_ref)
    if object_marking_refs:
        instance["object_marking_refs"] = object_marking_refs


def create_relationship(source_ref, target_ref, env, verb, rel_obj=None, marking_refs=None):
    relationship_instance = create_basic_object("relationship", rel_obj, env)
    relationship_instance["source_ref"] = source_ref
    relationship_instance["target_ref"] = target_ref
    relationship_instance["relationship_type"] = verb
    if env.created_by_ref:
        relationship_instance["created_by_ref"] = env.created_by_ref
    if rel_obj is not None and hasattr(rel_obj, "relationship") and rel_obj.relationship is not None:
        relationship_instance["description"] = rel_obj.relationship.value
    if marking_refs:
        finish_markings_for_relationship(relationship_instance, marking_refs)
        # double check in finalize_bundle
        add_unfinished_marked_object(relationship_instance)
    return relationship_instance


# Creating and Linking up relationships  (three cases)
# 1.  The object is embedded - create the object, add it to the bundle, return to id so the relationship is complete
# 2.  an idref is given, and it has a corresponding 2.0 id, use it
# 3.  an idref is given, but it has NO corresponding 2.0 id, add 1.x id, and fix at the end in fix_relationships


def handle_relationship_to_objs(items, source_id, env, verb, marking_refs):
    for item in items:
        new_stix2_instances = handle_embedded_object(item, env)
        for new_2x in new_stix2_instances:
            env.bundle_instance["relationships"].append(
                create_relationship(source_id, new_2x["id"] if new_2x else None, env, verb, item, marking_refs)
            )


def handle_embedded_ref(stix1_relationship, item, ref1, env, default_verb, to_direction, marking_refs):
    new_stix2_instances = handle_embedded_object(item, env)
    for new_2x in new_stix2_instances:
        if to_direction:
            source_id = ref1
            target_id = new_2x["id"] if new_2x else None
        else:
            source_id = new_2x["id"] if new_2x else None
            target_id = ref1
        env.bundle_instance["relationships"].append(
            create_relationship(source_id, target_id, env,
                                determine_appropriate_verb(default_verb, target_id),
                                stix1_relationship,
                                marking_refs)
        )


def handle_existing_ref(stix1_relationship, ref1, ref2, env, default_verb, to_direction, marking_refs):
    source_id = ref2 if to_direction else ref1
    target_id = ref1 if to_direction else ref2
    env.bundle_instance["relationships"].append(
        create_relationship(source_id, target_id, env, default_verb, stix1_relationship, marking_refs=marking_refs)
    )


def handle_existing_refs(ref, id, env, verb, to_direction, marking_refs):
    for ref_id in get_id_value(ref.item.idref):
        handle_existing_ref(ref, ref_id, id, env, verb, to_direction, marking_refs)


def handle_relationship_ref(ref, item, id, env, default_verb, to_direction=True, marking_refs=None):
    if item.idref is None:
        handle_embedded_ref(ref, item, id, env, default_verb, to_direction, marking_refs)
    elif exists_id_key(item.idref):
        handle_existing_refs(ref, id, env, default_verb, to_direction, marking_refs)
    else:
        # a forward reference, fix later
        source_id = id if to_direction else item.idref
        target_id = str(item.idref) if to_direction else id
        rel_obj = create_relationship(source_id, target_id, env, default_verb, item, marking_refs)
        if hasattr(ref, "relationship") and ref.relationship is not None:
            rel_obj["description"] = ref.relationship.value
        env.bundle_instance["relationships"].append(rel_obj)


def handle_relationship_to_refs(refs, source_id, env, default_verb, marking_refs=None):
    for ref in refs:
        if hasattr(ref, "item"):
            item = ref.item
        elif hasattr(ref, "course_of_action"):
            item = ref.course_of_action
        refs_markings = list(set(create_marking_union(item) + marking_refs))
        handle_relationship_ref(ref, item, source_id, env, default_verb, to_direction=True, marking_refs=refs_markings)


def handle_relationship_from_refs(refs, target_id, env, default_verb, marking_refs=None):
    for ref in refs:
        if hasattr(ref, "item"):
            item = ref.item
        elif hasattr(ref, "course_of_action"):
            item = ref.course_of_action
        refs_markings = list(set(create_marking_union(item) + marking_refs))
        handle_relationship_ref(ref, item, target_id, env, default_verb, to_direction=False, marking_refs=refs_markings)


def handle_observable_information_list_as_pattern(obs_list):
    return convert_observable_list_to_pattern(obs_list)


def handle_observable_information_list(obs_list, source_id, env, verb, marking_refs):
    for o in obs_list:
        obs_markings = list(set(create_marking_union(o) + marking_refs))
        if o.idref is None and o.object_ and not o.object_.idref:
            # embedded, so generate scos too
            new_od = convert_observed_data(o, env)
            add_id_of_obs_in_characterizations(new_od["id"])
            for obj_ref in new_od["object_refs"]:
                env.bundle_instance["relationships"].append(
                    create_relationship(source_id, obj_ref, env, verb, marking_refs=obs_markings)
                )
        else:
            if o.idref:
                idref = o.idref
            elif o.idref is None and o.object_ and o.object_.idref:
                idref = generate_stix2x_id("observed-data", o.object_.idref)
                obs_markings = list(set(create_marking_union(o.object_) + marking_refs))

            if id_in_observed_data_mappings(idref):
                obs2x = get_observed_data_from_mapping(idref)
                add_id_of_obs_in_characterizations(obs2x["id"])
                for ref in obs2x["object_refs"]:
                    env.bundle_instance["relationships"].append(
                        create_relationship(source_id, ref, env, verb, marking_refs=obs_markings)
                    )
            else:
                if id_in_observable_mappings(idref):
                    # handling a reference, scos generated later
                    new_od = convert_observed_data(get_obs_from_mapping(idref), env, keep_scos=False)
                    add_id_of_obs_in_characterizations(new_od["id"])
                    env.bundle_instance["objects"].append(new_od)
                    for ref in new_od["object_refs"]:
                        env.bundle_instance["relationships"].append(
                            create_relationship(source_id, ref, env, verb, marking_refs=obs_markings)
                        )
                else:
                    # a forward reference, fix later
                    env.bundle_instance["relationships"].append(
                        create_relationship(source_id, idref, env, verb, marking_refs=obs_markings)
                    )


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
                    extra_relationships.append(
                        create_relationship(m_id, ref["target_ref"], env, ref["verb"], marking_refs=ref.get("object_marking_refs", []))
                    )
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
                    extra_relationships.append(
                        create_relationship(ref["source_ref"], m_id, env, verb, marking_refs=ref.get("object_marking_refs", []))
                    )
    bundle_instance["relationships"].extend(extra_relationships)


def fix_markings():
    for stix2_instance in get_unfinished_marked_objects():
        object_marking_refs = []
        for marking_ref in stix2_instance.get("object_marking_refs", []):
            if isinstance(marking_ref, MarkingStructure):
                stix2x_marking = map_1x_markings_to_2x(marking_ref)
                if marking_ref != stix2x_marking:
                    if "definition_type" in stix2x_marking and stix2x_marking["definition_type"] == "ais":
                        apply_ais_markings(stix2_instance, stix2x_marking)
                        object_marking_refs.append(stix2x_marking["marking_ref"])
                    else:
                        object_marking_refs.append(stix2x_marking["id"])
            else:
                object_marking_refs.append(marking_ref)

        stix2_instance["object_marking_refs"] = object_marking_refs

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
                    info("Including %s in %s and added the target_ref %s to the report", 704, rel["id"], rep["id"], rel["target_ref"])
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
                    info("Including %s in %s and added the source_ref %s to the report", 705, rel["id"], rep["id"], rel["source_ref"])
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

def add_confidence_to_object(instance, confidence):
    if confidence is not None and confidence.value is not None:
        instance["confidence"] = convert_confidence(confidence, instance["id"])


# campaign
def handle_missing_properties_of_campaign(campaign_instance, camp):
    # handle missing properties
    container, extension_definition_id = determine_container_for_missing_properties("campaign", campaign_instance)

    if container is not None:
        handle_multiple_missing_statement_properties(container, camp.intended_effects, "intended_effects",
                                                     campaign_instance["id"], is_literal=True)
        handle_missing_string_property(container, "status", camp.status, campaign_instance["id"])

        if get_option_value("spec_version") == "2.0":
            handle_missing_confidence_property(container, camp.confidence, campaign_instance["id"])
        else:  # 2.1
            add_confidence_to_object(campaign_instance, camp.confidence)

        fill_in_extension_properties(campaign_instance, container, extension_definition_id)


def convert_campaign(camp, env):
    campaign_instance = create_basic_object("campaign", camp, env)
    process_description_and_short_description(campaign_instance, camp)
    campaign_instance["name"] = camp.title
    if camp.names is not None:
        campaign_instance["aliases"] = []
        for name in camp.names:
            if isinstance(name, str):
                campaign_instance["aliases"].append(name)
            else:
                campaign_instance["aliases"].append(name.value)
    handle_missing_properties_of_campaign(campaign_instance, camp)
    if "created_by_ref" in campaign_instance:
        new_env = env.newEnv(timestamp=campaign_instance["created"], created_by_ref=campaign_instance["created_by_ref"])
    else:
        new_env = env.newEnv(timestamp=campaign_instance["created"])
    # process information source before any relationships
    new_env.add_to_env(created_by_ref=process_information_source(camp.information_source, campaign_instance, new_env))
    camp_markings = create_marking_union(camp)

    if camp.activity is not None:
        for a in camp.activity:
            warn("Campaign/Activity type in %s not supported in STIX 2.x", 403, campaign_instance["id"])
    if camp.related_ttps is not None:
        # TODO: victims (identity) use targets, not uses
        # TODO: maybe use _TTP_RELATIONSHIP_MAPPING
        handle_relationship_to_refs(camp.related_ttps,
                                    campaign_instance["id"],
                                    new_env,
                                    "uses",
                                    marking_refs=camp_markings)
    if camp.related_incidents is not None and get_option_value("incidents"):
        handle_relationship_from_refs(camp.related_incidents,
                                      campaign_instance["id"],
                                      new_env,
                                      "attributed-to",
                                      marking_refs=camp_markings)
    if camp.related_indicators is not None:
        handle_relationship_from_refs(camp.related_indicators,
                                      campaign_instance["id"],
                                      new_env,
                                      "indicates",
                                      marking_refs=camp_markings)
    if camp.attribution is not None:
        for att in camp.attribution:
            handle_relationship_to_refs(att,
                                        campaign_instance["id"],
                                        new_env,
                                        "attributed-to",
                                        marking_refs=camp_markings)
    if camp.associated_campaigns:
        info("All 'associated campaigns' relationships of %s are assumed to not represent STIX 1.2 versioning", 710, camp.id_)
        handle_relationship_to_refs(camp.related_coas,
                                    campaign_instance["id"],
                                    new_env,
                                    "related-to",
                                    marking_refs=camp_markings)
    finish_basic_object(camp.id_, campaign_instance, env, camp)
    return campaign_instance


# course of action


def handle_missing_objective_property(container, objective, id):
    if objective is not None:
        if check_for_missing_policy("ignore"):
            warn("Missing property 'objective' of %s is ignored", 307, id)
        else:
            all_text = []

            if objective.descriptions:
                for d in objective.descriptions:
                    all_text.append(str(d.value))

            if objective.short_descriptions:
                for sd in objective.short_descriptions:
                    all_text.append(str(sd.value))

            if check_for_missing_policy("add-to-description"):
                container["description"] += "\n\n" + "OBJECTIVE: "
                container["description"] += "\n\n\t".join(all_text)
            elif check_for_missing_policy("use-custom-properties"):
                container[convert_to_custom_name("objective")] = " ".join(all_text)
                warn("Used custom property for objective of %s", 308, id)
            elif check_for_missing_policy("use-extensions"):
                container["objective"] = " ".join(all_text)
                warn("Used an extension for objective of %s", 311, id)
            if objective.applicability_confidence:
                handle_missing_confidence_property(container, objective.applicability_confidence, id, "objective")


def handle_missing_properties_of_course_of_action(coa_instance, coa):
    container, extension_definition_id = determine_container_for_missing_properties("course-of-action", coa_instance)

    if container is not None:
        handle_missing_string_property(container, "stage", coa.stage, coa_instance["id"], is_literal=True)
        handle_missing_objective_property(container, coa.objective, coa_instance["id"])
        if coa.parameter_observables is not None:
            parameter_expression = handle_observable_information_list_as_pattern(coa.parameter_observables)
            handle_missing_string_property(container, "parameter_expression", parameter_expression, coa_instance["id"])
        handle_missing_statement_properties(container, coa.impact, "impact", coa_instance["id"], is_literal=True)
        handle_missing_statement_properties(container, coa.cost, "cost", coa_instance["id"], is_literal=True)
        handle_missing_statement_properties(container, coa.efficacy, "efficacy", coa_instance["id"], is_literal=True)

    fill_in_extension_properties(coa_instance, container, extension_definition_id)


def convert_course_of_action(coa, env):
    coa_instance = create_basic_object("course-of-action", coa, env)
    new_env = env.newEnv(timestamp=coa_instance["created"])
    process_description_and_short_description(coa_instance, coa)
    coa_instance["name"] = coa.title

    if coa.type_:
        convert_controlled_vocabs_to_open_vocabs(coa_instance, "labels", [coa.type_], COA_LABEL_MAP, False)
    if coa.structured_coa:
        warn("Structured COAs type in %s are not supported in STIX 2.x", 404, coa_instance["id"])

    handle_missing_properties_of_course_of_action(coa_instance, coa)

    new_env.add_to_env(created_by_ref=process_information_source(coa.information_source,
                                                                 coa_instance,
                                                                 new_env))
    # process information source before any relationships
    if coa.related_coas:
        coa_markings = create_marking_union(coa)
        info("All 'associated coas' relationships of %s are assumed to not represent STIX 1.2 versioning", 710, coa.id_)
        handle_relationship_to_refs(coa.related_coas, coa_instance["id"], new_env,
                                    "related-to", marking_refs=coa_markings)
    finish_basic_object(coa.id_, coa_instance, new_env, coa)
    return coa_instance


# exploit target


def process_et_properties(sdo_instance, et, env):
    process_description_and_short_description(sdo_instance, et, True)
    if "name" in sdo_instance:
        info("Title in %s used for name, appending exploit_target %s title in description property",
             303, sdo_instance["type"], sdo_instance["id"])
        handle_missing_string_property(sdo_instance, "title", et.title, False)
    elif et.title is not None:
        sdo_instance["name"] = et.title
    new_env = env.newEnv(timestamp=sdo_instance["created"])
    new_env.add_to_env(created_by_ref=process_information_source(et.information_source, sdo_instance, new_env))
    if et.potential_coas is not None:
        et_markings = create_marking_union(et)
        handle_relationship_from_refs(et.potential_coas, sdo_instance["id"],
                                      new_env,
                                      "mitigates",
                                      marking_refs=et_markings)


def handle_missing_properties_of_vulnerability(vulnerability_instance, v):
    container, extension_definition_id = determine_container_for_missing_properties("vulnerability",
                                                                                    vulnerability_instance)

    if container is not None:
        if v.source is not None:
            handle_missing_string_property(container, "source", v.source, vulnerability_instance["id"], False)

        if v.cvss_score is not None:
            # FIXME: add CVSS score into description
            info("CVSS Score in %s is not handled, yet.", 815, vulnerability_instance["id"])

        if v.discovered_datetime is not None:
            handle_missing_string_property(container,
                                           "discovered_datetime",
                                           v.discovered_datetime.value.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                           vulnerability_instance["id"],
                                           False)

        if v.published_datetime is not None:
            handle_missing_string_property(container,
                                           "published_datetime",
                                           v.published_datetime.value.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                                           vulnerability_instance["id"],
                                           False)

        if v.affected_software is not None:
            info("Affected Software in %s is not handled, yet.", 815, vulnerability_instance["id"])

        fill_in_extension_properties(vulnerability_instance, container, extension_definition_id)


def convert_vulnerability(v, et, env):
    vulnerability_instance = create_basic_object("vulnerability", v, env, et.id_)
    if v.title is not None:
        vulnerability_instance["name"] = v.title
    process_description_and_short_description(vulnerability_instance, v)
    if v.cve_id is not None:
        vulnerability_instance["external_references"].append({"source_name": "cve", "external_id": v.cve_id})
    if v.osvdb_id is not None:
        vulnerability_instance["external_references"].append({"source_name": "osvdb", "external_id": str(v.osvdb_id)})

    handle_missing_properties_of_vulnerability(vulnerability_instance, v)

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
def determine_administrative_area(geo):
    if geo.name_code:
        return geo.name_code
    elif geo.value:
        return geo.value
    else:
        return None


def convert_ciq_addresses2_1(ciq_info_addresses, identity_instance, env, created_by_ref_source, parent_markings):
    location_keys = []
    for ciq_info_address in ciq_info_addresses:
        if not ciq_info_address.free_text_address:
            # only reuse if administrative area and country match, and no free text address
            if (hasattr(ciq_info_address, "administrative_area") and
                    ciq_info_address.administrative_area and
                    hasattr(ciq_info_address, "country") and
                    ciq_info_address.country):
                if len(ciq_info_address.country.name_elements) == 1:
                    country_code = determine_country_code(ciq_info_address.country.name_elements[0])
                    for administrative_area in ciq_info_address.administrative_area.name_elements:
                        location_keys.append("c:" + str(country_code) +
                                             "," +
                                             "aa:" + str(determine_administrative_area(administrative_area)))
                else:
                    warn("Multiple administrative areas with multiple countries in %s is not handled", 631, None)
            elif hasattr(ciq_info_address, "administrative_area") and ciq_info_address.administrative_area:
                for administrative_area in ciq_info_address.adminstrative_area.name_elements:
                    location_keys.append("aa:" + str(determine_administrative_area(administrative_area)))
            elif hasattr(ciq_info_address, "country") and ciq_info_address.country:
                for country_code in ciq_info_address.country.name_elements:
                    location_keys.append("c:" + str(determine_country_code(country_code)))
        else:
            # only remember locations with no free text address
            warn("Location with free text address in %s not handled yet", 433, identity_instance["id"])
        for key in location_keys:
            if exists_location_object(key):
                location = get_location_object(key)
            else:
                administrative_area = None
                country_code = None
                location = create_basic_object("location", ciq_info_address, env)
                location["spec_version"] = "2.1"
                if key.find(",") != -1:
                    both_parts = key.split(",")
                    country_code = both_parts[0].split(":")[1]
                    administrative_area = both_parts[1].split(":")[1]
                else:
                    part = key.split(":")
                    if part[0] == "c":
                        country_code = part[1]
                    elif part[0] == "aa":
                        administrative_area = part[1]
                if administrative_area:
                    location["administrative_area"] = administrative_area
                if country_code:
                    location["country"] = country_code
                add_location_object(key, location)
                if created_by_ref_source == "this_identity":
                    location["created_by_ref"] = identity_instance["id"]
                else:
                    location["created_by_ref"] = env.created_by_ref
                location["object_marking_refs"] = parent_markings
                warn("Location %s may not contain all aspects of the STIX 1.x CIQAddress object", 803, location["id"])
                env.bundle_instance["objects"].append(location)
            relationship = create_relationship(
                identity_instance["id"],
                location["id"],
                env.newEnv(created_by_ref=identity_instance["id"]) if created_by_ref_source == "this_identity" else env,
                "located-at",
                marking_refs=parent_markings,
            )
            info("Included parent markings for Relationship %s and Location %s", 729, relationship["id"], location["id"])
            env.bundle_instance["objects"].append(relationship)
            add_unfinished_marked_object(location)


def handle_missing_properties_of_ciq_instance(identity_instance, ciq):
    container, extension_definition_id = determine_container_for_missing_properties("identity-ciq", identity_instance)

    if container is not None:
        if ciq.roles:
            handle_missing_string_property(container,
                                           "information_source_roles",
                                           ciq.roles,
                                           identity_instance["id"],
                                           True)
            warn("Roles is not a property of an identity (%s).  Perhaps the roles are associated with a related Threat Actor",
                 428,
                 identity_instance["id"])
        if ciq._specification.free_text_lines:
            lines = ""
            for line in ciq._specification.free_text_lines:
                lines += line.value
            handle_missing_string_property(container, "free_text_lines", lines, identity_instance["id"])

        fill_in_extension_properties(identity_instance, container, extension_definition_id)


def convert_identity(identity, env, created_by_ref_source, parent_id=None, temp_marking_id=None):
    identity_instance = create_basic_object("identity", identity, env, parent_id)
    identity_instance["sectors"] = []
    spec_version = get_option_value("spec_version")
    if spec_version == "2.0":
        identity_instance["identity_class"] = "unknown"
    if identity.name is not None:
        identity_instance["name"] = identity.name
    if isinstance(identity, CIQIdentity3_0Instance):
        handle_missing_properties_of_ciq_instance(identity_instance, identity)
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
                parent_markings = create_marking_union(identity)
                convert_ciq_addresses2_1(ciq_info.addresses, identity_instance, env, created_by_ref_source, parent_markings)
            else:
                warn("CIQ Address information in %s is not representable in 2.0", 435, identity.id_ if hasattr(identity, "id_") else parent_id)

    if identity.related_identities:
        identity_markings = create_marking_union(identity)
        msg = "All 'associated identities' relationships of %s are assumed to not represent STIX 1.2 versioning"
        info(msg, 710, identity_instance["id"])
        handle_relationship_to_refs(identity.related_identities, identity_instance["id"], env, "related-to",
                                    marking_refs=identity_markings)

    if created_by_ref_source == "this_identity":
        new_env = env.newEnv(created_by_ref=identity_instance["id"])
    elif created_by_ref_source == "from_env":
        new_env = env
    elif created_by_ref_source == "parent":
        new_env = env.newEnv(created_by_ref=parent_id)
    finish_basic_object(identity.id_,
                        identity_instance,
                        new_env,
                        identity,
                        temp_marking_id=temp_marking_id)
    return identity_instance

# incident


def handle_incident_time_info(container, incident_instance, incident):
    time_values = incident.time
    if time_values.first_malicious_action:
        handle_missing_timestamp_property(container, "time_of_first_malicious_action",
                                          time_values.first_malicious_action.value, incident_instance["id"])
    if time_values.initial_compromise:
        handle_missing_timestamp_property(container, "time_of_initial_compromise",
                                          time_values.initial_compromise.value, incident_instance["id"])
    if time_values.first_data_exfiltration:
        handle_missing_timestamp_property(container, "time_of_first_data_exfiltration",
                                          time_values.first_data_exfiltration.value, incident_instance["id"])
    if time_values.incident_discovery:
        handle_missing_timestamp_property(container, "time_of_incident_discovery",
                                          time_values.incident_discovery.value, incident_instance["id"])
    if time_values.incident_opened:
        handle_missing_timestamp_property(container, "time_when_incident_opened",
                                          time_values.incident_opened.value, incident_instance["id"])
    if time_values.containment_achieved:
        handle_missing_timestamp_property(container, "time_when_containment_achieved",
                                          time_values.containment_achieved.value, incident_instance["id"])
    if time_values.restoration_achieved:
        handle_missing_timestamp_property(container, "time_when_restoration_achieved",
                                          time_values.restoration_achieved.value, incident_instance["id"])
    if time_values.incident_reported:
        handle_missing_timestamp_property(container, "time_when_incident_reported",
                                          time_values.incident_reported.value, incident_instance["id"])
    if time_values.incident_closed:
        handle_missing_timestamp_property(container, "time_when_incident_closed",
                                          time_values.incident_closed.value, incident_instance["id"])


def handle_missing_identity_ref_properties(container, instance2x, sources, env, property_name):
    # TODO: Make this work for both ref and refs
    identities = list()
    for s in sources:
        if s.identity:
            if check_for_missing_policy("add-to-description"):
                id_info = s.identity.name
            else:
                id2x = convert_identity(s.identity, env, "from_env")
                env.bundle_instance["objects"].append(id2x)
                id_info = id2x["id"]
            identities.append(id_info)
    if not identities == list():
        handle_missing_string_property(container, property_name, identities, instance2x["id"], is_list=True)


def handle_missing_properties_of_incident(incident_instance, incident, env):
    # handle missing properties
    container, extension_definition_id = determine_container_for_missing_properties("incident", incident_instance)

    if container is not None:

        if incident.time:
            handle_incident_time_info(container, incident_instance, incident)

        if get_option_value("spec_version") == "2.0":
            handle_missing_confidence_property(container, incident.confidence, incident_instance["id"])
        else:  # 2.1
            add_confidence_to_object(incident_instance, incident.confidence)

        if incident.contacts is not None:
            handle_missing_identity_ref_properties(container, incident_instance, incident.contacts, env, "contact_refs")

        if incident.reporter is not None:
            reporter = incident.reporter
            if reporter.identity:
                id2x = convert_identity(reporter.identity, env, "from_env")
                env.bundle_instance["objects"].append(id2x)
                handle_missing_string_property(container, "reporter_ref", id2x["id"], incident_instance["id"])

        if incident.responders is not None:
            handle_missing_identity_ref_properties(container, incident_instance, incident.responders, env, "responder_refs")

        if incident.coordinators is not None:
            handle_missing_identity_ref_properties(container, incident_instance, incident.coordinators, env, "coordinator_refs")

        if incident.victims is not None:
            handle_missing_identity_ref_properties(container, incident_instance, incident.victims, env, "victim_refs")

        if incident.affected_assets is not None:
            # FIXME: add affected_assets to description
            info("Incident Affected Assets in %s is not handled, yet.", 815, incident_instance["id"])

        if incident.impact_assessment is not None:
            # FIXME: add impact_assessment to description
            info("Incident Impact Assessment in %s is not handled, yet", 815, incident_instance["id"])

        handle_missing_string_property(container, "status", incident.status, incident_instance["id"], is_literal=True)

        handle_missing_string_property(container, "security_compromise", incident.security_compromise, incident_instance["id"], is_literal=True),

        handle_missing_string_property(container, "discovery_methods", incident.discovery_methods, incident_instance["id"],
                                       is_list=True, is_literal=True)

        handle_multiple_missing_statement_properties(container, incident.intended_effects, "intended_effects",
                                                     incident_instance["id"], is_literal=True,
                                                     mapping=_INTENDED_EFFECTS_LITERAL_MAPPING)

        fill_in_extension_properties(incident_instance, container, extension_definition_id)


def convert_incident(incident, env):
    if get_option_value("spec_version") == "2.0":
        incident_type_name = convert_to_custom_name("incident", separator="-")
    else:
        incident_type_name = "incident"
    incident_instance = create_basic_object(incident_type_name, incident, env)
    new_env = env.newEnv(timestamp=incident_instance["created"])
    process_description_and_short_description(incident_instance, incident)
    if incident.title is not None:
        incident_instance["name"] = incident.title
    if incident.external_ids is not None:
        for ex_id in incident.external_ids:
            incident_instance["external_references"].append(
                {"source_name": ex_id.source, "external_id": ex_id.value})
    # time
    if incident.categories is not None:
        convert_controlled_vocabs_to_open_vocabs(incident_instance, "labels", incident.categories, INCIDENT_LABEL_MAP,
                                                 False)
    # process information source before any relationships
    new_env.add_to_env(created_by_ref=process_information_source(incident.information_source, incident_instance, new_env))
    incident_markings = create_marking_union(incident)

    # process related observables first
    if incident.related_observables is not None:
        handle_relationship_from_refs(incident.related_observables, incident_instance["id"], new_env, "part-of",
                                      marking_refs=incident_markings)
    if incident.related_indicators is not None:
        handle_relationship_from_refs(incident.related_indicators, incident_instance["id"], new_env, "indicates",
                                      marking_refs=incident_markings)
    if incident.leveraged_ttps is not None:
        warn("Using %s for the %s of %s", 718, "related-to", "leveraged TTPs", incident.id_)
        handle_relationship_to_refs(incident.leveraged_ttps, incident_instance["id"], new_env, "related-to",
                                    marking_refs=incident_markings)
    if incident.coa_taken is not None:
        handle_relationship_to_refs(incident.coa_taken, incident_instance["id"], new_env, "used",
                                    marking_refs=incident_markings)

    if incident.coa_requested is not None:
        handle_relationship_to_refs(incident.coa_requested, incident_instance["id"], new_env, "mitigates",
                                    marking_refs=incident_markings)

    if incident.attributed_threat_actors is not None:
        handle_relationship_to_refs(incident.attributed_threat_actors, incident_instance["id"], new_env, "attributed-to",
                                    marking_refs=incident_markings)

    handle_missing_properties_of_incident(incident_instance, incident, new_env)

    if incident.related_incidents:
        info("All 'related incidents' relationships of %s are assumed to not represent STIX 1.2 versioning",
             710, incident_instance["id"])
        handle_relationship_to_refs(incident.related_incidents, incident_instance["id"], new_env, "related-to",
                                    marking_refs=incident_markings)
    finish_basic_object(incident.id_, incident_instance, new_env, incident)
    return incident_instance


# indicator

def convert_kill_chain_missing_names(phase, kill_chain_phases_2x):
    kill_chain_name = phase.kill_chain_name
    phase_name = phase.name
    if not phase.kill_chain_name and phase.kill_chain_id:
        kill_chain_name = phase.kill_chain_id
    if not phase.name and phase.phase_id:
        phase_name = phase.phase_id
    if check_lmco(phase):
        kill_chain_name = "lockheed-martin-cyber-kill-chain"
        phase_name = convert_to_stix_literal(phase_name)
        phase_name = lmco_id_to_name(phase_name)
        kill_chain_phases_2x.append({"kill_chain_name": kill_chain_name, "phase_name": phase_name})
    else:
        kill_chain_phases_2x.append({"kill_chain_name": kill_chain_name, "phase_name": phase_name})


def convert_kill_chains(kill_chain_phases, sdo_instance):
    if kill_chain_phases is not None:
        kill_chain_phases_2x = []
        for phase in kill_chain_phases:
            if isinstance(phase, KillChainPhaseReference):
                try:
                    if phase.phase_id:
                        kill_chain_info = _KILL_CHAINS_PHASES[phase.phase_id]
                    else:
                        kill_chain_info = _KILL_CHAINS_PHASES[phase]
                    kill_chain_phases_2x.append({"kill_chain_name": kill_chain_info["kill_chain_name"],
                                                 "phase_name": kill_chain_info["phase_name"]})
                except KeyError:
                    warn("Unknown phase_id %s in %s", 632, phase.phase_id, sdo_instance["id"])
                    convert_kill_chain_missing_names(phase, kill_chain_phases_2x)
            elif isinstance(phase, KillChainPhase):
                convert_kill_chain_missing_names(phase, kill_chain_phases_2x)
        if kill_chain_phases_2x:
            sdo_instance["kill_chain_phases"] = kill_chain_phases_2x


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
                        indicator_instance["pattern"] = str(tm.rule.value)
                        indicator_instance["pattern_type"] = "yara"
                    elif isinstance(tm, SnortTestMechanism):
                        list_of_strings = []
                        for rule in tm.rules:
                            list_of_strings.append(str(rule.value))
                        indicator_instance["pattern"] = ", ".join(list_of_strings)
                        indicator_instance["pattern_type"] = "snort"
                    elif isinstance(tm, OpenIOCTestMechanism):
                        warn("IOC indicator in %s cannot be converted to a STIX pattern", 410, indicator_instance["id"])
                        indicator_instance["pattern"] = bytes.decode(etree.tostring(tm.ioc))
                        indicator_instance["pattern_type"] = "openioc"


def negate_indicator(indicator):
    return hasattr(indicator, "negate") and indicator.negate


def handle_missing_properties_of_indicator(indicator_instance, indicator):
    container, extension_definition_id = determine_container_for_missing_properties("indicator",
                                                                                    indicator_instance)
    if container is not None:
        if indicator.likely_impact:
            handle_missing_statement_properties(container, indicator.likely_impact, "likely_impact",
                                                indicator_instance["id"], is_literal=True)

        if get_option_value("spec_version") == "2.0":
            handle_missing_confidence_property(container, indicator.confidence, indicator_instance["id"])
        else:  # 2.1
            add_confidence_to_object(indicator_instance, indicator.confidence)

        fill_in_extension_properties(indicator_instance, container, extension_definition_id)


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
                if not window.start_time:
                    warn("No start time for the first valid time interval is available in %s, using current time (other time intervals might be more appropriate)", # noqa
                         619, indicator_instance["id"])
                    indicator_instance["valid_from"] = indicator_instance["created"]
                else:
                    indicator_instance["valid_from"] = convert_timestamp_to_string(window.start_time.value)
                if not window.end_time:
                    warn("No end time for the first valid time interval is available in %s, other time intervals might be more appropriate",
                         619, indicator_instance["id"])
                else:
                    indicator_instance["valid_until"] = convert_timestamp_to_string(window.end_time.value)
            else:
                warn("Only one valid time window allowed for %s in STIX 2.x - used first one",
                     507, indicator_instance["id"])
        if "valid_from" not in indicator_instance:
            warn("No valid time position information available in %s, using parent timestamp",
                 903, indicator_instance["id"])
            indicator_instance["valid_from"] = convert_timestamp_of_stix_object(indicator, env.timestamp)
    convert_kill_chains(indicator.kill_chain_phases, indicator_instance)
    handle_missing_properties_of_indicator(indicator_instance, indicator)
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
    if "pattern" not in indicator_instance:
        warn("Indicator %s does not contain the information necessary to generate a pattern", 638, indicator_instance["id"])
    env = env.newEnv(timestamp=indicator_instance["created"])
    indicator_created_by_ref = process_information_source(indicator.producer, indicator_instance,
                                                          env)
    env.add_to_env(created_by_ref=indicator_created_by_ref)
    indicator_markings = create_marking_union(indicator)
    # process information source before any relationships
    if indicator.sightings:
        for s in indicator.sightings:
            env.bundle_instance["objects"].append(handle_sighting(s, indicator_instance["id"], env))
    if indicator.suggested_coas is not None:
        warn("Using %s for the %s of %s", 718, "investigates", "suggested COAs", indicator.id_)
        handle_relationship_from_refs(indicator.suggested_coas, indicator_instance["id"], env,
                                      "investigates", marking_refs=indicator_markings)
    if indicator.related_campaigns is not None:
        handle_relationship_to_refs(indicator.related_campaigns, indicator_instance["id"], env,
                                    "attributed-to", marking_refs=indicator_markings)
    if indicator.indicated_ttps is not None:
        handle_relationship_to_refs(indicator.indicated_ttps, indicator_instance["id"], env,
                                    "indicates", marking_refs=indicator_markings)
    if indicator.related_indicators:
        info("All 'related indicators' relationships of %s are assumed to not represent STIX 1.2 versioning", 710, indicator.id_)
        handle_relationship_to_refs(indicator.related_indicators, indicator_instance["id"], env,
                                    "related-to", marking_refs=indicator_markings)
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
        add_object_id_value(obs.id_, scos)
        if obs.object_.related_objects:
            for o in obs.object_.related_objects:
                if not o.idref:
                    # it is embedded - for idrefs see convert_cybox.py
                    related = convert_cybox_object(o, env)
                    if related:
                        scos.extend(related)
                        property_name = embedded_property_ref_name(obs.object_.properties, o.relationship)
                        if not property_name:
                            marking_refs = create_marking_union(obs.object_, o)
                            rel_verb = o.relationship.value.lower() if o.relationship and o.relationship.value else "resolves-to"
                            env.bundle_instance["objects"].append(
                                create_relationship(scos[0]["id"], related[0]["id"], env, rel_verb, marking_refs=marking_refs)
                            )
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
                            observed_data_instance["objects"][str(int(index) + int(current_largest_id) + 1)] = obj
                        property_name = embedded_property_ref_name(obs.object_.properties, o.relationship)
                        if property_name and o.relationship and o.relationship.value:
                            set_embedded_ref_property_2_0(observed_data_instance["objects"]["0"],
                                                          str(int(current_largest_id) + 1),
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
        sdo_instance["primary_motivation"] = map_vocabs_to_label(str(motivations[0].value), ATTACK_MOTIVATION_MAP)

    values = []

    if len(motivations) > 1:
        for m in motivations[1:]:
            if m.value is not None:
                values.append(m.value)

        if values:
            convert_controlled_vocabs_to_open_vocabs(sdo_instance, "secondary_motivations", values, ATTACK_MOTIVATION_MAP, False)


def handle_missing_properties_of_threat_actor(threat_actor_instance, threat_actor):
    container, extension_definition_id = determine_container_for_missing_properties("threat-actor",
                                                                                    threat_actor_instance)
    if container is not None:
        handle_multiple_missing_statement_properties(container, threat_actor.planning_and_operational_supports,
                                                     "planning_and_operational_support", threat_actor_instance["id"],
                                                     is_literal=True)
        if get_option_value("spec_version") == "2.0":
            handle_missing_confidence_property(container, threat_actor.confidence, threat_actor_instance["id"])
        else:  # 2.1
            add_confidence_to_object(threat_actor_instance, threat_actor.confidence)

        fill_in_extension_properties(threat_actor_instance, container, extension_definition_id)


def convert_threat_actor(threat_actor, env):
    threat_actor_instance = create_basic_object("threat-actor", threat_actor, env)
    process_description_and_short_description(threat_actor_instance, threat_actor)
    new_env = env.newEnv(timestamp=threat_actor_instance["created"])
    new_env.add_to_env(created_by_ref=process_information_source(threat_actor.information_source, threat_actor_instance, new_env))
    ta_markings = create_marking_union(threat_actor)
    # process information source before any relationships
    if threat_actor.identity is not None:
        if threat_actor.identity.id_:
            info("Threat Actor identity %s being used as basis of attributed-to relationship", 701, threat_actor.identity.id_)
        ta_id_markings = create_marking_union(threat_actor, threat_actor.identity)
        handle_relationship_to_objs([threat_actor.identity], threat_actor_instance["id"], new_env, "attributed-to", ta_id_markings)
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
            threat_actor_instance["goals"].append(str(g.value))
    handle_missing_properties_of_threat_actor(threat_actor_instance, threat_actor)
    spec_version = get_option_value("spec_version")
    convert_controlled_vocabs_to_open_vocabs(threat_actor_instance,
                                             "labels" if spec_version == "2.0" else "threat_actor_types",
                                             threat_actor.types,
                                             THREAT_ACTOR_LABEL_MAP,
                                             False,
                                             required=spec_version == "2.0")

    if threat_actor.motivations:
        add_motivations_to_threat_actor(threat_actor_instance, threat_actor.motivations)

    convert_controlled_vocabs_to_open_vocabs(threat_actor_instance, "sophistication", threat_actor.sophistications,
                                             THREAT_ACTOR_SOPHISTICATION_MAP, True)
    # handle relationships
    if threat_actor.observed_ttps is not None:
        handle_relationship_to_refs(threat_actor.observed_ttps, threat_actor_instance["id"], new_env,
                                    "uses", marking_refs=ta_markings)
    if threat_actor.associated_campaigns is not None:
        handle_relationship_from_refs(threat_actor.associated_campaigns, threat_actor_instance["id"], new_env,
                                      "attributed-to", marking_refs=ta_markings)
    if threat_actor.associated_actors:
        info("All 'associated actors' relationships of %s are assumed to not represent STIX 1.2 versioning", 710, threat_actor.id_)
        handle_relationship_to_refs(threat_actor.associated_actors, threat_actor_instance["id"], new_env,
                                    "related-to", marking_refs=ta_markings)

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


def handle_missing_properties_of_ttp(sdo_instance, ttp):
    container, extension_definition_id = determine_container_for_missing_properties(sdo_instance["type"],
                                                                                    sdo_instance)
    if container is not None:
        handle_multiple_missing_statement_properties(container, ttp.intended_effects, "intended_effects",
                                                     sdo_instance["id"], is_literal=True,
                                                     mapping=_INTENDED_EFFECTS_LITERAL_MAPPING)
        if hasattr(ttp, "title"):
            if "name" not in sdo_instance or sdo_instance["name"] is None:
                sdo_instance["name"] = ttp.title
            else:
                handle_missing_string_property(container, "title", ttp.title, sdo_instance["id"], False)

        fill_in_extension_properties(sdo_instance, container, extension_definition_id)


def process_ttp_properties(sdo_instance, ttp, env, kill_chains_in_sdo=True, marking_refs=None):
    process_description_and_short_description(sdo_instance, ttp, True)

    # only populate kill chain phases if that is a property of the sdo_instance type, as indicated by kill_chains_in_sdo
    if kill_chains_in_sdo and hasattr(ttp, "kill_chain_phases"):
        convert_kill_chains(ttp.kill_chain_phases, sdo_instance)
    env = env.newEnv(timestamp=sdo_instance["created"])
    ttp_created_by_ref = process_information_source(ttp.information_source, sdo_instance, env)
    env.add_to_env(created_by_ref=ttp_created_by_ref)
    if ttp.exploit_targets is not None:
        handle_relationship_to_refs(ttp.exploit_targets, sdo_instance["id"], env,
                                    "targets", marking_refs=marking_refs)
    if ttp.related_ttps:
        info("All 'related ttps' relationships of %s are assumed to not represent STIX 1.2 versioning", 710, ttp.id_)
        for rel in ttp.related_ttps:
            source_type = get_type_from_id(sdo_instance["id"])
            if rel.item.idref is None:
                target_type = get_type_from_id(rel.item.id_)
                verb, to_direction = determine_ttp_relationship_type_and_direction(source_type, target_type,
                                                                                   str(rel.relationship))
                refs_markings = list(set(create_marking_union(rel) + marking_refs))
                handle_embedded_ref(rel, rel.item, rel.item.id_, env, verb, to_direction, refs_markings)
            else:
                target_id = rel.item.idref
                stix2x_target_ids = get_id_value(target_id)
                if stix2x_target_ids != []:
                    for id20 in stix2x_target_ids:
                        target_type = get_type_from_id(id20)
                        verb, to_direction = determine_ttp_relationship_type_and_direction(source_type, target_type, str(rel.relationship))
                        refs_markings = list(set(create_marking_union(rel) + marking_refs))
                        handle_existing_ref(rel, id20, sdo_instance["id"], env, verb, to_direction, refs_markings)
                else:
                    refs_markings = list(set(create_marking_union(rel) + marking_refs))
                    handle_relationship_ref(rel, rel.item, sdo_instance["id"], env, "related-to", to_direction=True, marking_refs=refs_markings)
    if hasattr(ttp, "related_packages") and ttp.related_packages is not None:
        for p in ttp.related_packages:
            warn("Related_Packages type in %s not supported in STIX 2.x", 402, ttp.id_)
    handle_missing_properties_of_ttp(sdo_instance, ttp)


def convert_attack_pattern(ap, ttp, env, ttp_id_used):
    attack_pattern_instance = create_basic_object("attack-pattern", ap, env, ttp.id_, not ttp_id_used)
    if ap.title is not None:
        attack_pattern_instance["name"] = ap.title
    process_description_and_short_description(attack_pattern_instance, ap)
    if ap.capec_id is not None:
        attack_pattern_instance["external_references"] = [{"source_name": "capec", "external_id": ap.capec_id}]
    ap_markings = create_marking_union(ap)
    process_ttp_properties(attack_pattern_instance, ttp, env, marking_refs=ap_markings)
    finish_basic_object(ttp.id_, attack_pattern_instance, env, ttp)
    return attack_pattern_instance


def handle_missing_properties_of_malware_instance(sdo_instance, malware1x_instance):
    container, extension_definition_id = determine_container_for_missing_properties("malware",
                                                                                    sdo_instance)
    if container is not None and not check_for_missing_policy("ignore"):
        # first name populated in convert_malware_instance, no alias property in 2.0
        if get_option_value("spec_version") == "2.0":
            if malware1x_instance.names is not None and len(malware1x_instance.names) > 1:
                handle_missing_string_property(container, "other_names", malware1x_instance.names[1:], sdo_instance["id"],
                                               is_list=True)
        if hasattr(malware1x_instance, "title"):
            if "name" not in container or container["name"] is None:
                # this case is handled in convert_malware_instance
                pass
            else:
                handle_missing_string_property(container, "title", malware1x_instance.title, sdo_instance["id"], False)

        fill_in_extension_properties(sdo_instance, container, extension_definition_id)


def convert_malware_instance(mal, ttp, env, ttp_id_used):
    malware_instance_instance = create_basic_object("malware", mal, env, ttp.id_, not ttp_id_used)
    if get_option_value("spec_version") == "2.1":
        malware_instance_instance["is_family"] = False
        info("The is_family property of malware instance %s is assumed to be false", 728, malware_instance_instance["id"])
    aliases = []
    if mal.names is not None:
        for n in mal.names:
            if "name" not in malware_instance_instance:
                malware_instance_instance["name"] = str(n)
            elif check_for_missing_policy("ignore"):
                warn("Only one name for malware is allowed for %s in STIX 2.x - used %s, dropped %s",
                     508,
                     malware_instance_instance["id"],
                     malware_instance_instance["name"],
                     str(n))
            elif get_option_value("spec_version") == "2.1":
                alias_name = str(n)
                aliases.append(alias_name)
                warn("Only one name for malware is allowed for %s in STIX 2.1, used %s, %s becomes an alias",
                     502,
                     malware_instance_instance["id"],
                     malware_instance_instance["name"],
                     alias_name)
    if mal.title is not None:
        if "name" not in malware_instance_instance:
            malware_instance_instance["name"] = mal.title
    if aliases:
        malware_instance_instance["aliases"] = aliases
    process_description_and_short_description(malware_instance_instance, mal)
    spec_version = get_option_value("spec_version")
    convert_controlled_vocabs_to_open_vocabs(malware_instance_instance,
                                             "labels" if spec_version == "2.0" else "malware_types",
                                             mal.types,
                                             MALWARE_LABELS_MAP,
                                             False,
                                             required=spec_version == "2.0")

    if isinstance(mal, MAECInstance):
        warn("MAEC content in %s cannot be represented in STIX 2.x", 426, ttp.id_)
    mi_markings = create_marking_union(mal)
    process_ttp_properties(malware_instance_instance, ttp, env, marking_refs=mi_markings)
    handle_missing_properties_of_malware_instance(malware_instance_instance, mal)
    finish_basic_object(ttp.id_, malware_instance_instance, env, ttp)
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


def handle_missing_properties_of_tool(tool_instance, tool):
    container, extension_definition_id = determine_container_for_missing_properties("tool",
                                                                                    tool_instance)
    if container is not None:
        handle_missing_string_property(container, "vendor", tool.vendor, tool_instance["id"])
        handle_missing_string_property(container, "service_pack", tool.service_pack, tool_instance["id"])
        # TODO: add tool_specific_data to descriptor <-- Not Implemented!

        if tool.tool_hashes is not None:
            # FIXME: add tool_hashes to descriptor
            info("Tool Tool_Hashes in %s is not handled, yet.", 815, tool_instance["id"])

        # TODO: add tool_configuration to descriptor <-- Not Implemented!
        # TODO: add execution_environment to descriptor <-- Not Implemented!
        # TODO: add errors to descriptor <-- Not Implemented!
        # TODO: add compensation_model to descriptor <-- Not Implemented!

        fill_in_extension_properties(tool_instance, container, extension_definition_id)


def convert_tool(tool, ttp, env, first_one):
    tool_instance = create_basic_object("tool", tool, env, ttp.id_, not first_one)
    if tool.name is not None:
        tool_instance["name"] = tool.name
        if tool.title is not None:
            handle_missing_string_property(tool_instance, "title", tool.title)
    elif tool.title is not None:
        tool_instance["name"] = tool.title
    process_description_and_short_description(tool_instance, tool)
    handle_missing_properties_of_tool(tool_instance, tool)
    spec_version = get_option_value("spec_version")
    convert_controlled_vocabs_to_open_vocabs(tool_instance,
                                             "labels" if spec_version == "2.0" else "tool_types",
                                             tool.type_,
                                             TOOL_LABELS_MAP,
                                             False,
                                             required=spec_version == "2.0")
    tool_instance["tool_version"] = tool.version
    tool_markings = create_marking_union(tool)
    process_ttp_properties(tool_instance, ttp, env, marking_refs=tool_markings)
    finish_basic_object(ttp.id_, tool_instance, env, ttp)
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
    infra_markings = create_marking_union(infra)
    if infra.observable_characterization is not None:
        handle_observable_information_list(infra.observable_characterization, infrastructure_instance["id"], env, "consists-of", infra_markings)
    process_ttp_properties(infrastructure_instance, ttp, env, marking_refs=infra_markings)
    finish_basic_object(ttp.id_, infrastructure_instance, env, ttp)
    return infrastructure_instance


def convert_resources(resources, ttp, env, generated_ttps):
    resources_generated = []
    first_one = bool(generated_ttps)
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
        else:
            warn("Infrastructure in %s not part of STIX 2.0", 409, ttp.id_ or "")
    return resources_generated


def convert_identity_for_victim_target(identity, ttp, env, ttp_generated):
    if identity:
        identity_markings = create_marking_union(identity)
        identity_instance = convert_identity(identity,
                                             env,
                                             created_by_ref_source="from_env",
                                             parent_id=ttp.id_ if not ttp_generated else None)
    else:
        identity_instance = create_basic_object("identity", None, env, ttp.id_)
        identity_instance["identity_class"] = "unknown"
        identity_markings = create_marking_union(ttp)
    env.bundle_instance["objects"].append(identity_instance)
    process_ttp_properties(identity_instance, ttp, env, False, marking_refs=identity_markings)
    finish_basic_object(ttp.id_, identity_instance, env, ttp)
    return identity_instance


def handle_missing_properties_of_victim_target(identity_instance, victim_targeting):
    container, extension_definition_id = determine_container_for_missing_properties("identity",
                                                                                    identity_instance)

    if container is not None:
        if victim_targeting.targeted_systems:
            handle_missing_string_property(container, "targeted_systems", victim_targeting.targeted_systems, identity_instance["id"],
                                           True)
        if victim_targeting.targeted_information:
            handle_missing_string_property(container, "targeted_information",
                                           victim_targeting.targeted_information, identity_instance["id"], True)
        # TODO: technical_details are Observables
        if hasattr(victim_targeting, "technical_details") and victim_targeting.targeted_technical_details is not None:
            warn("The technical_details property of %s is not part of STIX 2.x", 418, identity_instance["id"])

        fill_in_extension_properties(identity_instance, container, extension_definition_id)


def convert_victim_targeting(victim_targeting, ttp, env, ttps_generated):
    identity_instance = convert_identity_for_victim_target(victim_targeting.identity, ttp, env, ttps_generated)
    info("%s generated an identity associated with a victim", 713, ttp.id_)
    handle_missing_properties_of_victim_target(identity_instance, victim_targeting)

    if ttps_generated:
        marking_refs = create_marking_union(ttp, victim_targeting.identity)
        for generated_ttp in ttps_generated:
            env.bundle_instance["relationships"].append(
                create_relationship(generated_ttp["id"], identity_instance["id"], env,
                                    "targets", marking_refs=marking_refs)
            )
        # the relationships has been created, so its not necessary to propagate it up
    return identity_instance


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
        new20 = convert_identity(obj, env, "from_env")
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


def maybe_split_parenthetical_ors_into_compound_observation_expressions(result):
    new_expression_operands = []
    for operand in result.operands:
        if operand.any_operand_contains_observed_expressions():
            new_expression_operands.append(operand)
        else:
            new_expression_operands.append(operand.wrap_as_observed_expression())
    return CompoundObservationExpressionForElevator("OR", new_expression_operands)


def finalize_bundle(env):
    bundle_instance = env.bundle_instance
    if _KILL_CHAINS_PHASES != {}:
        for ind20 in bundle_instance["indicators"]:
            if "kill_chain_phases" in ind20:
                fixed_kill_chain_phases = []
                for kcp in ind20["kill_chain_phases"]:
                    if isinstance(kcp, str):
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

    fix_markings()

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
                if isinstance(pattern, str):
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
                        if (isinstance(result, BooleanExpressionForElevator) and
                            result.operator == "OR" and
                                result.any_operand_contains_observed_expressions()):
                            result = maybe_split_parenthetical_ors_into_compound_observation_expressions(result)
                        if isinstance(result, CompoundObservationExpressionForElevator):
                            ind["pattern"] = "%s" % result
                        else:
                            ind["pattern"] = "[%s]" % result
                    else:
                        ind["pattern"] = str(final_pattern.partition_according_to_object_path())

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
                stix2x_id = get_id_value(value)

                if stix2x_id[0] is None:
                    warn("STIX 1.X ID: %s was not mapped to STIX 2.x ID", 603, value)
                    continue

                operation_on_path(bundle_instance, path, stix2x_id[0])
                info("Found STIX 1.X ID: %s replaced by %s", 702, value, stix2x_id[0])
            elif is_stix1x_id(value) and not exists_id_key(value):
                warn("STIX 1.X ID: %s was not mapped to STIX 2.x ID", 603, value)

    for item in reversed(to_remove):
        operation_on_path(bundle_instance, item, "", op=2)

    if "objects" in bundle_instance:
        remove_pattern_objects(bundle_instance)
    else:
        error("EMPTY BUNDLE -- No objects created from 1.x input document!", 208)


def get_identity_from_information_source(information_source, env, created_by_ref_source):
    if information_source:
        if information_source.identity is not None:
            return get_identity_ref(information_source.identity, env, created_by_ref_source)
        if information_source.contributing_sources is not None:
            if information_source.contributing_sources.source is not None:
                sources = information_source.contributing_sources.source

                if len(sources) > 1:
                    warn("Only one identity allowed - using first one.", 510)

                for source in sources:
                    if source.identity is not None:
                        return get_identity_ref(source.identity, env, created_by_ref_source)
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
        env.created_by_ref = get_identity_from_information_source(stix_package.stix_header.information_source, env, "this_identity")
    isa_marking = None
    isa_marking_assertions = []
    # Markings are processed in the beginning for handling later for each SDO.
    for marking_specification in navigator.iterwalk(stix_package):
        if isinstance(marking_specification, MarkingSpecification):
            stix2x_markings, isa_marking = convert_marking_specification(marking_specification,
                                                                         env,
                                                                         stix_package.id_,
                                                                         isa_marking,
                                                                         isa_marking_assertions)
            for marking in stix2x_markings:
                if (("definition_type" in marking and marking["definition_type"] != "ais") or
                        "extensions" in marking):
                    bundle_instance["objects"].append(marking)

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
