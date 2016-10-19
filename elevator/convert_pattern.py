# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

from cybox.core import Observable
from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI
from cybox.objects.email_message_object import EmailMessage
from cybox.objects.file_object import File
from cybox.objects.win_registry_key_object import WinRegistryKey
from cybox.objects.win_process_object import WinProcess
from cybox.objects.win_service_object import WinService
from cybox.objects.process_object import Process
from cybox.objects.domain_name_object import DomainName
from cybox.objects.mutex_object import Mutex
from cybox.objects.network_connection_object import NetworkConnection
from cybox.objects.win_executable_file_object import WinExecutableFile
from cybox.objects.archive_file_object import ArchiveFile

from elevator.utils import *
from elevator.vocab_mappings import *

OBSERVABLE_TO_PATTERN_MAPPING = {}


def clear_pattern_mapping():
    global OBSERVABLE_TO_PATTERN_MAPPING
    OBSERVABLE_TO_PATTERN_MAPPING = {}

KEEP_OBSERVABLE_DATA = False

# simulate dynamic variable environment

_DYNAMIC_SCOPING_ENV= {}

def intialize_dynamic_variable(var):
    global _DYNAMIC_SCOPING_ENV
    if var in  _DYNAMIC_SCOPING_ENV:
        raise Exception
    else:
        _DYNAMIC_SCOPING_ENV[var] = []


def set_dynamic_variable(var, value):
    global _DYNAMIC_SCOPING_ENV
    if var not in _DYNAMIC_SCOPING_ENV:
        intialize_dynamic_variable(var)
    _DYNAMIC_SCOPING_ENV[var].append(value)


def get_dynamic_variable(var):
    if var not in _DYNAMIC_SCOPING_ENV:
        raise Exception
    else:
        return _DYNAMIC_SCOPING_ENV[var][-1]


def pop_dynamic_variable(var):
    if var not in _DYNAMIC_SCOPING_ENV or not _DYNAMIC_SCOPING_ENV[var]:
        raise Exception
    else:
        _DYNAMIC_SCOPING_ENV[var].pop


def need_not(condition):
    return condition == "DoesNotContain"


def add_parens_if_needed(expr):
    if expr.find("AND") != -1 or expr.find("OR") != -1:
        return "(" + expr + ")"
    else:
        return expr


def convert_condition(condition):
    if condition == "Equals":
        return "="
    elif condition == "DoesNotEqual":
        return "!="
    elif condition == "Contains":
        return "="
    elif condition == "DoesNotContain":
        return "!="
    elif condition == "GreaterThan":
        return ">"
    elif condition == "GreaterThanOrEqual":
        return ">="
    elif condition == "LessThan":
        return "<"
    elif condition == "LessThanOrEqual":
        return "<="
    # StartsWith - handled in create_term_with_regex
    # EndsWith  - handled in create_term_with_regex
    # InclusiveBetween - handled in create_term_with_range
    # ExclusiveBetween - handled in create_term_with_range
    # FitsPattern
    # BitwiseAnd
    # BitwiseOr
    elif condition is None:
        warn("No condition given for " + identifying_info(get_dynamic_variable("current_observable")) + " - assume '='")
        return "="


def create_term_with_regex(lhs, condition, rhs):
    if condition == "StartsWith":
        return lhs + " MATCHES " + " /^" + rhs + "/"
    elif condition == "EndsWith":
        return lhs + " MATCHES " + " /" + rhs + "$/"
    elif condition == "Contains" or condition == "DoesNotContain":
        return lhs + " MATCHES " + " /" + rhs + "/"


def create_term_with_range(lhs, condition, rhs):
    if not isinstance(rhs, list) or len(rhs) != 2:
        error("{0} was used, but two values were not provided.".format(condition))
        return "'range term underspecified'"
    else:
        if condition == "InclusiveBetween":
            return "(" + lhs + " GE " + str(rhs[0]) + " AND " + lhs + " LE " + str(rhs[1]) + ")"
        else: # "ExclusiveBetween"
            return "(" + lhs + " GT " + str(rhs[0]) + " AND " + lhs + " LT " + str(rhs[1]) + ")"

def multi_valued_property(object_path):
    return object_path and object_path.find("*") != -1

def create_term(lhs, condition, rhs):
    if condition == "StartsWith" or condition == "EndsWith":
        return create_term_with_regex(lhs, condition, rhs)
    elif condition == "InclusiveBetween" or condition == "ExclusiveBetween":
        return create_term_with_range(lhs, condition, rhs)
    else:
        if (condition == "Contains" or condition == "DoesNotContain") and not multi_valued_property(lhs):
            warn("Used MATCHES operator for " + condition)
            return ("NOT " if condition == "DoesNotContain" else "") + create_term_with_regex(lhs, condition, rhs)
        return lhs + " " + convert_condition(condition) + " '" + str(rhs) + "'"


def add_comparison_expression(prop, object_path, first):
    if prop is not None:
        if hasattr(prop, "condition"):
            cond = prop.condition
        else:
            warn("No condition given - assume EQ")
            cond = None
        comparison_expression = create_term(object_path, cond, prop.value)
        return (" AND " if first else "") + comparison_expression
    return ""


def convert_address_to_pattern(add):
    if add.category == add.CAT_IPV4:
        return create_term("ipv4-addr:value", add.address_value.condition, add.address_value.value)
    elif add.category == add.CAT_IPV6:
        return create_term("ipv6-addr:value", add.address_value.condition, add.address_value.value)
    elif add.category == add.CAT_MAC:
        return create_term("mac-addr:value", add.address_value.condition, add.address_value.value)
    elif add.category == add.CAT_EMAIL:
        return create_term("email-addr:value", add.address_value.condition, add.address_value.value)
    else:
        warn("The address type " + add.category + " is not part of Cybox 3.0")


def convert_uri_to_pattern(uri):
    return create_term("url:value", uri.value.condition, uri.value.value)

_EMAIL_HEADER_PROPERTIES = [ ["email-message:subject", [ "subject" ]],
                             ["email-message:from_ref", [ "from_", "address_value"]],
                             ["email-message:sender_ref", [ "sender" ]],
                             ["email-message:date", [ "date"]],
                             ["email-message:content_type", [ "content_type"]],
                             ["email-message:to_refs[*]", [ "to*", "address_value" ]],
                             ["email-message:cc_refs[*]", [ "cc*", "address_value" ]],
                             ["email-message:bcc_refs[*]", [ "bcc*", "address_value"]] ]

def cannonicalize_prop_name(name):
    if name.find("*") == -1:
        return name
    else:
        return name[:-1]

def create_terms_from_prop_list(prop_list, obj, object_path):
    if len(prop_list) == 1:
        prop_1x = prop_list[0]
        if hasattr(obj, cannonicalize_prop_name(prop_1x)):
            if multi_valued_property(prop_1x):
                prop_expr = ""
                for c in getattr(obj, cannonicalize_prop_name(prop_1x)):
                    prop_expr += add_comparison_expression(c, object_path, (prop_expr != ""), "OR")
                return prop_expr
            else:
                return add_comparison_expression(getattr(obj, cannonicalize_prop_name(prop_1x)), object_path, False)
    else:
        prop_1x, rest_of_prop_list = prop_list[0], prop_list[1:]
        if hasattr(obj, cannonicalize_prop_name(prop_1x)):
            if multi_valued_property(prop_1x):
                prop_expr = ""
                values = getattr(obj, cannonicalize_prop_name(prop_1x))
                if values:
                    for c in values:
                        prop_expr += (" OR " if prop_expr != "" else "") + create_terms_from_prop_list(rest_of_prop_list, c, object_path)
                return prop_expr
            else:
                return create_terms_from_prop_list(rest_of_prop_list, getattr(obj, cannonicalize_prop_name(prop_1x)), object_path)

def convert_email_header_to_pattern(head):
    header_expression = ""
    for prop_spec in _EMAIL_HEADER_PROPERTIES:
        object_path = prop_spec[0]
        prop_1x_list = prop_spec[1]
        if hasattr(head, cannonicalize_prop_name(prop_1x_list[0])):
            term = create_terms_from_prop_list(prop_1x_list, head, object_path)
            if term:
                header_expression += (" AND " if header_expression != "" else "") + term
    return header_expression

def convert_email_message_to_pattern(mess):
    expression = ""
    if mess.header is not None:
        expression += convert_email_header_to_pattern(mess.header)
    if mess.attachments is not None:
        warn("email attachments not handled yet")
    return expression

_PE_FILE_HEADER_PROPERTIES = [ ["machine", "file:extended_properties.windows_pebinary_ext.file_header:machine"],
                               ["time_date_stamp", "file:extended_properties.windows_pebinary_ext.file_header.time_date_stamp"],
                               ["number_of_sections", "file:extended_properties.windows_pebinary_ext.file_header.number_of_sections"],
                               ["pointer_to_symbol_table", "file:extended_properties.windows_pebinary_ext.file_header.pointer_to_symbol_table"],
                               ["number_of_symbols", "file:extended_properties.windows_pebinary_ext.file_header.number_of_symbols"],
                               ["size_of_optional_header", "file:extended_properties.windows_pebinary_ext.file_header.size_of_optional_header"],
                               ["characteristics", "file:extended_properties.windows_pebinary_ext.file_header.characteristics"]]

_PE_SECTION_HEADER_PROPERTIES = [ ["name", "file:extended_properties.windows_pebinary_ext.section[*].name"],
                                  ["virtual_size", "file:extended_properties.windows_pebinary_ext.section[*].size" ]]

_ARCHIVE_FILE_PROPERTIES = [ ["comment", "file:extended_properties.archive_file.comment"],
                             ["version", "file:extended_properties.archive_file.version" ]]


def convert_windows_executable_file_to_pattern(file):
    expression = ""
    if file.headers:
        file_header = file.headers.file_header
        if file_header:
            file_header_expression = ""
            for prop_spec in _PE_FILE_HEADER_PROPERTIES:
                prop_1x = prop_spec[0]
                object_path = prop_spec[1]
                if hasattr(file_header, prop_1x):
                    file_header_expression += add_comparison_expression(getattr(file_header, prop_1x), object_path, (file_header_expression != ""))
            if file_header.hashes is not None:
                hash_expression = convert_hashes_to_pattern(file_header.hashes)
                if hash_expression:
                    file_header_expression += (" AND " if file_header_expression != "" else "") + hash_expression
        expression += (" AND " if expression != "" else "") + add_parens_if_needed(file_header_expression)
        if file.headers.optional_header:
            warn("file:extended_properties:windows_pebinary_ext:optional_header is not implemented yet")

    if file.type_:
        expression += (" AND " if expression != "" else "") + \
                      create_term("file:extended_properties.windows_pebinary_ext.pe_type",
                                  file.type_.condition,
                                  map_vocabs_to_label(file.type_.value, WINDOWS_PEBINARY))
    sections = file.sections
    if sections:
        sections_expression = ""
        # should order matter in patterns???
        for s in sections:
            section_expression = ""
            if s.section_header:
                for prop_spec in _PE_SECTION_HEADER_PROPERTIES:
                    prop_1x = prop_spec[0]
                    object_path = prop_spec[1]
                    if hasattr(s.section_header, prop_1x):
                        section_expression += add_comparison_expression(getattr(s.section_header, prop_1x), object_path, (section_expression != ""))
            if s.entropy:
                section_expression += (" AND " if section_expression != "" else "") + \
                                      create_term("file:extended_properties.windows_pebinary_ext.section[*].entropy",
                                                    s.entropy.condition,
                                                    s.entropy.value)
            if s.data_hashes:
                hash_expression1 = convert_hashes_to_pattern(s.data_hashes)
            hash_expression = ""
            if s.header_hashes:
                hash_expression += (" AND " if hash_expression1 != hash_expression1 else "") + convert_hashes_to_pattern(s.header_hashes)
            if hash_expression:
                section_expression += (" AND " if section_expression != "" else "") + add_parens_if_needed(hash_expression)
            sections_expression += (" AND " if sections_expression != "" else "") + section_expression
        expression += (" AND " if expression != "" else "") + add_parens_if_needed(section_expression)
    if file.exports:
        warn("The exports property of WinExecutableFileObj is not part of Cybox 3.0")
    if file.imports:
        warn("The imports property of WinExecutableFileObj is not part of Cybox 3.0")
    return expression


def convert_archive_file_to_pattern(file):
    expression = ""
    for prop_spec in _ARCHIVE_FILE_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(file, prop_1x):
            expression += add_comparison_expression(getattr(file, prop_1x), object_path, (expression != ""))
    return expression


def convert_hashes_to_pattern(hashes):
    hash_expression = ""
    for hash in hashes:
        hash_expression += (" OR " if not hash_expression == "" else "") + \
                           create_term("file:hashes" + ":" + str(hash.type_).lower(),
                                       hash.simple_hash_value.condition,
                                       hash.simple_hash_value.value)
    return hash_expression


def convert_file_name_and_path_to_pattern(file):
    file_name_path_expression = ""
    if file.file_name:
        file_name_path_expression += create_term("file:file_name", file.file_name.condition, file.file_name.value)
    if file.file_path:
        if file.device_path:
            file_name_path_expression += (" AND " if file_name_path_expression != "" else "") + \
                                            create_term("file:parent_directory_ref.name",
                                                        file.file_path.condition,
                                                        file.device_path.value + file.file_path.value)
    if file.full_path:
        warn("1.x full file paths are not processed, yet")
    return file_name_path_expression



_FILE_PROPERTIES = [ ["size_in_bytes", "file:size"],
                     ["magic_number", "file:magic_number_hex"],
                     ["created_time", "file:created"],
                     ["modified_time", "file:modified"],
                     ["accessed_time", "file:accessed"],
                     ["encyption_algorithm", "file:encyption_algorithm"],
                     ["decryption_key", "file:decryption_key" ]]


def convert_file_to_pattern(file):
    expression = ""
    if file.hashes is not None:
        hash_expression = convert_hashes_to_pattern(file.hashes)
        if hash_expression:
            expression += hash_expression
    expression += convert_file_name_and_path_to_pattern(file)
    for prop_spec in _FILE_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(file, prop_1x):
            expression += add_comparison_expression(getattr(file, prop_1x), object_path, (expression != ""))
    if isinstance(file, WinExecutableFile):
        expression += (" AND " if expression != "" else "") + add_parens_if_needed(convert_windows_executable_file_to_pattern(file))
    if isinstance(file, ArchiveFile):
        expression += (" AND " if expression != "" else "") + add_parens_if_needed(convert_archive_file_to_pattern(file))
    return expression

_REGISTRY_KEY_VALUES_PROPERTIES = [["data", "win-registry-key:values[*].data"],
                                    ["name", "win-registry-key:values[*].name"],
                                    ["datatype", "win-registry-key:values[*].data_type" ]]


def convert_registry_key_to_pattern(reg_key):
    first_one = True
    expression = ""
    if reg_key.key:
        key_value_term = ""
        if reg_key.hive:
            if reg_key.hive.condition is None:
                key_value_term += reg_key.hive.value + "\\"
            else:
                warn("Condition on a hive property not handled")
            key_value_term += reg_key.key.value
            expression += create_term("win-registry-key:key", reg_key.key.condition,  key_value_term)
    if reg_key.values:
        values_expression = ""
        for v in reg_key.values:
            value_expression = ""
            for prop_spec in _REGISTRY_KEY_VALUES_PROPERTIES:
                prop_1x = prop_spec[0]
                object_path = prop_spec[1]
                if hasattr(v, prop_1x):
                    value_expression += add_comparison_expression(getattr(v, prop_1x), object_path, (value_expression != ""))
            values_expression += (" OR " if values_expression != "" else "") + value_expression
        expression += (" AND " if expression != "" else "") + add_parens_if_needed(values_expression)
    return expression


def convert_process_to_pattern(process):
    expression = ""
    if process.name:
        expression += (" AND " if expression != "" else "") + \
                      create_term("process:name", process.name.condition, process.name.value)
    if isinstance(process, WinProcess):
        win_process_expression = convert_windows_process_to_pattern(process)
        if win_process_expression:
            expression += (" AND " if expression != "" else "") + add_parens_if_needed(win_process_expression)
        if isinstance(process, WinService):
            service_expression = convert_windows_service_to_pattern(process)
            if service_expression:
                expression += (" AND " if expression != "" else "") + add_parens_if_needed(service_expression)
    return expression


def convert_windows_process_to_pattern(process):
    expression = ""
    if process.handle_list:
        for h in process.handle_list:
            warn("Window handles are not a part of CybOX 3.0")
    return expression

_WINDOWS_PROCESS_PROPERTIES = [ ["service_name", "process:extension_data.windows_service_ext.service_name"],
                                ["display_name", "process:extension_data.windows_service_ext.display_name"],
                                ["startup_command_line", "process:extension_data.windows_service_ext.startup_command_line"],
                                ["start_type", "process:extension_data.windows_service_ext.start_type"],
                                ["service_type", "process:extension_data.windows_service_ext.service_type"],
                                ["service_status", "process:extension_data.windows_service_ext.service_status" ]]


def convert_windows_service_to_pattern(service):
    expression = ""
    for prop_spec in _WINDOWS_PROCESS_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(service, prop_1x):
            expression += add_comparison_expression(getattr(service, prop_1x), object_path, (expression != ""))
    if hasattr(service, "description_list") and service.description_list:
        description_expression = ""
        for d in service.description_list:
            description_expression += (" OR " if not description_expression == "" else "") + \
                           create_term("process:extension_data.windows_service_ext.descriptions[*]",
                                       d.condition,
                                       d.value)
        expression += (" AND " if expression != "" else "") + description_expression
    if hasattr(service, "service_dll") and service.service_dll:
        warn("WinServiceObject.service_dll cannot be converted to a pattern, yet.")
    return expression

####################################################################################################################


def convert_observable_composition_to_pattern(obs_comp, bundleInstance, observable_mapping):
    expression = []
    for obs in obs_comp.observables:
        term = convert_observable_to_pattern(obs, bundleInstance, observable_mapping)
        if term:
            expression.append(term)
        else:
            warn("No term was yielded for {0}".format((obs.id_ if obs.id_ else obs.idref)))
    if expression:
        operator_as_string = " " + obs_comp.operator + " "
        return "(" + operator_as_string.join(expression) + ")"
    else:
        return ""


def convert_domain_name_to_pattern(domain_name):
    return create_term("domain-name:value", domain_name.value.condition, domain_name.value.value)


def convert_mutex_to_pattern(mutex):
    return create_term("mutex:name", mutex.name.condition, mutex.name.value)


def convert_network_connection_to_pattern(conn):
    # TODO: Implement pattern
    return "'term not converted'"


def convert_object_to_pattern(obj):
    prop = obj.properties

    if isinstance(prop, Address):
        return convert_address_to_pattern(prop)
    elif isinstance(prop, URI):
        return convert_uri_to_pattern(prop)
    elif isinstance(prop, EmailMessage):
        return convert_email_message_to_pattern(prop)
    elif isinstance(prop, File):
        return convert_file_to_pattern(prop)
    elif isinstance(prop, WinRegistryKey):
        return convert_registry_key_to_pattern(prop)
    elif isinstance(prop, Process):
        return convert_process_to_pattern(prop)
    elif isinstance(prop, DomainName):
        return convert_domain_name_to_pattern(prop)
    elif isinstance(prop, Mutex):
        return convert_mutex_to_pattern(prop)
    elif isinstance(prop, NetworkConnection):
        return convert_network_connection_to_pattern(prop)
    else:
        warn("{0} cannot be converted to a pattern, yet.".format(str(obj.properties)))
        return "'term not converted'"


def match_1x_id_with_20_id(id_1x, id_20):
    id_1x_split = id_1x.split("-", 1)
    id_20_split = id_20.split("--")
    return id_1x_split[1] == id_20_split[1]


def find_observable_data(idref, obserableData):
    for obs in obserableData:
        if match_1x_id_with_20_id(idref, obs["id"]):
            info("Found observed_data for {0}".format(idref))
            return obs
    # warn (idref + " cannot be resolved")
    return None


def negate_expression(obs):
    return hasattr(obs, "negate") and obs.negate


def convert_observable_to_pattern(obs, bundleInstance, observable_mapping):
    try:
        set_dynamic_variable("current_observable", obs)
        return ("NOT (" if negate_expression(obs) else "") + \
               convert_observable_to_pattern_without_negate(obs, bundleInstance, observable_mapping) + \
               (")" if negate_expression(obs) else "")
    finally:
        pop_dynamic_variable("current_observable")



def convert_observable_to_pattern_without_negate(obs, bundleInstance, id_to_observable_mapping):
    global OBSERVABLE_TO_PATTERN_MAPPING
    if obs.observable_composition is not None:
        pattern = convert_observable_composition_to_pattern(obs.observable_composition,
                                                            bundleInstance,
                                                            id_to_observable_mapping)
        if pattern and obs.id_:
            OBSERVABLE_TO_PATTERN_MAPPING[obs.id_] = pattern
        return pattern
    elif obs.object_ is not None:
        pattern = convert_object_to_pattern(obs.object_)
        OBSERVABLE_TO_PATTERN_MAPPING[obs.id_] = pattern
        return pattern
    elif obs.idref is not None:
        if obs.idref in OBSERVABLE_TO_PATTERN_MAPPING:
            return OBSERVABLE_TO_PATTERN_MAPPING[obs.idref]
        else:
            # resolve now if possible, and remove from observed_data
            observableDataInstance = find_observable_data(obs.idref, bundleInstance["observed_data"])
            if observableDataInstance is not None:
                if not KEEP_OBSERVABLE_DATA:
                    bundleInstance["observed_data"].remove(observableDataInstance)
                    # TODO: remove from the report's object_refs
                if obs.idref in id_to_observable_mapping:
                    return convert_observable_to_pattern(id_to_observable_mapping[obs.idref], bundleInstance, id_to_observable_mapping)
            return "PLACEHOLDER:" + obs.idref


# patterns can contain idrefs which might need to be resolved because the order in which the ids and idrefs appear
def interatively_resolve_placeholder_refs():
    global OBSERVABLE_TO_PATTERN_MAPPING
    if not OBSERVABLE_TO_PATTERN_MAPPING:
        return
    done = False
    while not done:
        # collect all of the fully resolved idrefs
        fully_resolved_idrefs = []
        for idref, expr in OBSERVABLE_TO_PATTERN_MAPPING.items():
            if expr.find("PLACEHOLDER:") == -1:
                # no PLACEHOLDER idrefs found in the expr, means this idref is fully resolved
                fully_resolved_idrefs.append(idref)
        # replace only fully resolved idrefs
        change_made = False
        for fr_idref in fully_resolved_idrefs:
            for idref, expr in OBSERVABLE_TO_PATTERN_MAPPING.items():
                if expr.find("PLACEHOLDER:" + fr_idref) != -1:
                    # a change will be made, which could introduce a new placeholder id into the expr
                    change_made = True
                    OBSERVABLE_TO_PATTERN_MAPPING[idref] = expr.replace("PLACEHOLDER:" + fr_idref, OBSERVABLE_TO_PATTERN_MAPPING[fr_idref])
        done = not change_made


def fix_pattern(pattern):
    if not OBSERVABLE_TO_PATTERN_MAPPING == {}:
        #info(str(OBSERVABLE_TO_PATTERN_MAPPING))
        #info("pattern is: " +  pattern)
        for idref in OBSERVABLE_TO_PATTERN_MAPPING.keys():
            # TODO: this can probably be done in place
            pattern = pattern.replace("PLACEHOLDER:" + idref, OBSERVABLE_TO_PATTERN_MAPPING[idref])
    return pattern