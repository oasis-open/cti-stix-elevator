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
from elevator.ids import *

PATTERN_CACHE = {}

KEEP_OBSERVABLE_DATA_USED_IN_PATTERNS = False

KEEP_INDICATORS_USED_IN_COMPOSITE_INDICATOR_EXPRESSION = True


def clear_pattern_mapping():
    global PATTERN_CACHE
    PATTERN_CACHE = {}


def add_to_pattern_cache(key, pattern):
    global PATTERN_CACHE
    PATTERN_CACHE[key] = pattern

# simulate dynamic variable environment


_DYNAMIC_SCOPING_ENV = {}


def intialize_dynamic_variable(var):
    global _DYNAMIC_SCOPING_ENV
    if var in _DYNAMIC_SCOPING_ENV:
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


_CLASS_NAME_MAPPING = {"File": "file",
                       "URI": "uri",
                       "EmailMessage": "email-message",
                       "WinRegistryKey": "win-registry-key",
                       "Process": "process",
                       "DomainName": "domain_name",
                       "Mutex": "mutex"}


# address, network_connection


def convert_cybox_class_name_to_object_path_root_name(instance):
    class_name = instance.__class__.__name__
    if class_name in _CLASS_NAME_MAPPING:
        return _CLASS_NAME_MAPPING[class_name]
    else:
        error("Cannot convert cybox 2.x class name {name} to an object_path_root_name".format(name=class_name))
        return None


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


def create_term_with_regex(lhs, condition, rhs, negated):
    if condition == "StartsWith":
        pattern = " /^" + rhs + "/"
    elif condition == "EndsWith":
        pattern = " /" + rhs + "$/"
    elif condition == "Contains" or condition == "DoesNotContain":
        pattern = " /" + rhs + "/"
    return lhs + (" NOT MATCHES " if negated else " MATCHES ") + pattern

def create_term_with_range(lhs, condition, rhs, negated=False):
    # TODO: handle negated
    if not isinstance(rhs, list) or len(rhs) != 2:
        error("{0} was used, but two values were not provided.".format(condition))
        return "'range term underspecified'"
    else:
        if condition == "InclusiveBetween":
            return "(" + lhs + " GE " + str(rhs[0]) + " AND " + lhs + " LE " + str(rhs[1]) + ")"
        else:  # "ExclusiveBetween"
            return "(" + lhs + " GT " + str(rhs[0]) + " AND " + lhs + " LT " + str(rhs[1]) + ")"


def multi_valued_property(object_path):
    return object_path and object_path.find("*") != -1


def negate_if_needed(condition, negated):
    if negated:
        return "NOT " + condition
    else:
        return condition


def create_term(lhs, condition, rhs, negated=False):
    if condition == "StartsWith" or condition == "EndsWith":
        return create_term_with_regex(lhs, condition, rhs, negated)
    elif condition == "InclusiveBetween" or condition == "ExclusiveBetween":
        return create_term_with_range(lhs, condition, rhs, negated)
    else:
        if condition == "Contains" and not multi_valued_property(lhs):
            warn("Used MATCHES operator for " + condition)
            return (create_term_with_regex(lhs, condition, rhs, negated))
        elif condition == "DoesNotContain":
            warn("Used MATCHES operator for " + condition)
            return (create_term_with_regex(lhs, condition, rhs, not negated))
        return lhs + " " + negate_if_needed(convert_condition(condition), negated) + " '" + convert_to_str(rhs) + "'"


def add_comparison_expression(prop, object_path):
    if prop is not None:
        if hasattr(prop, "condition"):
            cond = prop.condition
        else:
            warn("No condition given - assume ==")
            cond = None
        return create_term(object_path, cond, prop.value)
    return ""


def convert_custom_properties(cps, object_type_name):
    expressions = []
    for cp in cps.property_:
        expressions.append(create_term(object_type_name + ":x_" + cp.name, cp.condition, cp.value))
    return " AND ".join(expressions)


def convert_address_to_pattern(add):
    cond = add.address_value.condition
    if add.category == add.CAT_IPV4:
        return create_term("ipv4-addr:value", cond, add.address_value.value)
    elif add.category == add.CAT_IPV6:
        return create_term("ipv6-addr:value", cond, add.address_value.value)
    elif add.category == add.CAT_MAC:
        return create_term("mac-addr:value", cond, add.address_value.value)
    elif add.category == add.CAT_EMAIL:
        return create_term("email-addr:value", cond, add.address_value.value)
    else:
        warn("The address type " + add.category + " is not part of Cybox 3.0")


def convert_uri_to_pattern(uri):
    return create_term("url:value", uri.value.condition, uri.value.value)

# NOTICE:  The format of these PROPERTIES is different than the others in this file!!!!!!
_EMAIL_HEADER_PROPERTIES = [["email-message:subject", ["subject"]],
                            ["email-message:from_ref", ["from_", "address_value"]],
                            ["email-message:sender_ref", ["sender", "address_value"]],
                            ["email-message:date", ["date"]],
                            ["email-message:content_type", ["content_type"]],
                            ["email-message:to_refs[*]", ["to*", "address_value"]],
                            ["email-message:cc_refs[*]", ["cc*", "address_value"]],
                            ["email-message:bcc_refs[*]", ["bcc*", "address_value"]]]


_EMAIL_ADDITIONAL_HEADERS_PROPERTIES = \
    [["email-message:additional_header_fields:Reply-To", ["reply-to*", "address_value"]],
     ["email-message:additional_header_fields:Message_ID", ["message_id"]],
     ["email-message:additional_header_fields:X_Mailer", ["x_mailer"]]]


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
                prop_exprs = []
                for c in getattr(obj, cannonicalize_prop_name(prop_1x)):
                    prop_exprs.append(add_comparison_expression(c, object_path))
                return " OR ".join(prop_exprs)
            else:
                return add_comparison_expression(getattr(obj, cannonicalize_prop_name(prop_1x)), object_path)
    else:
        prop_1x, rest_of_prop_list = prop_list[0], prop_list[1:]
        if hasattr(obj, cannonicalize_prop_name(prop_1x)):
            if multi_valued_property(prop_1x):
                prop_exprs = []
                values = getattr(obj, cannonicalize_prop_name(prop_1x))
                if values:
                    for c in values:
                        prop_exprs.append(create_terms_from_prop_list(rest_of_prop_list, c, object_path))
                return " OR ".join(prop_exprs)
            else:
                return create_terms_from_prop_list(rest_of_prop_list,
                                                   getattr(obj, cannonicalize_prop_name(prop_1x)),
                                                   object_path)


def convert_email_header_to_pattern(head, properties):
    header_expressions = []
    for prop_spec in properties:
        object_path = prop_spec[0]
        prop_1x_list = prop_spec[1]
        if hasattr(head, cannonicalize_prop_name(prop_1x_list[0])):
            term = create_terms_from_prop_list(prop_1x_list, head, object_path)
            if term:
                header_expressions.append(term)
    return " AND ".join(header_expressions)


def convert_email_message_to_pattern(mess):
    expressions = []
    if mess.header is not None:
        expressions.append(convert_email_header_to_pattern(mess.header, _EMAIL_HEADER_PROPERTIES))
        add_headers = convert_email_header_to_pattern(mess.header, _EMAIL_ADDITIONAL_HEADERS_PROPERTIES)
        if add_headers:
            expressions.append(add_headers)
    if mess.attachments is not None:
        warn("Email attachments not handled yet")
    return " AND ".join(expressions)


_PE_FILE_HEADER_PROPERTIES = \
    [["machine", "file:extended_properties.windows_pebinary_ext.file_header:machine"],
     ["time_date_stamp", "file:extended_properties.windows_pebinary_ext.file_header.time_date_stamp"],
     ["number_of_sections", "file:extended_properties.windows_pebinary_ext.file_header.number_of_sections"],
     ["pointer_to_symbol_table", "file:extended_properties.windows_pebinary_ext.file_header.pointer_to_symbol_table"],
     ["number_of_symbols", "file:extended_properties.windows_pebinary_ext.file_header.number_of_symbols"],
     ["size_of_optional_header", "file:extended_properties.windows_pebinary_ext.file_header.size_of_optional_header"],
     ["characteristics", "file:extended_properties.windows_pebinary_ext.file_header.characteristics"]]


_PE_SECTION_HEADER_PROPERTIES = [["name", "file:extended_properties.windows_pebinary_ext.section[*].name"],
                                 ["virtual_size", "file:extended_properties.windows_pebinary_ext.section[*].size"]]


_ARCHIVE_FILE_PROPERTIES = [["comment", "file:extended_properties.archive_file.comment"],
                            ["version", "file:extended_properties.archive_file.version"]]


def convert_windows_executable_file_to_pattern(file):
    expressions = []
    if file.headers:
        file_header = file.headers.file_header
        if file_header:
            file_header_expressions = []
            for prop_spec in _PE_FILE_HEADER_PROPERTIES:
                prop_1x = prop_spec[0]
                object_path = prop_spec[1]
                if hasattr(file_header, prop_1x) and getattr(file_header, prop_1x):
                    file_header_expressions.append(add_comparison_expression(getattr(file_header, prop_1x),
                                                                             object_path))
            if file_header.hashes is not None:
                hash_expression = convert_hashes_to_pattern(file_header.hashes)
                if hash_expression:
                    file_header_expressions.append(hash_expression)
            if file_header_expressions:
                expressions.append(add_parens_if_needed(" AND ".join(file_header_expressions)))
        if file.headers.optional_header:
            warn("file:extended_properties:windows_pebinary_ext:optional_header is not implemented yet")

    if file.type_:
        expressions.append(create_term("file:extended_properties.windows_pebinary_ext.pe_type",
                                       file.type_.condition,
                                       map_vocabs_to_label(file.type_.value, WINDOWS_PEBINARY)))
    sections = file.sections
    if sections:
        sections_expressions = []
        # should order matter in patterns???
        for s in sections:
            section_expressions = []
            if s.section_header:
                for prop_spec in _PE_SECTION_HEADER_PROPERTIES:
                    prop_1x = prop_spec[0]
                    object_path = prop_spec[1]
                    if hasattr(s.section_header, prop_1x) and getattr(s.section_header, prop_1x):
                        section_expressions.append(add_comparison_expression(getattr(s.section_header, prop_1x),
                                                                             object_path))
            if s.entropy:
                section_expressions.append(create_term("file:extended_properties.windows_pebinary_ext.section[*].entropy",
                                                       s.entropy.condition,
                                                       s.entropy.value))
            if s.data_hashes:
                section_expressions.append(convert_hashes_to_pattern(s.data_hashes))
            hash_expression = ""
            if s.header_hashes:
                section_expressions.append(convert_hashes_to_pattern(s.header_hashes))
            sections_expressions.append(" AND ".join(section_expressions))
        expressions.append(add_parens_if_needed(" AND ".join(sections_expressions)))
    if file.exports:
        warn("The exports property of WinExecutableFileObj is not part of Cybox 3.0")
    if file.imports:
        warn("The imports property of WinExecutableFileObj is not part of Cybox 3.0")
    return " AND ".join(expressions)


def convert_archive_file_to_pattern(file):
    and_expressions = []
    for prop_spec in _ARCHIVE_FILE_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(file, prop_1x):
            and_expressions.append(add_comparison_expression(getattr(file, prop_1x), object_path))
    return " AND ".join(and_expressions)


def convert_hashes_to_pattern(hashes):
    hash_expressions = []
    for h in hashes:
        if getattr(h, "simple_hash_value"):
            hash_value = h.simple_hash_value
        else:
            hash_value = h.fuzzy_hash_value
        hash_expressions.append(create_term("file:hashes" + ":" + str(h.type_).lower(),
                                            hash_value.condition,
                                            hash_value.value))
    return " OR ".join(hash_expressions)


def convert_file_name_and_path_to_pattern(file):
    file_name_path_expressions = []
    if file.file_name:
        file_name_path_expressions.append(create_term("file:file_name", file.file_name.condition, file.file_name.value))
    if file.file_path:
        if file.device_path:
            file_name_path_expressions.append(create_term("file:parent_directory_ref.name",
                                                          file.file_path.condition,
                                                          file.device_path.value + file.file_path.value))
    if file.full_path:
        warn("1.x full file paths are not processed, yet")
    return " AND ".join(file_name_path_expressions)


_FILE_PROPERTIES = [["size_in_bytes", "file:size"],
                    ["magic_number", "file:magic_number_hex"],
                    ["created_time", "file:created"],
                    ["modified_time", "file:modified"],
                    ["accessed_time", "file:accessed"],
                    ["encyption_algorithm", "file:encyption_algorithm"],
                    ["decryption_key", "file:decryption_key"]]


def convert_file_to_pattern(file):
    expressions = []
    if file.hashes is not None:
        hash_expression = convert_hashes_to_pattern(file.hashes)
        if hash_expression:
            expressions.append(hash_expression)
    file_name_and_path_expression = convert_file_name_and_path_to_pattern(file)
    if file_name_and_path_expression:
        expressions.append(file_name_and_path_expression)
    properties_expressions = []
    for prop_spec in _FILE_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(file, prop_1x) and getattr(file, prop_1x):
            properties_expressions.append(add_comparison_expression(getattr(file, prop_1x), object_path))
    if properties_expressions:
        expressions.append(" AND ".join(properties_expressions))
    if isinstance(file, WinExecutableFile):
        expressions.append(add_parens_if_needed(convert_windows_executable_file_to_pattern(file)))
    if isinstance(file, ArchiveFile):
        expressions.append(add_parens_if_needed(convert_archive_file_to_pattern(file)))
    return " AND ".join(expressions)

_REGISTRY_KEY_VALUES_PROPERTIES = [["data", "win-registry-key:values[*].data"],
                                   ["name", "win-registry-key:values[*].name"],
                                   ["datatype", "win-registry-key:values[*].data_type"]]


def convert_registry_key_to_pattern(reg_key):
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
            value_expression = []
            for prop_spec in _REGISTRY_KEY_VALUES_PROPERTIES:
                prop_1x = prop_spec[0]
                object_path = prop_spec[1]
                if hasattr(v, prop_1x) and getattr(v, prop_1x):
                    value_expression.append(add_comparison_expression(getattr(v, prop_1x),
                                                                      object_path))
            values_expression += " OR ".join(value_expression)
        expression += (" AND " if expression != "" else "") + add_parens_if_needed(values_expression)
    return expression


def convert_process_to_pattern(process):
    expressions = []
    if process.name:
        expressions.append(create_term("process:name", process.name.condition, process.name.value))
    if isinstance(process, WinProcess):
        win_process_expression = convert_windows_process_to_pattern(process)
        if win_process_expression:
            expressions.append(add_parens_if_needed(win_process_expression))
        if isinstance(process, WinService):
            service_expression = convert_windows_service_to_pattern(process)
            if service_expression:
                expressions.append(add_parens_if_needed(service_expression))
    return " AND ".join(expressions)


def convert_windows_process_to_pattern(process):
    expression = ""
    if process.handle_list:
        for h in process.handle_list:
            warn("Window handles are not a part of CybOX 3.0")
    return expression

_WINDOWS_PROCESS_PROPERTIES = \
    [["service_name", "process:extension_data.windows_service_ext.service_name"],
     ["display_name", "process:extension_data.windows_service_ext.display_name"],
     ["startup_command_line", "process:extension_data.windows_service_ext.startup_command_line"],
     ["start_type", "process:extension_data.windows_service_ext.start_type"],
     ["service_type", "process:extension_data.windows_service_ext.service_type"],
     ["service_status", "process:extension_data.windows_service_ext.service_status"]]


def convert_windows_service_to_pattern(service):
    expressions = []
    for prop_spec in _WINDOWS_PROCESS_PROPERTIES:
        prop_1x = prop_spec[0]
        object_path = prop_spec[1]
        if hasattr(service, prop_1x) and getattr(service, prop_1x):
            expressions.append(add_comparison_expression(getattr(service, prop_1x), object_path))
    if hasattr(service, "description_list") and service.description_list:
        description_expressions = []
        for d in service.description_list:
            description_expressions.append(create_term("process:extension_data.windows_service_ext.descriptions[*]",
                                                       d.condition,
                                                       d.value))
        if description_expressions:
            expressions.append(" OR ".join(description_expressions))
    if hasattr(service, "service_dll") and service.service_dll:
        warn("WinServiceObject.service_dll cannot be converted to a pattern, yet.")
    return " AND ".join(expressions)

####################################################################################################################


def convert_observable_composition_to_pattern(obs_comp, bundle_instance, observable_mapping):
    expression = []
    for obs in obs_comp.observables:
        term = convert_observable_to_pattern(obs, bundle_instance, observable_mapping)
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
    if mutex.name:
        return create_term("mutex:name", mutex.name.condition, mutex.name.value)
    else:
        return ""


def convert_network_connection_to_pattern(conn):
    # TODO: Implement pattern
    return "'term not converted'"


def convert_object_to_pattern(obj, obs_id):
    prop = obj.properties

    if isinstance(prop, Address):
        expression = convert_address_to_pattern(prop)
    elif isinstance(prop, URI):
        expression = convert_uri_to_pattern(prop)
    elif isinstance(prop, EmailMessage):
        expression = convert_email_message_to_pattern(prop)
    elif isinstance(prop, File):
        expression = convert_file_to_pattern(prop)
    elif isinstance(prop, WinRegistryKey):
        expression = convert_registry_key_to_pattern(prop)
    elif isinstance(prop, Process):
        expression = convert_process_to_pattern(prop)
    elif isinstance(prop, DomainName):
        expression = convert_domain_name_to_pattern(prop)
    elif isinstance(prop, Mutex):
        expression = convert_mutex_to_pattern(prop)
    elif isinstance(prop, NetworkConnection):
        expression = convert_network_connection_to_pattern(prop)
    else:
        warn("{0} found in {1} cannot be converted to a pattern, yet.".format(str(obj.properties), obs_id))
        return "'term not converted'"
    if prop.custom_properties is not None:
        expression += (" AND " if expression != "" else "") + \
                      convert_custom_properties(prop.custom_properties,
                                                convert_cybox_class_name_to_object_path_root_name(prop))
    return expression


def match_1x_id_with_20_id(id_1x, id_20):
    id_1x_split = id_1x.split("-", 1)
    id_20_split = id_20.split("--")
    return id_1x_split[1] == id_20_split[1]


def find_definition(idref, sdos):
    for obs in sdos:
        if match_1x_id_with_20_id(idref, obs["id"]):
            info("Found definition for {0}".format(idref))
            return obs
    # warn (idref + " cannot be resolved")
    return None


def negate_expression(obs):
    return hasattr(obs, "negate") and obs.negate


def convert_observable_to_pattern(obs, bundle_instance, observable_mapping):
    try:
        set_dynamic_variable("current_observable", obs)
        if negate_expression(obs):
            warn("Negation of {obs_id} is not handled yet".format(obs_id=obs.id_))
        return convert_observable_to_pattern_without_negate(obs, bundle_instance, observable_mapping)
    finally:
        pop_dynamic_variable("current_observable")


def convert_observable_to_pattern_without_negate(obs, bundle_instance, id_to_observable_mapping):
    global PATTERN_CACHE
    if obs.observable_composition is not None:
        pattern = convert_observable_composition_to_pattern(obs.observable_composition,
                                                            bundle_instance,
                                                            id_to_observable_mapping)
        if pattern and obs.id_:
            add_to_pattern_cache(obs.id_, pattern)
        return pattern
    elif obs.object_ is not None:
        pattern = convert_object_to_pattern(obs.object_, obs.id_)
        add_to_pattern_cache(obs.id_, pattern)
        return pattern
    elif obs.idref is not None:
        if obs.idref in PATTERN_CACHE:
            return PATTERN_CACHE[obs.idref]
        else:
            # resolve now if possible, and remove from observed_data
            observable_data_instance = find_definition(obs.idref, bundle_instance["observed_data"])
            if observable_data_instance is not None:
                    # TODO: remove from the report's object_refs
                if obs.idref in id_to_observable_mapping:
                    return convert_observable_to_pattern(id_to_observable_mapping[obs.idref],
                                                         bundle_instance,
                                                         id_to_observable_mapping)
            return "PLACEHOLDER:" + obs.idref


# patterns can contain idrefs which might need to be resolved because the order in which the ids and idrefs appear
def interatively_resolve_placeholder_refs():
    global PATTERN_CACHE
    if not PATTERN_CACHE:
        return
    done = False
    while not done:
        # collect all of the fully resolved idrefs
        fully_resolved_idrefs = []
        for idref, expr in PATTERN_CACHE.items():
            if expr.find("PLACEHOLDER:") == -1:
                # no PLACEHOLDER idrefs found in the expr, means this idref is fully resolved
                fully_resolved_idrefs.append(idref)
        # replace only fully resolved idrefs
        change_made = False
        for fr_idref in fully_resolved_idrefs:
            for idref, expr in PATTERN_CACHE.items():
                if expr.find("PLACEHOLDER:" + fr_idref) != -1:
                    # a change will be made, which could introduce a new placeholder id into the expr
                    change_made = True
                    PATTERN_CACHE[idref] = \
                        expr.replace("PLACEHOLDER:" + fr_idref, PATTERN_CACHE[fr_idref])
        done = not change_made


def is_placeholder(thing):
    return thing.index("PLACEHOLDER") != -1


def fix_pattern(pattern):
    if not PATTERN_CACHE == {}:
        # info(str(PATTERN_CACHE))
        # info("pattern is: " +  pattern)
        if pattern.find("PLACEHOLDER:") != -1:
            for idref in PATTERN_CACHE.keys():
                pattern = pattern.replace("PLACEHOLDER:" + idref, PATTERN_CACHE[idref])
    return pattern


def convert_indicator_to_pattern(ind, bundle_instance, observable_mapping):
    try:
        set_dynamic_variable("current_indicator", ind)
        if ind.negate:
            warn("Negation of {ind_id} is not handled yet".format(ind_id=ind.id_))
        return convert_indicator_to_pattern_without_negate(ind, bundle_instance, observable_mapping)

    finally:
        pop_dynamic_variable("current_indicator")


def convert_indicator_to_pattern_without_negate(ind, bundle_instance, id_to_observable_mapping):
    global PATTERN_CACHE
    if ind.composite_indicator_expression is not None:
        pattern = convert_indicator_composition_to_pattern(ind.composite_indicator_expression,
                                                           bundle_instance,
                                                           id_to_observable_mapping)
        if pattern and ind.id_:
            add_to_pattern_cache(ind.id_, pattern)
        return pattern
    elif ind.observable is not None:
        pattern = convert_observable_to_pattern(ind.observable)
        add_to_pattern_cache(ind.id_, pattern)
        return pattern
    elif ind.idref is not None:
        if ind.idref in PATTERN_CACHE:
            return PATTERN_CACHE[ind.idref]
        else:
            # resolve now if possible, and remove from observed_data
            indicator_data_instance = find_definition(ind.idref, bundle_instance["indicators"])
            if indicator_data_instance is not None:
                indicator_data_instance["used_in_pattern"] = True
                # TODO: remove from the report's object_refs
                if ind.idref in id_to_observable_mapping:
                    return convert_observable_to_pattern(id_to_observable_mapping[ind.idref],
                                                         bundle_instance,
                                                         id_to_observable_mapping)
            return "PLACEHOLDER:" + ind.idref


def convert_indicator_composition_to_pattern(ind_comp, bundle_instance, observable_mapping):
    expression = []
    for ind in ind_comp.indicators:
        term = convert_indicator_to_pattern(ind, bundle_instance, observable_mapping)
        if term:
            expression.append(term)
        else:
            warn("No term was yielded for {0}".format((ind.id_ if ind.id_ else ind.idref)))
    if expression:
        operator_as_string = " " + ind_comp.operator + " "
        return "(" + operator_as_string.join(expression) + ")"
    else:
        return ""


def remove_pattern_objects(bundle_instance):
    all_new_ids_with_patterns = []
    for old_id in PATTERN_CACHE.keys():
        new_id = get_id_value(old_id)
        if new_id and len(new_id) == 1:
            all_new_ids_with_patterns.append(new_id[0])

    print(all_new_ids_with_patterns)
    if not KEEP_OBSERVABLE_DATA_USED_IN_PATTERNS and "observed_data" in bundle_instance:
        remaining_observed_data = []
        for obs in bundle_instance["observed_data"]:
            if obs["id"] not in all_new_ids_with_patterns:
                remaining_observed_data.append(obs)
        bundle_instance["observed_data"] = remaining_observed_data

 # TODO: only remove indicators that were involved ONLY as sub-indicators within composite indicator expressions
 #   if not KEEP_INDICATORS_USED_IN_COMPOSITE_INDICATOR_EXPRESSION and "indicators" in bundle_instance:
 #       remaining_indicators = []
 #       for ind in bundle_instance["indicators"]:
 #           if ind["id"] not in all_new_ids_with_patterns:
 #               remaining_indicators.append(ind)
 #       bundle_instance["indicators"] = remaining_indicators