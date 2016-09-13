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
from cybox.objects.win_executable_file_object import WinExecutableFile

from elevator.utils import info, warn, error, map_vocabs_to_label
from elevator.convert_cybox import WINDOWS_PEBINARY


OBSERVABLE_TO_PATTERN_MAPPING = {}

KEEP_OBSERVABLE_DATA = True

def need_not(condition):
    return condition == "DoesNotContain"


def add_parens_if_needed(expr):
    if expr.find("AND") != -1 or expr.find("OR") != -1:
        return "(" + expr + ")"
    else:
        return expr


def convert_condition(condition):
    if condition == "Equals":
        return "EQ"
    elif condition == "DoesNotEqual":
        return "NEQ"
    elif condition == "Contains" or condition == "DoesNotContain":
        return "CONTAINS"
    elif condition == "GreaterThan":
        return "GT"
    elif condition == "GreaterThanOrEqual":
        return "GE"
    elif condition == "LessThan":
        return "LT"
    elif condition == "LessThanOrEqual":
        return "LE"
    # StartsWith - handled in create_term_with_regex
    # EndsWith  - handled in create_term_with_regex
    # InclusiveBetween - handled in create_term_with_range
    # ExclusiveBetween - handled in create_term_with_range
    # FitsPattern
    # BitwiseAnd
    # BitwiseOr
    elif condition is None:
        warn("No condition given - assume EQ")
        return "EQ"


def create_term_with_regex(lhs, condition, rhs):
    if condition == "StartsWith":
        return lhs + " MATCHES " + " /^" + rhs + "/"
    elif condition == "EndsWith":
        return lhs + " MATCHES " + " /" + rhs + "$/"


def create_term_with_range(lhs, condition, rhs):
    if not isinstance(rhs, list) or len(rhs) != 2:
        error(condition + " was used, but two values were not provided.")
        return "'range term underspecified'"
    else:
        if condition == "InclusiveBetween":
            return "(" + lhs + " GE " + str(rhs[0]) + " AND " + lhs + " LE " + str(rhs[1]) + ")"
        else: # "ExclusiveBetween"
            return "(" + lhs + " GT " + str(rhs[0]) + " AND " + lhs + " LT " + str(rhs[1]) + ")"


def create_term(lhs, condition, rhs):
    if condition == "StartsWith" or condition == "EndsWith":
        return create_term_with_regex(lhs, condition, rhs)
    elif condition == "InclusiveBetween" or condition == "ExclusiveBetween":
        return create_term_with_range(lhs, condition, rhs)
    elif condition is None:
        warn("No condition given - assume EQ")
        return lhs + " EQ '" + str(rhs) + "'"
    else:
        try:
            if need_not(condition):
                return "NOT (" + lhs + " " + convert_condition(condition) + " '" + str(rhs) + "')"
            else:
                return lhs + " " + convert_condition(condition) + " '" + str(rhs) + "'"
        except TypeError:
            pass


def convert_address_to_pattern(add):
    if add.category == add.CAT_IPV4:
        return create_term("ipv4addr-object:value",  add.address_value.condition, add.address_value.value)


def convert_uri_to_pattern(uri):
    return create_term("url-object:value", uri.value.condition, uri.value.value)


def convert_email_message_to_pattern(mess):
    first_one = True
    expression = ""
    if mess.header is not None:
        header = mess.header
        if header.to is not None:
            # is to a list???
            expression += (" AND " if not first_one else "") + \
                          create_term("email-message-object:header:to",
                                      header.to.condition,
                                      header.to.value)
            first_one = False
        elif header.subject is not None:
            expression += (" AND " if not first_one else "") + \
                         create_term("email-message-object:header:subject",
                                     header.subject.condition,
                                     header.subject.value)
            first_one = False
    if mess.attachments is not None:
        warn("email attachments not handled yet")
    return expression


def convert_windows_executable_file_to_pattern(file):
    expression = ""
    if file.headers:
        file_header = file.headers.file_header
        if file_header:
            file_header_expression = ""
            if file_header.machine:
                file_header_expression += (" AND " if file_header_expression != "" else "") + \
                                create_term("file:extended-properties:windows-pebinary-ext:file-header:machine",
                                            file_header.machine.condition,
                                            file_header.machine.value)
            if file_header.time_date_stamp:
                file_header_expression += (" AND " if file_header_expression != "" else "") + \
                                create_term("file:extended-properties:windows-pebinary-ext:file-header:time_date_stamp",
                                            file_header.time_date_stamp.condition,
                                            file_header.time_date_stamp.value)
            if file_header.number_of_sections:
                file_header_expression += (" AND " if file_header_expression != "" else "") + \
                                create_term("file:extended-properties:windows-pebinary-ext:file-header:number_of_sections",
                                            file_header.number_of_sections.condition,
                                            file_header.number_of_sections.value)
            if file_header.pointer_to_symbol_table:
                file_header_expression += (" AND " if file_header_expression != "" else "") + \
                                create_term("file:extended-properties:windows-pebinary-ext:file-header:pointer_to_symbol_table",
                                            file_header.pointer_to_symbol_table.condition,
                                            file_header.pointer_to_symbol_table.value)
            if file_header.number_of_symbols:
                file_header_expression += (" AND " if file_header_expression != "" else "") + \
                                create_term("file:extended-properties:windows-pebinary-ext:file-header:number_of_symbols",
                                            file_header.number_of_symbols.condition,
                                            file_header.number_of_symbols.value)
            if file_header.size_of_optional_header:
                file_header_expression += (" AND " if file_header_expression != "" else "") + \
                                create_term("file:extended-properties:windows-pebinary-ext:file-header:size_of_optional_header",
                                            file_header.size_of_optional_header.condition,
                                            file_header.size_of_optional_header.value)
            if file_header.characteristics:
                file_header_expression += (" AND " if file_header_expression != "" else "") + \
                                          create_term(
                                              "file:extended-properties:windows-pebinary-ext:file-header:characteristics",
                                              file_header.characteristics.condition,
                                              file_header.characteristics.value)
            if file_header.hashes is not None:
                hash_expression = convert_hashes_to_pattern(file_header.hashes)
                if hash_expression:
                    file_header_expression += (" AND " if file_header_expression != "" else "") + hash_expression
        expression += (" AND " if expression != "" else "") + add_parens_if_needed(file_header_expression)
        if file.headers.optional_header:
            warn("file:extended-properties:windows-pebinary-ext:optional_header is not implemented yet")

    if file.type_:
        expression += (" AND " if expression != "" else "") + \
                      create_term("file:extended-properties:windows-pebinary-ext:pe_type",
                                  file.type_.condition,
                                  map_vocabs_to_label(file.type_.value, WINDOWS_PEBINARY))
    sections = file.sections
    if sections:
        sections_expression = ""
        # should order matter in patterns???
        for s in sections:
            section_expression = ""
            if s.section_header:
                if s.section_header.name:
                    section_expression += (" AND " if section_expression != "" else "") + \
                                            create_term("file:extended-properties:windows-pebinary-ext:section[*]:name",
                                                        s.section_header.name.condition,
                                                        s.section_header.name.value)
                if s.section_header.virtual_size:
                    section_expression += (" AND " if section_expression != "" else "") + \
                                            create_term("file:extended-properties:windows-pebinary-ext:size[*]:size",
                                                        s.section_header.virtual_size.condition,
                                                        s.section_header.virtual_size.value)
            if s.entropy:
                section_expression += (" AND " if section_expression != "" else "") + \
                                      create_term("file:extended-properties:windows-pebinary-ext:size[*]:entropy",
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


def convert_hashes_to_pattern(hashes):
    hash_expression = ""
    for hash in hashes:
        hash_expression += (" OR " if not hash_expression == "" else "") + \
                           create_term("file-object:hashes" + ":" + str(hash.type_).lower(),
                                       hash.simple_hash_value.condition,
                                       hash.simple_hash_value.value)
    return hash_expression


def convert_file_to_pattern(file):
    first_one = True
    expression = ""
    if file.hashes is not None:
        hash_expression = convert_hashes_to_pattern(file.hashes)
        if hash_expression:
            expression += hash_expression
    if file.file_name is not None:
        name_expression = create_term("file-object:file_name",
                                      file.file_name.condition,
                                      file.file_name.value)
        expression += (" AND " if expression != "" else "") + name_expression
    if file.size_in_bytes:
        size_expression = create_term("file-object:size",
                                      file.size_in_bytes.condition,
                                      file.size_in_bytes.value)
        expression += (" AND " if expression != "" else "") + size_expression
    if isinstance(file, WinExecutableFile):
        expression += (" AND " if expression != "" else "") + add_parens_if_needed(convert_windows_executable_file_to_pattern(file))
    return expression


def convert_registry_key_value_property(prop, property_name):
    property_expression = ""
    if hasattr(prop, "condition"):
        cond = prop.condition
    else:
        warn("No condition given - assume EQ")
        cond = None
    return create_term("win-registry-key-object:values[*]" + ":" + property_name, cond, prop)


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
            expression += create_term("win-registry-key-object:key", reg_key.key.condition,  key_value_term)
    if reg_key.values:
        values_expression = ""
        data_expression = ""
        name_expression = ""
        type_expression = ""
        first_value = True
        for v in reg_key.values:
            value_expression = ""
            if hasattr(v, "data") and v.data:
                data_expression = convert_registry_key_value_property(v.data, "data")
            if data_expression:
                value_expression += (" AND " if value_expression != "" else "") + data_expression
            if hasattr(v, "name") and v.name:
                name_expression = convert_registry_key_value_property(v.name, "name")
            if name_expression:
                value_expression += (" AND " if value_expression != "" else "") + name_expression
            if hasattr(v, "datatype") and v.datatype:
                type_expression = convert_registry_key_value_property(v.datatype, "data_type")
            if type_expression:
                value_expression += (" AND " if value_expression != "" else "") + type_expression
            values_expression += (" OR " if value_expression else "") + value_expression
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
            service_expression = convert_windows_process_to_pattern(process)
            if service_expression:
                expression += (" AND " if expression != "" else "") + add_parens_if_needed(service_expression)
    return expression


def convert_windows_process_to_pattern(process):
    expression = ""
    if process.handle_list:
        for h in process.handle_list:
            warn("Window handles are not a part of CybOX 3.0")
    return expression


def convert_windows_service_to_pattern(service):
    pass


####################################################################################################################


def convert_observable_composition_to_pattern(obs_comp, bundleInstance, observable_mapping):
    expression = []
    for obs in obs_comp.observables:
        term = convert_observable_to_pattern(obs, bundleInstance, observable_mapping)
        if term:
            expression.append(term)
        else:
            warn("No term was yielded for " + (obs.id_ if obs.id_ else obs.idref))
    if expression:
        operator_as_string = " " + obs_comp.operator + " "
        return "(" + operator_as_string.join(expression) + ")"
    else:
        return ""


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
    else:
        warn(str(obj.properties) + " cannot be converted to a pattern, yet.")
        return "'term not converted'"


def match_1x_id_with_20_id(id_1x, id_20):
    return True


def find_observable_data(idref, obserableData):
    for obs in obserableData:
        if match_1x_id_with_20_id(idref, obs["id"]):
            return obs
    warn (idref + " cannot be resolved")
    return None


def negate_expression(obs):
    return hasattr(obs, "negate") and obs.negate


def convert_observable_to_pattern(obs, bundleInstance, observable_mapping):
    return ("NOT (" if negate_expression(obs) else "") + \
           convert_observable_to_pattern_without_negate(obs, bundleInstance, observable_mapping) + \
           (")" if negate_expression(obs) else "")


def convert_observable_to_pattern_without_negate(obs, bundleInstance, observable_mapping):
    global OBSERVABLE_TO_PATTERN_MAPPING
    if obs.observable_composition is not None:
        return convert_observable_composition_to_pattern(obs.observable_composition,
                                                         bundleInstance,
                                                         observable_mapping)
    elif obs.object_ is not None:
        pattern = convert_object_to_pattern(obs.object_)
        OBSERVABLE_TO_PATTERN_MAPPING[obs.id_] = pattern
        return pattern
    elif obs.idref is not None:
        if obs.idref in OBSERVABLE_TO_PATTERN_MAPPING:
            return OBSERVABLE_TO_PATTERN_MAPPING[obs.idref]
        else:
            # resolve now, and remove from observed_data
            observableDataInstance = find_observable_data(obs.idref, bundleInstance["observed_data"])
            if observableDataInstance is not None:
                if not KEEP_OBSERVABLE_DATA:
                    bundleInstance["observed_data"].remove(observableDataInstance)
                if obs.idref in observable_mapping:
                    return convert_observable_to_pattern(observable_mapping[obs.idref], bundleInstance, observable_mapping)
            return obs.idref


def interatively_resolve_placeholder_refs():
    global OBSERVABLE_TO_PATTERN_MAPPING
    done = True
    while done:
        # collect all of the fully resolved idrefs
        fully_resolved_idrefs = []
        for idref, expr in OBSERVABLE_TO_PATTERN_MAPPING.iteritems():
            if expr.find(idref) != -1:
                fully_resolved_idrefs.append(idref)
                done = False
        # replace only fully resolved idrefs
        for fr_idref in fully_resolved_idrefs:
            for idref, expr in OBSERVABLE_TO_PATTERN_MAPPING.iteritems():
                OBSERVABLE_TO_PATTERN_MAPPING[idref] = expr.replace(idref, OBSERVABLE_TO_PATTERN_MAPPING[fr_idref])


def fix_pattern(pattern):
    if not OBSERVABLE_TO_PATTERN_MAPPING == {}:
        # interatively_resolve_placeholder_refs()
        for idref in OBSERVABLE_TO_PATTERN_MAPPING.keys():
            # TODO: this can probably be done in place
            pattern = pattern.replace(idref, OBSERVABLE_TO_PATTERN_MAPPING[idref])
    return pattern