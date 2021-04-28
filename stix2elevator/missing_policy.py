# Standard Library
import re
import uuid

# external
import pluralizer

# internal
from stix2elevator.extension_definitions import get_extension_definition_id
from stix2elevator.options import get_option_value, info, warn

_PLURALIZER = None


def singular(word):
    global _PLURALIZER

    if _PLURALIZER is None:
        _PLURALIZER = pluralizer.Pluralizer()
    return _PLURALIZER.singular(word)


def check_for_missing_policy(policy):
    return get_option_value("missing_policy") == policy


def convert_to_custom_name(name, separator="_"):
    if re.search('[A-Z]', name):
        warn("Custom name %s has been converted to all lower case", 727, name)
    # use custom_property_prefix for all custom names
    return "x" + separator + get_option_value("custom_property_prefix") + separator + name.lower()


def remove_custom_name(name, separator="_"):
    prefix = "x" + separator + get_option_value("custom_property_prefix") + separator
    return name[len(prefix):]


def add_string_property_to_description(sdo_instance, property_name, property_value, is_list=False):
    if is_list:
        sdo_instance["description"] += "\n\n" + property_name.upper() + ":\n"
        property_values = []
        for v in property_value:
            property_values.append(str(v))
        sdo_instance["description"] += ",\n".join(property_values)
    else:
        sdo_instance["description"] += "\n\n" + property_name.upper() + ":\n\t" + str(property_value)
    warn("Appended %s to description of %s", 302, property_name, sdo_instance["id"])


def add_string_property_as_custom_property(sdo_instance, property_name, property_value, is_list=False):
    if is_list:
        property_values = list()
        for v in property_value:
            property_values.append(str(v))
        sdo_instance[convert_to_custom_name(property_name)] = property_values
    else:
        sdo_instance[convert_to_custom_name(property_name)] = str(property_value)
    warn("Used custom property for %s", 308, property_name + (" of " + sdo_instance["id"] if "id" in sdo_instance else ""))


def add_string_property_as_extension_property(container, property_name, property_value, sdo_id, is_list=False):
    if is_list:
        property_values = list()
        for v in property_value:
            property_values.append(str(v))
        container[property_name] = property_values
    else:
        container[property_name] = str(property_value)
    warn("Used extension property for %s", 313, property_name + (" of " + sdo_id if sdo_id else ""))


def handle_missing_string_property(container, property_name, property_value, sdo_id, is_list=False, is_sco=False):
    if property_value:
        if check_for_missing_policy("add-to-description"):
            if is_sco or "description" not in container:
                warn("Missing property %s is ignored, because there is no description property", 309,
                     ("'" + property_name + "'" + (" of " + sdo_id if sdo_id else "")))
            else:
                add_string_property_to_description(container, property_name, property_value, is_list)
        elif check_for_missing_policy("use-custom-properties"):
            add_string_property_as_custom_property(container, property_name, property_value, is_list)
        elif check_for_missing_policy("use-extensions"):
            add_string_property_as_extension_property(container, property_name, property_value, sdo_id, is_list)
        else:
            warn("Missing property %s is ignored", 307, ("'" + property_name + "'" + (" of " + sdo_id if sdo_id else "")))


def add_confidence_property_to_description(sdo_instance, confidence, parent_property_name):
    prefix = parent_property_name.upper() + " " if parent_property_name else ""
    if confidence is not None:
        sdo_instance["description"] += "\n\n" + prefix + "CONFIDENCE: "
        if confidence.value is not None:
            sdo_instance["description"] += str(confidence.value)
        if confidence.description is not None:
            sdo_instance["description"] += "\n\t" + prefix + "DESCRIPTION: " + str(confidence.description)
        warn("Appended Confidence type content to description %s", 304, ("of" + sdo_instance["id"] if "id" in sdo_instance else ""))


def add_confidence_property_as_custom_property(sdo_instance, confidence, parent_property_name=None):
    prefix = parent_property_name + "_" if parent_property_name else ""
    if confidence.value is not None:
        value = str(confidence.value)
        if value.isdigit():
            value = int(value)
        sdo_instance[convert_to_custom_name(prefix + "confidence")] = value
    if confidence.description is not None:
        sdo_instance[convert_to_custom_name(prefix + "confidence_description")] = str(confidence.description)
    warn("Used custom properties for Confidence type content %s", 308, ("of" + sdo_instance["id"] if "id" in sdo_instance else ""))


def add_confidence_property_as_extension_property(container, confidence, id, parent_property_name=None):
    prefix = parent_property_name + "_" if parent_property_name else ""
    if confidence.value is not None:
        container[prefix + "confidence"] = str(confidence.value)
    if confidence.description is not None:
        container[prefix + "confidence_description"] = str(confidence.description)
    warn("Used extensions properties for Confidence type content of %s", 313, id)


def handle_missing_confidence_property(container, confidence, id, parent_property_name=None):
    if confidence and confidence.value:
        if check_for_missing_policy("add-to-description") and confidence:
            add_confidence_property_to_description(container, confidence, parent_property_name)
        elif check_for_missing_policy("use-custom-properties"):
            add_confidence_property_as_custom_property(container, confidence, parent_property_name)
        elif check_for_missing_policy("use-extensions"):
            add_confidence_property_as_extension_property(container, confidence, id, parent_property_name)
        else:
            warn("Missing property 'confidence' of %s is ignored", 307, id)


def add_statement_type_to_description(sdo_instance, statement, property_name):
    sdo_instance["description"] += "\n\n" + property_name.upper() + ":"
    has_value = False
    if statement.value:
        sdo_instance["description"] += str(statement.value)
        has_value = True
    if statement.descriptions:
        descriptions = []
        for d in statement.descriptions:
            descriptions.append(str(d.value))
        sdo_instance["description"] += (": " if has_value else "") + "\n\n\t".join(descriptions)
    if statement.source is not None:
        # FIXME: Handle source
        info("Source in %s is not handled, yet.", 815, sdo_instance["id"])
    if statement.confidence:
        add_confidence_property_to_description(sdo_instance, statement.confidence, property_name)
    warn("Appended Statement type content to description %s", 305, ("of" + sdo_instance["id"] if "id" in sdo_instance else ""))


def add_statement_type_as_custom_or_extension_property(statement):
    statement_json = {}
    if statement.value:
        statement_json["value"] = str(statement.value)
    if statement.descriptions:
        descriptions = []
        for d in statement.descriptions:
            descriptions.append(str(d.value))
        statement_json["description"] = " ".join(descriptions)
    if statement.source is not None:
        # FIXME: Handle source
        info("Source property in STIX 1.x statement is not handled, yet.", 815)
    if statement.confidence:
        handle_missing_confidence_property(statement_json, statement.confidence, None)
    return statement_json


def statement_type_as_custom_properties(sdo_instance, statement, property_name, is_list):
    map = dict()
    if statement.descriptions:
        descriptions = []
        for d in statement.descriptions:
            descriptions.append(str(d.value))
        map["description"] = " ".join(descriptions)
    if statement.source is not None:
        # FIXME: Handle source
        info("Source property in STIX 1.x statement is not handled, yet.", 815)
    if statement.confidence:
        add_confidence_property_as_custom_property(map, statement.confidence, property_name)
    if map:
        if statement.value:
            map["value"] = str(statement.value)
        sdo_instance[convert_to_custom_name(property_name)] = [map] if is_list else map
    else:
        sdo_instance[convert_to_custom_name(property_name)] = [str(statement.value)] if is_list else str(statement.value)


def statement_type_as_extension_properties(container, statement, property_name, id, is_list):
    map = dict()
    if statement.descriptions:
        descriptions = []
        for d in statement.descriptions:
            descriptions.append(str(d.value))
        map["description"] = " ".join(descriptions)
    if statement.source is not None:
        # FIXME: Handle source
        info("Source property in STIX 1.x statement is not handled, yet.", 815)
    if statement.confidence:
        add_confidence_property_as_extension_property(map, statement.confidence, property_name, id)
    if map:
        if statement.value:
            map["value"] = str(statement.value)
        container[property_name] = [map] if is_list else map
    else:
        container[property_name] = [str(statement.value)] if is_list else str(statement.value)


def handle_missing_statement_properties(container, statement, property_name, id, is_list=False):
    if statement:
        if check_for_missing_policy("add-to-description"):
            if is_list:
                property_name = singular(property_name)
            add_statement_type_to_description(container, statement, property_name)
        elif check_for_missing_policy("use-custom-properties"):
            statement_type_as_custom_properties(container, statement, property_name, is_list)
            warn("Used custom properties for Statement type content of %s", 308, id)
        elif check_for_missing_policy("use-extensions"):
            statement_type_as_extension_properties(container, statement, property_name, id, is_list)
            warn("Used extensions properties for Statement type content of %s", 308, id)
        else:
            warn("Missing property %s of %s is ignored", 307, property_name, id)


def collect_statement_type_as_custom_or_extension_property(statements):
    statements_json = []
    for s in statements:
        statements_json.append(add_statement_type_as_custom_or_extension_property(s))
    return statements_json


def handle_multiple_missing_statement_properties(container, statements, property_name, id):
    if statements:
        if len(statements) == 1:
            handle_missing_statement_properties(container, statements[0], property_name, id, is_list=True)
        else:
            if check_for_missing_policy("add-to-description"):
                for s in statements:
                    add_statement_type_to_description(container, s, singular(property_name))
            elif check_for_missing_policy("use-custom-properties"):
                container[convert_to_custom_name(property_name)] = \
                    collect_statement_type_as_custom_or_extension_property(statements)
            elif check_for_missing_policy("use-extensions"):
                container[property_name] = collect_statement_type_as_custom_or_extension_property(statements)
            else:
                warn("Missing property %s of %s is ignored", 307, property_name, id)


def handle_missing_tool_property(sdo_instance, tool):
    if tool.name:
        if check_for_missing_policy("add-to-description"):
            sdo_instance["description"] += "\n\nTOOL SOURCE:"
            sdo_instance["description"] += "\n\tname: " + str(tool.name)
        warn("Appended Tool type content to description of %s", 306, sdo_instance["id"])
    elif check_for_missing_policy("use-custom-properties"):
        sdo_instance[convert_to_custom_name("tool_source")] = str(tool.name)
    else:
        warn("Missing property 'name' %s is ignored", 307, ("of" + sdo_instance["id"] if "id" in sdo_instance else ""))


def determine_container_for_missing_properties(object_type, object_instance, custom_object=False):
    if check_for_missing_policy("use-extensions"):
        extension_definition_id = get_extension_definition_id(object_type)
        if "extensions" in object_instance and extension_definition_id in object_instance["extensions"]:
            return object_instance["extensions"][extension_definition_id], extension_definition_id
        elif not extension_definition_id:
            warn("No extension-definition was found for STIX 1 type %s %s",
                 312,
                 object_type,
                 (("of " + object_instance["id"]) if "id" in object_instance else ""))
            if custom_object:
                new_id = "extension-definition" + "--" + str(uuid.uuid4())
                warn("New extension-definition id %s was generated for %s. %s",
                     315,
                     new_id,
                     object_type,
                     (("See " + object_instance["id"]) if "id" in object_instance else ""))
                return dict(), new_id
            else:
                return None, None
        else:
            container = dict()
            return container, extension_definition_id
    else:
        return object_instance, None


def fill_in_extension_properties(instance, container, extension_definition_id, extension_type="property-extension"):
    if check_for_missing_policy("use-extensions") and container != dict():
        if extension_definition_id:
            if "extensions" not in instance:
                instance["extensions"] = dict()
            if extension_definition_id not in instance["extensions"]:
                instance["extensions"][extension_definition_id] = container
            # the object itself might be an extension, so it already should have an extension_type
            if extension_type and "extension_type" not in instance["extensions"][extension_definition_id]:
                instance["extensions"][extension_definition_id]["extension_type"] = extension_type
