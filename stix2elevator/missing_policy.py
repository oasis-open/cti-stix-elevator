# Standard Library
import re

# external
from six import text_type

# internal
from stix2elevator.options import get_option_value, info, warn


def convert_to_custom_name(name, separator="_"):
    if re.search('[A-Z]', name):
        warn("Custom name %s has been converted to all lower case", 727, name)
    # use custom_property_prefix for all custom names
    return "x" + separator + get_option_value("custom_property_prefix") + separator + name.lower()


def add_string_property_to_description(sdo_instance, property_name, property_value, is_list=False):
    if is_list:
        sdo_instance["description"] += "\n\n" + property_name.upper() + ":\n"
        property_values = []
        for v in property_value:
            property_values.append(text_type(v))
        sdo_instance["description"] += ",\n".join(property_values)
    else:
        sdo_instance["description"] += "\n\n" + property_name.upper() + ":\n\t" + text_type(property_value)
    warn("Appended %s to description of %s", 302, property_name, sdo_instance["id"])


def add_string_property_as_custom_property(sdo_instance, property_name, property_value, is_list=False):
    if is_list:
        property_values = list()
        for v in property_value:
            property_values.append(text_type(v))
        sdo_instance[convert_to_custom_name(property_name)] = ",".join(property_values)
    else:
        sdo_instance[convert_to_custom_name(property_name)] = text_type(property_value)
    warn("Used custom property for %s", 308, property_name + (" of " + sdo_instance["id"] if "id" in sdo_instance else ""))


def handle_missing_string_property(sdo_instance, property_name, property_value, is_list=False, is_sco=False):
    if property_value:
        if get_option_value("missing_policy") == "add-to-description" and not is_sco and "description" in sdo_instance:
            add_string_property_to_description(sdo_instance, property_name, property_value, is_list)
        elif get_option_value("missing_policy") == "use-custom-properties":
            add_string_property_as_custom_property(sdo_instance, property_name, property_value, is_list)
        else:
            warn("Missing property %s is ignored", 307, ("'" + property_name + "'" + (" of " + sdo_instance["id"] if "id" in sdo_instance else "")))


def add_confidence_property_to_description(sdo_instance, confidence, parent_property_name):
    prefix = parent_property_name.upper() + " " if parent_property_name else ""
    if confidence is not None:
        sdo_instance["description"] += "\n\n" + prefix + "CONFIDENCE: "
        if confidence.value is not None:
            sdo_instance["description"] += text_type(confidence.value)
        if confidence.description is not None:
            sdo_instance["description"] += "\n\t" + prefix + "DESCRIPTION: " + text_type(confidence.description)
        warn("Appended Confidence type content to description of %s", 304, sdo_instance["id"])


def add_confidence_property_as_custom_property(sdo_instance, confidence, parent_property_name=None):
    prefix = parent_property_name + "_" if parent_property_name else ""
    if confidence.value is not None:
        sdo_instance[convert_to_custom_name(prefix + "confidence")] = text_type(confidence.value)
    if confidence.description is not None:
        sdo_instance[convert_to_custom_name(prefix + "confidence_description")] = text_type(confidence.description)
    warn("Used custom properties for Confidence type content of %s", 308, sdo_instance["id"])


def handle_missing_confidence_property(sdo_instance, confidence, parent_property_name=None):
    if confidence and confidence.value:
        if get_option_value("missing_policy") == "add-to-description" and confidence:
            add_confidence_property_to_description(sdo_instance, confidence, parent_property_name)
        elif get_option_value("missing_policy") == "use-custom-properties":
            add_confidence_property_as_custom_property(sdo_instance, confidence, parent_property_name)
        else:
            warn("Missing property 'confidence' of %s is ignored", 307, sdo_instance["id"])


def add_statement_type_to_description(sdo_instance, statement, property_name):
    sdo_instance["description"] += "\n\n" + property_name.upper() + ":"
    has_value = False
    if statement.value:
        sdo_instance["description"] += text_type(statement.value)
        has_value = True
    if statement.descriptions:
        descriptions = []
        for d in statement.descriptions:
            descriptions.append(text_type(d.value))
        sdo_instance["description"] += (": " if has_value else "") + "\n\n\t".join(descriptions)
    if statement.source is not None:
        # FIXME: Handle source
        info("Source in %s is not handled, yet.", 815, sdo_instance["id"])
    if statement.confidence:
        add_confidence_property_to_description(sdo_instance, statement.confidence, property_name)
    warn("Appended Statement type content to description of %s", 305, sdo_instance["id"])


def add_statement_type_as_custom_property(statement):
    statement_json = {}
    if statement.value:
        statement_json["value"] = text_type(statement.value)
    if statement.descriptions:
        descriptions = []
        for d in statement.descriptions:
            descriptions.append(text_type(d.value))
        statement_json["description"] = " ".join(descriptions)
    if statement.source is not None:
        # FIXME: Handle source
        info("Source property in STIX 1.x statement is not handled, yet.", 815)
    if statement.confidence:
        add_confidence_property_as_custom_property(statement_json, statement.confidence)
    return statement_json


def statement_type_as_properties(sdo_instance, statement, property_name):
    if statement.value:
        sdo_instance[convert_to_custom_name(property_name)] = text_type(statement.value)
    if statement.descriptions:
        descriptions = []
        for d in statement.descriptions:
            descriptions.append(text_type(d.value))
        sdo_instance[convert_to_custom_name(property_name) + "_description"] = " ".join(descriptions)
    if statement.source is not None:
        # FIXME: Handle source
        info("Source property in STIX 1.x statement is not handled, yet.", 815)
    if statement.confidence:
        add_confidence_property_as_custom_property(sdo_instance, statement.confidence, property_name)


def handle_missing_statement_properties(sdo_instance, statement, property_name):
    if statement:
        if get_option_value("missing_policy") == "add-to-description":
            add_statement_type_to_description(sdo_instance, statement, property_name)
        elif get_option_value("missing_policy") == "use-custom-properties":
            statement_type_as_properties(sdo_instance, statement, property_name)
            warn("Used custom properties for Statement type content of %s", 308, sdo_instance["id"])
        else:
            warn("Missing property %s of %s is ignored", 307, property_name, sdo_instance["id"])


def handle_multiple_missing_statement_properties(sdo_instance, statements, property_name):
    if statements:
        if len(statements) == 1:
            handle_missing_statement_properties(sdo_instance, statements[0], property_name)
        else:
            if get_option_value("missing_policy") == "add-to-description":
                for s in statements:
                    add_statement_type_to_description(sdo_instance, s, property_name)
            elif get_option_value("missing_policy") == "use-custom-properties":
                statements_json = []
                for s in statements:
                    statements_json.append(add_statement_type_as_custom_property(s))
                sdo_instance[convert_to_custom_name(property_name + "s")] = statements_json
            else:
                warn("Missing property %s of %s is ignored", 307, property_name, sdo_instance["id"])


def handle_missing_tool_property(sdo_instance, tool):
    if tool.name:
        if get_option_value("missing_policy") == "add-to-description":
            sdo_instance["description"] += "\n\nTOOL SOURCE:"
            sdo_instance["description"] += "\n\tname: " + text_type(tool.name)
        warn("Appended Tool type content to description of %s", 306, sdo_instance["id"])
    elif get_option_value("missing_policy") == "use-custom-properties":
        sdo_instance[convert_to_custom_name("tool_source")] = text_type(tool.name)
    else:
        warn("Missing property name of %s is ignored", 307, sdo_instance["id"])
