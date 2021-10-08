# internal
from stix2elevator.options import warn
from stix2elevator.utils import convert_timestamp_to_string

_ACS_EXTENSION_DEFINITION_ID = "extension-definition--3a65884d-005a-4290-8335-cb2d778a83ce"


def convert_original_classification(original_classification):
    co = {}
    if original_classification.classified_by:
        co["classified_by"] = str(original_classification.classified_by)
    else:
        warn("Required property %s is not provided for ACS data marking", 641, "classified_by")
    if original_classification.classified_on:
        co["classified_on"] = convert_timestamp_to_string(original_classification.classified_on)
    if original_classification.classification_reason:
        co["classification_reason"] = str(original_classification.classification_reason)
    if original_classification.compilation_reason:
        co["compilation_reason"] = str(original_classification.compilation_reason)
    return co


def convert_derivative_classification(derivative_classification):
    cd = {}
    if derivative_classification.classified_by:
        cd["classified_by"] = str(derivative_classification.classified_by)
    else:
        warn("Required property %s is not provided for ACS data marking", 641, "classified_by")
    if derivative_classification.classified_on:
        cd["classified_on"] = convert_timestamp_to_string(derivative_classification.classified_on)
    if derivative_classification.derived_from:
        cd["derived_from"] = str(derivative_classification.derived_from)
    else:
        warn("Required property %s is not provided for ACS data marking", 641, "derived_from")
    return cd


def convert_declassification(declassification):
    dec = {}
    if declassification.declass_exemption:
        dec["declass_exemption"] = str(declassification.declass_exemption)
    if declassification.declass_period:
        dec["declass_period"] = int(declassification.declass_period)
    if declassification.declass_date:
        dec["declass_date"] = convert_timestamp_to_string(declassification.declass_date)
    if declassification.declass_event:
        dec["declass_event"] = str(declassification.declass_event)
    return dec


def convert_resource_disposition(resource_disposition):
    rd = {}
    if resource_disposition.disposition_date:
        rd["disposition_date"] = convert_timestamp_to_string(resource_disposition.disposition_date)
    if resource_disposition.disposition_process:
        rd["disposition_process"] = str(resource_disposition.disposition_process)
    return rd


def convert_public_release(public_release):
    pr = {}
    if public_release.released_by:
        pr["released_by"] = str(public_release.released_by)
    else:
        warn("Required property %s is not provided for ACS data marking", 641, "released_by")
    if public_release.released_on:
        pr["released_on"] = convert_timestamp_to_string(public_release.released_on)
    return pr


def convert_one_scope(ps, property, item):
    if property not in ps:
        ps[property] = []
    ps[property].append(item)


def convert_privilege_scope(privilege_scope):
    ps = {}
    for s in privilege_scope:
        if str(s) == "ALL":
            convert_one_scope(ps, "permitted_nationalities", "ALL")
            convert_one_scope(ps, "permitted_organizations", "ALL")
            convert_one_scope(ps, "shareability", "ALL")
            convert_one_scope(ps, "entity", "ALL")
            return ps
        for item in s:
            item_parts = item.split(":")
            token = item_parts[0]
            if token == "CTRY":
                convert_one_scope(ps, "permitted_nationalities", item_parts[1])
            elif token == "ORG":
                convert_one_scope(ps, "permitted_organizations", item_parts[1])
            elif token == "SHAR":
                convert_one_scope(ps, "shareability", item_parts[1])
            elif token == "ENTITY":
                convert_one_scope(ps, "entity", item_parts[1])
    return ps


def convert_access_privilege(access_privilege):
    ap = {}
    if access_privilege.privilege_action:
        ap["privilege_action"] = str(access_privilege.privilege_action)
    else:
        warn("Required property %s is not provided for ACS data marking", 641, "privilege_action")
    if access_privilege.privilege_scope:
        ap["privilege_scope"] = convert_privilege_scope(access_privilege.privilege_scope)
    else:
        warn("Required property %s is not provided for ACS data marking", 641, "privilege_scope")
    if access_privilege.rule_effect:
        ap["rule_effect"] = str(access_privilege.rule_effect)
    else:
        warn("Required property %s is not provided for ACS data marking", 641, "rule_effect")
    return ap


def convert_further_sharing(further_sharing):
    fs = {}
    if further_sharing.sharing_scope:
        fs["sharing_scope"] = further_sharing.sharing_scope
    else:
        warn("Required property %s is not provided for ACS data marking", 641, "sharing_scope")
    if further_sharing.rule_effect:
        fs["rule_effect"] = further_sharing.rule_effect
    else:
        warn("Required property %s is not provided for ACS data marking", 641, "rule_effect")
    return fs


def convert_control_set(control_set):
    cs = {}
    for item in control_set.value:
        item_parts = item.split(":")
        token = item_parts[0]
        if token == "CLS":
            cs["classification"] = item_parts[1]
        elif token == "SCI":
            convert_one_scope(cs, "sci_controls", item_parts[1])
        elif token == "LAC":
            convert_one_scope(cs, "logical_authority_category", item_parts[1])
        elif token == "FD":
            convert_one_scope(cs, "formal_determination", item_parts[1])
        elif token == "CVT":
            convert_one_scope(cs, "caveat", item_parts[1])
        elif token == "SENS":
            convert_one_scope(cs, "sensitivity", item_parts[1])
        elif token == "SHAR":
            convert_one_scope(cs, "shareability", item_parts[1])
        elif token == "ENTITY":
            convert_one_scope(cs, "entity", item_parts[1])
        elif token == "CTRY":
            convert_one_scope(cs, "permitted_nationalities", item_parts[1])
        elif token == "ORG":
            convert_one_scope(cs, "permitted_organizations", item_parts[1])
        elif token == "CUI":
            if item_parts[1] == "FOUO":
                convert_one_scope(cs, "formal_determination", item_parts[1])
                warn("CUI:FOUO is treated as FD:FOUO", 0)
        else:
            warn("Token in control set not recognized: %s", 318, token)
    return cs


def convert_edh_marking_to_acs_marking(marking_definition_instance, isa_marking, marking_assertion):
    acs_marking = {"extension_type": "property-extension"}
    # name is optional
    if isa_marking.create_date_time:
        acs_marking["create_date_time"] = convert_timestamp_to_string(isa_marking.create_date_time)
    else:
        warn("Required property %s is not provided for ACS data marking", 641, "create_date_time")
    if isa_marking.responsible_entity:
        for entity in isa_marking.responsible_entity.value:
            responsible_entity_parts = entity.split(":")
            if responsible_entity_parts[0] == "CUST":
                acs_marking["responsible_entity_custodian"] = responsible_entity_parts[1]
            if responsible_entity_parts[0] == "ORIG":
                acs_marking["responsible_entity_originator"] = responsible_entity_parts[1]
        if "responsible_entity_custodian" not in acs_marking:
            warn("Required property %s is not provided for ACS data marking", 641, "responsible_entity_custodian")

    if isa_marking.identifier:
        acs_marking["identifier"] = isa_marking.identifier

    # both auth_ref properties in the XML schema are minOccurs="0" maxOccurs="1"
    if marking_assertion.auth_ref:
        acs_marking["authority_reference"] = [marking_assertion.auth_ref]
    if isa_marking.auth_ref:
        if acs_marking["authority_reference"]:
            acs_marking["authority_reference"].append(isa_marking.auth_ref)
        else:
            acs_marking["authority_reference"] = isa_marking.auth_ref
    if marking_assertion.policy_ref:
        acs_marking["policy_reference"] = marking_assertion.policy_ref
    else:
        warn("Required property %s is not provided for ACS data marking", 641, "policy_reference")
    if marking_assertion.original_classification:
        acs_marking["original_classification"] = convert_original_classification(marking_assertion.original_classification)
    if marking_assertion.derivative_classification:
        acs_marking["derivative_classification"] = convert_derivative_classification(marking_assertion.derivative_classification)
    if marking_assertion.declassification:
        acs_marking["declassification"] = convert_declassification(marking_assertion.declassification)
    if marking_assertion.resource_disposition:
        acs_marking["resource_disposition"] = convert_resource_disposition(marking_assertion.resource_disposition)
    if marking_assertion.public_release:
        acs_marking["public_release"] = convert_public_release(marking_assertion.public_release)
    if marking_assertion.access_privilege:
        acs_marking["access_privilege"] = []
        for ac in marking_assertion.access_privilege:
            acs_marking["access_privilege"].append(convert_access_privilege(ac))
    if marking_assertion.further_sharing:
        acs_marking["further_sharing"] = []
        for fs in marking_assertion.further_sharing:
            acs_marking["further_sharing"].append(convert_further_sharing(fs))
    if marking_assertion.control_set:
        acs_marking["control_set"] = convert_control_set(marking_assertion.control_set)
    else:
        warn("Required property %s is not provided for ACS data marking", 641, "control_set")
    marking_definition_instance["extensions"] = {_ACS_EXTENSION_DEFINITION_ID: acs_marking}
