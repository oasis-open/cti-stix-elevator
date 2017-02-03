import datetime
from six import text_type

import cybox

from stix2elevator.convert_pattern import *
from stix2elevator.vocab_mappings import *


def convert_address(add):
    if add.category == add.CAT_IPV4:
        return {"type": "ipv4-addr", "value": add.address_value.value}
    elif add.category == add.CAT_IPV6:
        return {"type": "ipv6-addr", "value": add.address_value.value}
    elif add.category == add.CAT_MAC:
        return {"type": "mac-addr", "value": add.address_value.value}
    elif add.category == add.CAT_EMAIL:
        return {"type": "email-addr", "value": add.address_value.value}
    else:
        warn("The address type %s is not part of Cybox 3.0", 421, add.category)


def convert_uri(uri):
    return {"type": "url-object", "value": + uri.value.value}


def create_directory(file):
    return {"type": "directory", "path": file.file_path.value}


def convert_file_properties(file):
    cybox_dict = {"type": "file"}
    if file.size is not None:
        if isinstance(file.size.value, list):
            error("File size window not allowed in top level observable, using first value", 511)
            cybox_dict["size"] = int(file.size.value[0])
        else:
            cybox_dict["size"] = int(file.size)
    if file.hashes is not None:
        hashes = {}
        for h in file.hashes:
            hashes[text_type(h.type_).lower()] = h.simple_hash_value.value
        cybox_dict["hashes"] = hashes
    if file.file_name:
        cybox_dict["file_name"] = text_type(file.file_name)
    if file.full_path:
        warn("1.x full file paths are not processed, yet", 802)
    return cybox_dict


def convert_file(file):
    objs = {}
    objs[0] = convert_file_properties(file)
    if file.file_path:
        objs[1] = create_directory(file)
        objs[0]["parent_directory_ref"] = "1"
    return objs


def convert_email_message(email_message):
    index = 0
    cybox_dict = {}
    email_dict = {"type": "email-message"}
    cybox_dict[index] = email_dict
    index += 1
    if email_message.header:
        header = email_message.header
        if header.date:
            email_dict["date"] = header, datetime.date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if header.content_type:
            email_dict["content_type"] = header.content_type
        if header.subject:
            email_dict["subject"] = header.subject
        if header.from_:
            # should there ever be more than one?
            from_ref = convert_address(header.from_)
            cybox_dict[index] = from_ref
            email_dict["from_ref"] = str(index)
            index += 1
        if header.to:
            for t in header.to:
                to_ref = convert_address(t)
                cybox_dict[index] = to_ref
                if "to_refs" not in email_dict:
                    email_dict["to_refs"] = []
                email_dict["to_refs"].append(str(index))
                index += 1
    return cybox_dict


def convert_registry_key(reg_key):
    cybox_reg = {"type": "windows-registry-key"}
    if reg_key.key or reg_key.hive:
        full_key = ""
        if reg_key.hive:
            full_key += reg_key.hive.value + "\\"
        if reg_key.key:
            full_key += reg_key.key.value
        cybox_reg["key"] = full_key
    else:
        error("windows-registry-key is required to have a key property", 608)
    if reg_key.values:
        cybox_reg["values"] = []
        for v in reg_key.values:
            reg_value = {}
            if hasattr(v, "data") and v.data:
                reg_value["data"] = text_type(v.data)
            if hasattr(v, "name") and v.name:
                reg_value["name"] = text_type(v.name)
            if hasattr(v, "datatype") and v.datatype:
                reg_value["data_type"] = text_type(v.datatype)
            cybox_reg["values"].append(reg_value)
    return cybox_reg


def convert_process(process):
    cybox_p = {}
    if process.name:
        cybox_p["name"] = text_type(process.name)
    if process.pid:
        cybox_p["pid"] = text_type(process.pid)
    if process.creation_time:
        cybox_p["created"] = convert_timestamp(process.creation_time)
    if isinstance(process, WinProcess):
        extended_properties = {}
        process_properties = convert_windows_process(process)
        if process_properties:
            extended_properties["windows-process-ext"] = process_properties
        if isinstance(process, WinService):
            service_properties = convert_windows_service(process)
            if service_properties:
                extended_properties["windows-service-ext"] = service_properties
        if extended_properties:
            cybox_p["extended_properties"] = extended_properties
    if cybox:
        cybox_p["type"] = "process"
    return cybox_p


def convert_windows_process(process):
    ext = {}
    if process.handle_list:
        for h in process.handle_list:
            warn("Windows handles are not a part of CybOX 3.0", 420)
    if process.aslr_enabled:
        ext["asl_enabled"] = bool(process.aslr_enabled)
    if process.dep_enabled:
        ext["dep_enabled"] = bool(process.dep_enabled)
    if process.priority:
        ext["priority"] = text_type(process.priority)
    if process.security_type:
        ext["owner_sid"] = text_type(process.security_type)
    if process.window_title:
        ext["window_title"] = text_type(process.window_title)
    if process.startup_info:
        warn("process:startup_info not handled yet", 803)
    return ext


def convert_windows_service(service):
    cybox_ws = {}
    if hasattr(service, "service_name") and service.service_name:
        cybox_ws["service_name"] = service.service_name.value
    if hasattr(service, "description_list") and service.description_list:
        descriptions = []
        for d in service.description_list:
            descriptions.append(d.value)
        cybox_ws["descriptions"] = descriptions
    if hasattr(service, "display_name") and service.display_name:
        cybox_ws["display_name"] = service.display_name.value
    if hasattr(service, "startup_command_line") and service.startup_command_line:
        cybox_ws["startup_command_line"] = service.startup_command_line.value
    if hasattr(service, "start_type") and service.start_type:
        cybox_ws["start_type"] = map_vocabs_to_label(service.start_type, SERVICE_START_TYPE)
    if hasattr(service, "service_type") and service.service_type:
        cybox_ws["service_type"] = map_vocabs_to_label(service.service_type, SERVICE_TYPE)
    if hasattr(service, "service_status") and service.service_status:
        cybox_ws["service_status"] = map_vocabs_to_label(service.service_status, SERVICE_STATUS)
    if hasattr(service, "service_dll") and service.service_dll:
        warn("WinServiceObject.service_dll is not handled, yet.", 804)
    return cybox_ws


def convert_domain_name(domain_name):
    cybox_dm = {"type": "domain-name"}
    if domain_name.value:
        cybox_dm["value"] = text_type(domain_name.value.value)

    # TODO: resolves_to_refs
    return cybox_dm


def convert_mutex(mutex):
    cybox_mutex = {"type": "mutex"}
    if mutex.name:
        cybox_mutex["name"] = text_type(mutex.name.value)

    return cybox_mutex


def convert_network_connection(conn):
    cybox_traffic = {"type": "network-traffic"}

    # cybox_traffic["start"]
    # cybox_traffic["end"]
    # cybox_traffic["is_active"]
    # cybox_traffic["src_ref"]
    # cybox_traffic["dst_ref"]
    # cybox_traffic["src_port"]
    # cybox_traffic["dst_port"]
    # cybox_traffic["protocols"]
    # cybox_traffic["src_byte_count"]
    # cybox_traffic["dst_byte_count"]
    # cybox_traffic["src_packets"]
    # cybox_traffic["dst_packets"]
    # cybox_traffic["ipfix"]
    # cybox_traffic["src_payload_ref"]
    # cybox_traffic["dst_payload_ref"]
    # cybox_traffic["encapsulates_refs"]
    # cybox_traffic["encapsulated_by_ref"]

    return cybox_traffic


def convert_cybox_object(obj):
    # TODO:  should related objects be handled on a case-by-case basis or just ignored
    if obj.related_objects:
        warn("Related Objects of cyber observables for %s are not handled yet", 809, obj.id_)
    prop = obj.properties
    objs = {}
    if isinstance(prop, Address):
        objs[0] = convert_address(prop)
    elif isinstance(prop, URI):
        objs[0] = convert_uri(prop)
    elif isinstance(prop, EmailMessage):
        # potentially returns multiple objects
        objs = convert_email_message(prop)
    elif isinstance(prop, File):
        # potentially returns multiple objects
        objs = convert_file(prop)
    elif isinstance(prop, WinRegistryKey):
        objs[0] = convert_registry_key(prop)
    elif isinstance(prop, Process):
        objs[0] = convert_process(prop)
    elif isinstance(prop, DomainName):
        objs[0] = convert_domain_name(prop)
    elif isinstance(prop, Mutex):
        objs[0] = convert_mutex(prop)
    elif isinstance(prop, NetworkConnection):
        objs[0] = convert_network_connection(prop)
    else:
        warn("CybOX object %s not handled yet", 805, text_type(type(prop)))
        return None
    if not objs:
        warn("%s did not yield any STIX 2.0 object", 417, text_type(type(prop)))
        return None
    else:
        primary_obj = objs[0]
        if prop.custom_properties:
            for cp in prop.custom_properties.property_:
                primary_obj["x_" + cp.name] = cp.value
        return objs
