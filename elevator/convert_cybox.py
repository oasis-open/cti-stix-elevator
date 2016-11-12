# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import cybox

from elevator.convert_pattern import *
from elevator.vocab_mappings import *


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
        warn("The address type " + add.category + " is not part of Cybox 3.0")


def convert_uri(uri):
    return {"type": "url-object", "value": + uri.value.value}


def create_directory(file):
    return {"type": "directory", "path": file.file_path.value}


def convert_file(file, directory_ref):
    cybox_dict = {"type": "file"}
    if file.size is not None:
        if isinstance(file.size.value, list):
            error("File size window not allowed in top level observable, using first value")
            cybox_dict["size"] = int(file.size.value[0])
        else:
            cybox_dict["size"] = int(file.size)
    if file.hashes is not None:
        hashes = {}
        for h in file.hashes:
            hashes[str(h.type_).lower()] = h.simple_hash_value.value
        cybox_dict["hashes"] = hashes
    if file.file_name:
        cybox_dict["file_name"] = str(file.file_name)
    if directory_ref != -1:
        cybox_dict["parent_directory_ref"] = directory_ref
    if file.full_path:
        warn("1.x full file paths are not processed, yet")
    return cybox_dict


def convert_email_message(email_message):
    index = 0
    cybox_dict = {}
    email_dict = {"type": "email-message"}
    cybox_dict[index] = email_dict
    index += 1
    if email_message.header:
        header = email_message.header
        if header.date:
            email_dict["date"] = header, date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if header.content_type:
            email_dict["content_type"] = header.content_type
        if header.subject:
            email_dict["subject"] = header.subject
        if header.from_:
            # should there ever be more than one?
            from_ref = convert_address(header.from_)
            cybox_dict[index] = from_ref
            email_dict["from_ref"] = index
            index += 1
        if header.to:
            for t in header.to:
                to_ref = convert_address(t)
                cybox_dict[index] = to_ref
                if "to_refs" not in email_dict:
                    email_dict["to_refs"] = []
                email_dict["to_refs"].append(index)
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
        error("windows-registry-key is required to have a key property")
    if reg_key.values:
        cybox_reg["values"] = []
        for v in reg_key.values:
            reg_value = {}
            if hasattr(v, "data") and v.data:
                reg_value["data"] = str(v.data)
            if hasattr(v, "name") and v.name:
                reg_value["name"] = str(v.name)
            if hasattr(v, "datatype") and v.datatype:
                reg_value["data_type"] = str(v.datatype)
            cybox_reg["values"].append(reg_value)
    return cybox_reg


def convert_process(process):
    cybox_p = {}
    if process.name:
        cybox_p["name"] = str(process.name)
    if process.pid:
        cybox_p["pid"] = str(process.pid)
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
            warn("Window handles are not a part of CybOX 3.0")
    if process.aslr_enabled:
        ext["asl_enabled"] = bool(process.aslr_enabled)
    if process.dep_enabled:
        ext["dep_enabled"] = bool(process.dep_enabled)
    if process.priority:
        ext["priority"] = str(process.priority)
    if process.security_type:
        ext["owner_sid"] = str(process.security_type)
    if process.window_title:
        ext["window_title"] = str(process.window_title)
    if process.startup_info:
        warn("process:startup_info not handled yet")
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
        warn("WinServiceObject.service_dll is not handled, yet.")
    return cybox_ws


def convert_domain_name(domain_name):
    cybox_dm = {"type": "domain-name"}
    if domain_name.value:
        cybox_dm["value"] = domain_name.value.value

    # TODO: resolves_to_refs
    return cybox_dm


def convert_mutex(mutex):
    cybox_mutex = {"type": "mutex"}
    if mutex.name:
        cybox_mutex["name"] = mutex.name.value

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
    prop = obj.properties
    objs = {}
    obj_index = 0
    if isinstance(prop, Address):
        objs[obj_index] = convert_address(prop)
    elif isinstance(prop, URI):
        objs[obj_index] = convert_uri(prop)
    elif isinstance(prop, EmailMessage):
        objs = convert_email_message(prop)
    elif isinstance(prop, File):
        directory_obj_index = -1
        if prop.file_path:
            objs[obj_index] = create_directory(prop)
            directory_obj_index = obj_index
            obj_index += 1
        objs[obj_index] = convert_file(prop, directory_obj_index)
    elif isinstance(prop, WinRegistryKey):
        objs[obj_index] = convert_registry_key(prop)
    elif isinstance(prop, Process):
        objs[obj_index] = convert_process(prop)
    elif isinstance(prop, DomainName):
        objs[obj_index] = convert_domain_name(prop)
    elif isinstance(prop, Mutex):
        objs[obj_index] = convert_mutex(prop)
    elif isinstance(prop, NetworkConnection):
        objs[obj_index] = convert_network_connection(prop)
    else:
        warn("{obj} not handled yet".format(obj=str(type(obj))))
        return None
    if not objs:
        warn("{obj} didn't yield any STIX 2.0 object".format(obj=str(prop)))
        return None
    else:
        return objs
