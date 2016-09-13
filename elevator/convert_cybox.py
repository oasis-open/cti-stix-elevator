# Copyright (c) 2016, The MITRE Corporation. All rights reserved.
# See LICENSE.txt for complete terms.

import sys
import stix
import cybox
from cybox.objects.address_object import Address
from cybox.objects.uri_object import URI
from cybox.objects.file_object import File
from cybox.objects.win_registry_key_object import WinRegistryKey
from cybox.objects.process_object import Process
from cybox.objects.win_process_object import WinProcess
from cybox.objects.win_service_object import WinService

from vocab_mappings import *

from utils import *

def convert_address(add):
    if add.category == add.CAT_IPV4:
       return { "type": "ipv4-address-object", "value": add.address_value.value}

def convert_uri(uri):
    return { "type": "url-object", "value": + uri.value.value }

def convert_file(file):
    first_one = True
    cybox = { "type": "file-object" }
    if file.size is not None:
        if isinstance(file.size.value, list):
            error("file size window not allowed in top level observable, using first value")
            cybox["size"] = int(file.size.value[0])
        else:
            cybox["size"] = int(file.size)
    if file.hashes is not None:
        hashes = {}
        for hash in file.hashes:
            hashes[str(hash.type_).lower()] = hash.simple_hash_value.value
        cybox["hashes"] = hashes
    if file.file_name:
        cybox["file_name"] = str(file.file_name)
    # TODO: handle path properties be generating a directory object?
    return cybox

def convert_registry_key(reg_key):
    cybox = {"type": "windows-registry-key"}
    if reg_key.key or reg_key.hive:
        full_key = ""
        if reg_key.hive:
            full_key += reg_key.hive.value + "\\"
        if reg_key.key:
            full_key += reg_key.key.value
        cybox["key"] = full_key
    else:
        error("windows-registry-key is required to have a key property")
    if reg_key.values:
        cybox["values"] = []
        for v in reg_key.values:
            reg_value = {}
            if hasattr(v, "data") and v.data:
                reg_value["data"] = str(v.data)
            if hasattr(v, "name") and v.name:
                reg_value["name"] = str(v.name)
            if hasattr(v, "datatype") and v.datatype:
                reg_value["data_type"] = str(v.datatype)
            cybox["values"].append(reg_value)
    return cybox

def convert_process(process):
    cybox = {}
    if process.name:
        cybox["name"] = str(process.name)
    if process.pid:
        cybox["pid"] = str(process.pid)
    if process.creation_time:
        cybox["created"] = convert_timestamp(process.creation_time)
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
            cybox["extended_properties"] = extended_properties
    if cybox:
        cybox["type"] = "process"
    return cybox

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
    cybox = {}
    if hasattr(service, "service_name") and service.service_name:
        cybox["service_name"] = service.service_name.value
    if hasattr(service, "description_list") and service.description_list:
        descriptions = []
        for d in service.description_list:
            descriptions.append(d.value)
        cybox["descriptions"] = descriptions
    if hasattr(service, "display_name") and service.display_name:
        cybox["display_name"] = service.display_name.value
    if hasattr(service, "startup_command_line") and service.startup_command_line:
        cybox["startup_command_line"] = service.startup_command_line.value
    if hasattr(service, "start_type") and service.start_type:
        cybox["start_type"] = map_vocabs_to_label(service.start_type, SERVICE_START_TYPE)
    if hasattr(service, "service_type") and service.service_type:
        cybox["service_type"] = map_vocabs_to_label(service.service_type, SERVICE_TYPE)
    if hasattr(service, "service_status") and service.service_status:
        cybox["service_status"] = map_vocabs_to_label(service.service_status, SERVICE_STATUS)
    if hasattr(service, "service_dll") and service.service_dll:
        warn("WinServiceObject.service_dll is not handled, yet.")
    return cybox


def convert_cybox_object(obj, cyboxContainer):
    prop = obj.properties
    if isinstance(prop, Address):
        cybox_obj = convert_address(prop)
    elif isinstance(prop, URI):
        cybox_obj = convert_uri(prop)
    elif isinstance(prop, File):
        cybox_obj = convert_file(prop)
    elif isinstance(prop, WinRegistryKey):
        cybox_obj = convert_registry_key(prop)
    elif isinstance(prop, Process):
        cybox_obj = convert_process(prop)
    else:
        warn(str(type(obj)) + " not handled yet")
        return None
    if cybox_obj:
        cyboxContainer["objects"] = { "0": cybox_obj }
        return cyboxContainer
    else:
        warn(str(prop) + " didn't yield any STIX 2.0 object")
        return None


