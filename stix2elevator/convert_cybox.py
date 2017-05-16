import cybox

from stix2elevator.convert_pattern import *
from stix2elevator.vocab_mappings import *
from stix2elevator.ids import add_object_id_value


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
        warn("The address type %s is not part of STIX 2.0", 421, add.category)


def convert_uri(uri):
    return {"type": "url", "value": uri.value.value}


def convert_file_properties(f):
    file_dict = {"type": "file"}
    dir_dict = None
    if f.size is not None:
        if isinstance(f.size.value, list):
            error("File size window not allowed in top level observable, using first value", 511)
            file_dict["size"] = int(f.size.value[0])
        else:
            file_dict["size"] = int(f.size)
    if f.hashes is not None:
        hashes = {}
        for h in f.hashes:
            if text_type(h.type_).startswith("SHA"):
                hash_type = "SHA" + "-" + text_type(h.type_)[3:]
            elif text_type(h.type_) == "SSDEEP":
                hash_type = text_type(h.type_).lower()
            else:
                hash_type = text_type(h.type_)
            hashes[hash_type] = h.simple_hash_value.value
        file_dict["hashes"] = hashes
    if f.file_name:
        file_dict["file_name"] = text_type(f.file_name)
    elif f.file_path and f.file_path.value:
        index = f.file_path.value.rfind("/")
        if index == -1:
            index = f.file_path.value.rfind("\\")
        if not (f.file_path.value.endswith("/") or f.file_path.value.endswith("\\")):
            file_dict["file_name"] = f.file_path.value[index + 1:]
        dir_path = f.file_path.value[0: index]
        if dir_path:
            dir_dict = {"type": "directory",
                        "path": (f.device_path.value if f.device_path else "") + dir_path}
    if f.full_path:
        warn("1.x full file paths are not processed, yet", 802)
    return file_dict, dir_dict


def convert_file(f):
    objs = {}
    objs[0], dir_dict = convert_file_properties(f)
    if dir_dict:
        objs[1] = dir_dict
        objs[0]["parent_directory_ref"] = "1"
    return objs


def convert_attachment(attachment):
    return {"body_raw_ref": attachment.object_reference}


def convert_email_message(email_message):
    index = 0
    cybox_dict = {}
    email_dict = {"type": "email-message",
                  "is_multipart": False}    # the default
    cybox_dict[index] = email_dict
    index += 1
    if email_message.header:
        header = email_message.header
        if header.date:
            email_dict["date"] = header.date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if header.content_type:
            email_dict["content_type"] = text_type(header.content_type)
        if header.subject:
            email_dict["subject"] = text_type(header.subject)
        if header.from_:
            # should there ever be more than one?
            from_ref = convert_address(header.from_)
            cybox_dict[index] = from_ref
            email_dict["from_ref"] = text_type(index)
            index += 1
        if header.to:
            for t in header.to:
                to_ref = convert_address(t)
                cybox_dict[index] = to_ref
                if "to_refs" not in email_dict:
                    email_dict["to_refs"] = []
                email_dict["to_refs"].append(text_type(index))
                index += 1
        if header.cc:
            for t in header.cc:
                cc_ref = convert_address(t)
                cybox_dict[index] = cc_ref
                if "cc_refs" not in email_dict:
                    email_dict["cc_refs"] = []
                email_dict["cc_refs"].append(text_type(index))
                index += 1
        if header.bcc:
            for t in header.bcc:
                bcc_ref = convert_address(t)
                cybox_dict[index] = bcc_ref
                if "bcc_refs" not in email_dict:
                    email_dict["bcc_refs"] = []
                email_dict["bcc_refs"].append(text_type(index))
                index += 1
        # TODO: handle additional headers
    if email_message.attachments:
        email_dict["is_multipart"] = True
        multiparts = []
        for a in email_message.attachments:
            multiparts.append(convert_attachment(a))
        email_dict["body_multipart"] = multiparts
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
            cybox_p["extensions"] = extended_properties
    if cybox:
        cybox_p["type"] = "process"
    return cybox_p


def convert_windows_process(process):
    ext = {}
    if process.handle_list:
        for h in process.handle_list:
            warn("Windows handles are not a part of STIX 2.0", 420)
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


def create_http_request_extension(http):
    http_extension = {}

    if http.http_client_request is not None:
        if http.http_client_request.http_request_line is not None:
            if http.http_client_request.http_request_line.http_method is not None:
                http_extension["request_method"] = text_type(http.http_client_request.http_request_line.http_method.value.lower())
            if http.http_client_request.http_request_line.version is not None:
                http_extension["request_version"] = text_type(http.http_client_request.http_request_line.version.value.lower())

        if http.http_client_request.http_request_header is not None:
            if http.http_client_request.http_request_header.parsed_header is not None:
                header = {}
                if http.http_client_request.http_request_header.parsed_header.accept is not None:
                    header["Accept"] = text_type(http.http_client_request.http_request_header.parsed_header.accept.value)
                if http.http_client_request.http_request_header.parsed_header.accept_charset is not None:
                    header["Accept-Charset"] = text_type(http.http_client_request.http_request_header.parsed_header.accept_charset.value)
                if http.http_client_request.http_request_header.parsed_header.accept_language is not None:
                    header["Accept-Language"] = text_type(http.http_client_request.http_request_header.parsed_header.accept_language.value)
                if http.http_client_request.http_request_header.parsed_header.accept_datetime is not None:
                    header["Accept-Datetime"] = text_type(http.http_client_request.http_request_header.parsed_header.accept_datetime.value)
                if http.http_client_request.http_request_header.parsed_header.accept_encoding is not None:
                    header["Accept-Encoding"] = text_type(http.http_client_request.http_request_header.parsed_header.accept_encoding.value)
                if http.http_client_request.http_request_header.parsed_header.authorization is not None:
                    header["Authorization"] = text_type(http.http_client_request.http_request_header.parsed_header.authorization.value)
                if http.http_client_request.http_request_header.parsed_header.cache_control is not None:
                    header["Cache-Control"] = text_type(http.http_client_request.http_request_header.parsed_header.cache_control.value)
                if http.http_client_request.http_request_header.parsed_header.connection is not None:
                    header["Connection"] = text_type(http.http_client_request.http_request_header.parsed_header.connection.value)
                if http.http_client_request.http_request_header.parsed_header.cookie is not None:
                    header["Cookie"] = text_type(http.http_client_request.http_request_header.parsed_header.cookie.value)
                if http.http_client_request.http_request_header.parsed_header.content_length is not None:
                    header["Content-Length"] = text_type(http.http_client_request.http_request_header.parsed_header.content_length.value)
                if http.http_client_request.http_request_header.parsed_header.content_md5 is not None:
                    header["Content-MD5"] = text_type(http.http_client_request.http_request_header.parsed_header.content_md5.value)
                if http.http_client_request.http_request_header.parsed_header.content_type is not None:
                    header["Content-Type"] = text_type(http.http_client_request.http_request_header.parsed_header.content_type.value)
                if http.http_client_request.http_request_header.parsed_header.date is not None:
                    header["Date"] = text_type(http.http_client_request.http_request_header.parsed_header.date)
                if http.http_client_request.http_request_header.parsed_header.expect is not None:
                    header["Expect"] = text_type(http.http_client_request.http_request_header.parsed_header.expect.value)
                if http.http_client_request.http_request_header.parsed_header.from_ is not None:
                    from_ = http.http_client_request.http_request_header.parsed_header.from_
                    if from_.address_value is not None:
                        header["From"] = text_type(from_.address_value.value)
                if http.http_client_request.http_request_header.parsed_header.host is not None:
                    host = http.http_client_request.http_request_header.parsed_header.host
                    value = ""
                    has_domain = False
                    if host.domain_name is not None:
                        has_domain = True
                        value += text_type(host.domain_name.value)
                    if host.port is not None and has_domain:
                        value += ":" + text_type(host.port.port_value)
                    else:
                        value += text_type(host.port.port_value)
                    if value:
                        header["Host"] = value
                if http.http_client_request.http_request_header.parsed_header.if_match is not None:
                    header["If-Match"] = text_type(http.http_client_request.http_request_header.parsed_header.if_match.value)
                if http.http_client_request.http_request_header.parsed_header.if_modified_since is not None:
                    header["If-Modified-Since"] = text_type(http.http_client_request.http_request_header.parsed_header.if_modified_since.value)
                if http.http_client_request.http_request_header.parsed_header.if_none_match is not None:
                    header["If-None-Match"] = text_type(http.http_client_request.http_request_header.parsed_header.if_none_match.value)
                if http.http_client_request.http_request_header.parsed_header.if_range is not None:
                    header["If-Range"] = text_type(http.http_client_request.http_request_header.parsed_header.if_range.value)
                if http.http_client_request.http_request_header.parsed_header.if_unmodified_since is not None:
                    header["If-Unmodified-Since"] = text_type(http.http_client_request.http_request_header.parsed_header.if_unmodified_since.value)
                if http.http_client_request.http_request_header.parsed_header.max_forwards is not None:
                    header["Max-Forwards"] = text_type(http.http_client_request.http_request_header.parsed_header.max_forwards.value)
                if http.http_client_request.http_request_header.parsed_header.pragma is not None:
                    header["Pragma"] = text_type(http.http_client_request.http_request_header.parsed_header.pragma.value)
                if http.http_client_request.http_request_header.parsed_header.proxy_authorization is not None:
                    header["Proxy-Authorization"] = text_type(http.http_client_request.http_request_header.parsed_header.proxy_authorization.value)
                if http.http_client_request.http_request_header.parsed_header.range_ is not None:
                    header["Range"] = text_type(http.http_client_request.http_request_header.parsed_header.range_.value)
                if http.http_client_request.http_request_header.parsed_header.referer is not None:
                    header["Referer"] = text_type(http.http_client_request.http_request_header.parsed_header.referer.value)
                if http.http_client_request.http_request_header.parsed_header.te is not None:
                    header["TE"] = text_type(http.http_client_request.http_request_header.parsed_header.te.value)
                if http.http_client_request.http_request_header.parsed_header.user_agent is not None:
                    header["User-Agent"] = text_type(http.http_client_request.http_request_header.parsed_header.user_agent.value)
                if http.http_client_request.http_request_header.parsed_header.via is not None:
                    header["Via"] = text_type(http.http_client_request.http_request_header.parsed_header.via.value)
                if http.http_client_request.http_request_header.parsed_header.warning is not None:
                    header["Warning"] = text_type(http.http_client_request.http_request_header.parsed_header.warning.value)
                if http.http_client_request.http_request_header.parsed_header.dnt is not None:
                    header["DNT"] = text_type(http.http_client_request.http_request_header.parsed_header.dnt.value)
                if http.http_client_request.http_request_header.parsed_header.x_requested_with is not None:
                    header["X-Requested-With"] = text_type(http.http_client_request.http_request_header.parsed_header.x_requested_with.value)
                if http.http_client_request.http_request_header.parsed_header.x_forwarded_for is not None:
                    header["X-Forwarded-For"] = text_type(http.http_client_request.http_request_header.parsed_header.x_forwarded_for.value)
                if http.http_client_request.http_request_header.parsed_header.x_att_deviceid is not None:
                    header["X-ATT-DeviceId"] = text_type(http.http_client_request.http_request_header.parsed_header.x_att_deviceid.value)
                if http.http_client_request.http_request_header.parsed_header.x_wap_profile is not None:
                    header["X-Wap-Profile"] = text_type(http.http_client_request.http_request_header.parsed_header.x_wap_profile.value)

                http_extension["request_header"] = header

    # http_extension["request_value"]
    # http_extension["message_body_length"]
    # http_extension["message_body_data_length"]

    return http_extension


def convert_network_connection(conn):
    index = 0
    cybox_dict = {}
    cybox_traffic = {}

    def create_domain_name_object(dn):
        return {"type": "domain-name", "value": text_type(dn.value)}

    if conn.creation_time is not None:
        cybox_traffic["start"] = convert_timestamp_string(conn.creation_time.value, None, None)

    cybox_traffic["protocols"] = []

    if conn.layer3_protocol is not None:
        cybox_traffic["protocols"].append(text_type(conn.layer3_protocol.value).lower())

    if conn.source_socket_address is not None:
        # The source, if present will have index "0".
        if conn.source_socket_address.port is not None:
            if conn.source_socket_address.port.port_value is not None:
                cybox_traffic["src_port"] = int(conn.source_socket_address.port.port_value)
            if conn.source_socket_address.port.layer4_protocol is not None:
                cybox_traffic["protocols"].append(text_type(conn.source_socket_address.port.layer4_protocol.value.lower()))
        if conn.source_socket_address.ip_address is not None:
            source = convert_address(conn.source_socket_address.ip_address)
            cybox_traffic["src_ref"] = str(index)
            cybox_dict[index] = source
            index += 1
        elif conn.source_socket_address.hostname is not None:
            if conn.source_socket_address.hostname.is_domain_name and conn.source_socket_address.hostname.hostname_value is not None:
                source_domain = create_domain_name_object(conn.source_socket_address.hostname.hostname_value)
                cybox_traffic["src_ref"] = str(index)
                cybox_dict[index] = source_domain
                index += 1
            elif (conn.source_socket_address.hostname.naming_system is not None and
                    any(x.value == "DNS" for x in conn.source_socket_address.hostname.naming_system)):
                source_domain = create_domain_name_object(conn.source_socket_address.hostname.hostname_value)
                cybox_traffic["src_ref"] = str(index)
                cybox_dict[index] = source_domain
                index += 1

    if conn.destination_socket_address is not None:
        # The destination will have index "1" if there is a source.
        if conn.destination_socket_address.port is not None:
            if conn.destination_socket_address.port is not None:
                cybox_traffic["dst_port"] = int(conn.destination_socket_address.port.port_value)
            if conn.destination_socket_address.port.layer4_protocol is not None:
                cybox_traffic["protocols"].append(text_type(conn.destination_socket_address.port.layer4_protocol.value.lower()))
        if conn.destination_socket_address.ip_address is not None:
            destination = convert_address(conn.destination_socket_address.ip_address)
            cybox_traffic["dst_ref"] = str(index)
            cybox_dict[index] = destination
            index += 1
        elif conn.destination_socket_address.hostname is not None:
            if conn.destination_socket_address.hostname.is_domain_name and conn.destination_socket_address.hostname.hostname_value is not None:
                destination_domain = create_domain_name_object(conn.destination_socket_address.hostname.hostname_value)
                cybox_traffic["dst_ref"] = str(index)
                cybox_dict[index] = destination_domain
                index += 1
            elif (conn.destination_socket_address.hostname.naming_system is not None and
                    any(x.value == "DNS" for x in conn.destination_socket_address.hostname.naming_system)):
                destination_domain = create_domain_name_object(conn.destination_socket_address.hostname.hostname_value)
                cybox_traffic["dst_ref"] = str(index)
                cybox_dict[index] = destination_domain
                index += 1

    if conn.layer4_protocol is not None:
        cybox_traffic["protocols"].append(text_type(conn.layer4_protocol.value).lower())

    if conn.layer7_protocol is not None:
        cybox_traffic["protocols"].append(text_type(conn.layer7_protocol.value).lower())

    if conn.layer7_connections is not None:
        if conn.layer7_connections.http_session is not None:
            # HTTP extension
            cybox_traffic["extensions"] = {}
            if conn.layer7_connections.http_session.http_request_response:
                cybox_traffic["extensions"] = {"http-request-ext": create_http_request_extension(conn.layer7_connections.http_session.http_request_response[0])}

                if len(conn.layer7_connections.http_session.http_request_response) > 1:
                    warn("Only one Layer7_Connections/HTTP_Request_Response used fot http-request-ext, using first value", 512)
        if conn.layer7_connections.dns_query:
            def add_resource_records(resource, index):
                # All domain records will be included with resolves to refs if ip address is present.
                for res in resource:
                    has_ip = False
                    if res.ip_address is not None:
                        cybox_dict[index] = convert_address(res.ip_address)
                        index += 1
                        has_ip = True
                    if res.domain_name is not None:
                        domain = create_domain_name_object(res.domain_name)
                        if has_ip:
                            domain["resolves_to_refs"] = index - 1
                        cybox_dict[index] = domain
                        index += 1
                    if res.entry_type is not None:
                        warn("Resource_Record/Entry_Type content not supported in STIX 2.0", 424)
                    if res.record_name is not None:
                        warn("Resource_Record/Record_Name content not supported in STIX 2.0", 424)
                    if res.record_type is not None:
                        warn("Resource_Record/Record_Type content not supported in STIX 2.0", 424)
                    if res.ttl is not None:
                        warn("Resource_Record/TTL content not supported in STIX 2.0", 424)
                    if res.flags is not None:
                        warn("Resource_Record/Flags content not supported in STIX 2.0", 424)
                    if res.data_length is not None:
                        warn("Resource_Record/Data_Length content not supported in STIX 2.0", 424)

            for dns in conn.layer7_connections.dns_query:
                if dns.answer_resource_records is not None and dns.answer_resource_records.resource_record:
                    add_resource_records(dns.answer_resource_records.resource_record, index)
                if dns.authority_resource_records is not None and dns.authority_resource_records.recource_record:
                    add_resource_records(dns.authority_resource_records.recource_record, index)
                if dns.additional_records is not None and dns.additional_records.resource_record:
                    add_resource_records(dns.additional_records.resource_record, index)
                if dns.question is not None:
                    if dns.question.qname is not None:
                        warn("Question\QName content not supported in STIX 2.0", 424)
                    if dns.question.qtype is not None:
                        warn("Question\QType content not supported in STIX 2.0", 424)
                    if dns.question.qclass is not None:
                        warn("Question\QClass content not supported in STIX 2.0", 424)

    if cybox_traffic:
        cybox_traffic["type"] = "network-traffic"
        cybox_dict[index] = cybox_traffic

    # cybox_traffic["end"]
    # cybox_traffic["is_active"]
    # cybox_traffic["src_byte_count"]
    # cybox_traffic["dst_byte_count"]
    # cybox_traffic["src_packets"]
    # cybox_traffic["dst_packets"]
    # cybox_traffic["ipfix"]
    # cybox_traffic["src_payload_ref"]
    # cybox_traffic["dst_payload_ref"]
    # cybox_traffic["encapsulates_refs"]
    # cybox_traffic["encapsulated_by_ref"]

    return cybox_dict


def convert_cybox_object(obj):
    # TODO:  should related objects be handled on a case-by-case basis or just ignored
    prop = obj.properties
    objs = {}
    if prop is None:
        return None
    elif isinstance(prop, Address):
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
        # potentially returns multiple objects
        objs = convert_network_connection(prop)
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
        if obj.id_:
            add_object_id_value(obj.id_, objs)
        return objs


def find_file_object_index(objs):
    for k, v in objs.items():
        if v["type"] == "file":
            return k
    return None


def add_attachment_objects(o, objs_to_add):
    o["objects"].update(objs_to_add)


def renumber_co(co, number_mapping):
    for k, v in co.items():
        if k.endswith("ref"):
            co[k] = number_mapping[co[k]]
        if k.endswith("refs"):
            new_refs = []
            for ref in co[k]:
                new_refs.append(number_mapping[ref])
            co[k] = new_refs
    return co


def renumber_objs(objs, number_mapping):

    new_objects = {}
    for k, v in objs.items():
        new_objects[number_mapping[k]] = renumber_co(v, number_mapping)
    return new_objects


def fix_cybox_relationships(observed_data):
    for o in observed_data:
        objs_to_add = {}
        if not o["objects"]:
            continue
        current_largest_id = max(o["objects"].keys())
        for co in o["objects"].values():
            if co["type"] == "email-message":
                if co["is_multipart"]:
                    for mp in co["body_multipart"]:
                        objs = get_object_id_value(mp["body_raw_ref"])
                        if objs:
                            file_obj_index = find_file_object_index(objs)
                            if file_obj_index >= 0:
                                number_mapping = {}
                                for k in objs.keys():
                                    current_largest_id += 1
                                    number_mapping[k] = current_largest_id
                                new_objs = renumber_objs(objs, number_mapping)
                                mp["body_raw_ref"] = text_type(number_mapping[file_obj_index])
                                objs_to_add.update(new_objs)
                            else:
                                pass  # warn
                        else:
                            pass  # warn mess
        if objs_to_add:
            add_attachment_objects(o, objs_to_add)
