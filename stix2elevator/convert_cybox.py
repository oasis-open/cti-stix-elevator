from cybox.objects.account_object import Account
from cybox.objects.address_object import Address
from cybox.objects.domain_name_object import DomainName
from cybox.objects.email_message_object import EmailMessage
from cybox.objects.file_object import File
from cybox.objects.http_session_object import HTTPSession
from cybox.objects.mutex_object import Mutex
from cybox.objects.network_connection_object import NetworkConnection
from cybox.objects.network_packet_object import NetworkPacket
from cybox.objects.network_socket_object import NetworkSocket
from cybox.objects.process_object import Process
from cybox.objects.unix_user_account_object import UnixUserAccount
from cybox.objects.uri_object import URI
from cybox.objects.user_account_object import UserAccount
from cybox.objects.win_computer_account_object import WinComputerAccount
from cybox.objects.win_process_object import WinProcess
from cybox.objects.win_registry_key_object import WinRegistryKey
from cybox.objects.win_service_object import WinService
from six import text_type

from stix2elevator.common import ADDRESS_FAMILY_ENUMERATION, SOCKET_OPTIONS
from stix2elevator.ids import add_object_id_value, get_object_id_value
from stix2elevator.options import error, get_option_value, info, warn
from stix2elevator.utils import (convert_timestamp_to_string,
                                 map_vocabs_to_label)
from stix2elevator.vocab_mappings import (SERVICE_START_TYPE, SERVICE_STATUS,
                                          SERVICE_TYPE)


def convert_account(acc):
    account_dict = {"type": "user-account"}
    if acc.creation_date:
        account_dict["account_created"] = acc.creation_date.value
    # if acc.last_accessed_time:
    #    account_dict["account_last_login"] = acc.last_accessed_time
    if acc.disabled:
        account_dict["is_disabled"] = acc.disabled
    if acc.authentication and get_option_value("spec_version") == "2.1":
        if acc.authentication.authentication_data:
            account_dict["credential"] = acc.authentication.authentication_data
    if isinstance(acc, UserAccount):
        if acc.username:
            account_dict["account_login"] = acc.username.value
        if acc.full_name:
            account_dict["display_name"] = acc.full_name.value
        if acc.last_login:
            account_dict["account_last_login"] = convert_timestamp_to_string(acc.last_login.value)
        if isinstance(acc, UnixUserAccount):
            account_dict["account_type"] = "unix"
            ext_dict = {}
            if acc.group_id:
                ext_dict["gid"] = acc.group_id.value
            if acc.user_id:
                account_dict["user_id"] = text_type(acc.user_id.value)
            if acc.login_shell:
                ext_dict["shell"] = acc.login_shell.value
            if acc.home_directory:
                ext_dict["home_dir"] = acc.home_directory.value
            if acc.group_list:
                ext_dict["groups"] = []
                for g in acc.group_list:
                    ext_dict["groups"].append(text_type(g.group_id.value))
            if ext_dict != {}:
                account_dict["extensions"] = {"unix-account-ext": ext_dict}
        elif isinstance(acc, WinComputerAccount):
            if acc.domain:
                account_dict["account_type"] = "windows-domain"
            else:
                account_dict["account_type"] = "windows-local"
    return account_dict


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
            warn("File size 'window' not allowed in top level observable, using first value", 511)
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
        file_dict["name"] = text_type(f.file_name)
    elif f.file_path and f.file_path.value:
        # this index is an array index, not for the objects dict
        index = f.file_path.value.rfind("/")
        if index == -1:
            index = f.file_path.value.rfind("\\")
        if not (f.file_path.value.endswith("/") or f.file_path.value.endswith("\\")):
            file_dict["name"] = f.file_path.value[index + 1:]
        dir_path = f.file_path.value[0: index]
        if dir_path:
            dir_dict = {"type": "directory",
                        "path": (f.device_path.value if f.device_path else "") + dir_path}
    if f.full_path:
        warn("1.x full file paths are not processed, yet", 802)
    return file_dict, dir_dict


def convert_file(f):
    objs = {}
    objs["0"], dir_dict = convert_file_properties(f)
    if dir_dict:
        objs["1"] = dir_dict
        objs["0"]["parent_directory_ref"] = "1"
    return objs


def convert_attachment(attachment):
    return {"body_raw_ref": attachment.object_reference}


def convert_email_message(email_message):
    index = 0
    cybox_dict = {}
    email_dict = {"type": "email-message",
                  "is_multipart": False}    # the default
    cybox_dict[text_type(index)] = email_dict
    index += 1
    if email_message.header:
        header = email_message.header
        if header.date:
            email_dict["date"] = convert_timestamp_to_string(header.date)
        if header.content_type:
            email_dict["content_type"] = text_type(header.content_type)
        if header.subject:
            email_dict["subject"] = text_type(header.subject)
        if header.from_:
            # should there ever be more than one?
            from_ref = convert_address(header.from_)
            cybox_dict[text_type(index)] = from_ref
            email_dict["from_ref"] = text_type(index)
            index += 1
        if header.to:
            for t in header.to:
                to_ref = convert_address(t)
                cybox_dict[text_type(index)] = to_ref
                if "to_refs" not in email_dict:
                    email_dict["to_refs"] = []
                email_dict["to_refs"].append(text_type(index))
                index += 1
        if header.cc:
            for t in header.cc:
                cc_ref = convert_address(t)
                cybox_dict[text_type(index)] = cc_ref
                if "cc_refs" not in email_dict:
                    email_dict["cc_refs"] = []
                email_dict["cc_refs"].append(text_type(index))
                index += 1
        if header.bcc:
            for t in header.bcc:
                bcc_ref = convert_address(t)
                cybox_dict[text_type(index)] = bcc_ref
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
    if reg_key.modified_time:
        cybox_reg["modified"] = convert_timestamp_to_string(reg_key.modified_time)
    return cybox_reg


def create_process_ref(cp, process_dict, cybox_dict, index, prop):
    cp_ref = {"type": "process", "pid": cp.value}
    cybox_dict[text_type(index)] = cp_ref
    if prop == "child_refs":
        if prop not in process_dict:
            process_dict["child_refs"] = []
        process_dict[prop].append(text_type(index))
    else:
        process_dict[prop] = text_type(index)


def convert_process(process):
    index = 0
    cybox_dict = {}
    process_dict = {"type": "process"}
    cybox_dict[text_type(index)] = process_dict
    index += 1
    if process.name and get_option_value("spec_version") == "2.0":
        process_dict["name"] = text_type(process.name)
    if process.pid:
        process_dict["pid"] = process.pid.value
    if process.creation_time:
        process_dict["created"] = convert_timestamp_to_string(process.creation_time.value)
    if process.child_pid_list:
        for cp in process.child_pid_list:
            create_process_ref(cp, process_dict, cybox_dict, index, "child_refs")
            index += 1
    if process.parent_pid:
        create_process_ref(process.parent_pid, process_dict, cybox_dict, index, "parent_ref")
        index += 1
    if process.argument_list and get_option_value("spec_version") == "2.0":
        process_dict["arguments"] = []
        for a in process.argument_list:
            process_dict["arguments"].append(a.value)
    if process.network_connection_list:
        renumbered_nc_dicts = {}
        process_dict["opened_connection_refs"] = []
        for nc in process.network_connection_list:
            nc_dicts = convert_network_connection(nc)
            root_obj_index = find_index_of_type(nc_dicts, "network-traffic")
            current_largest_id, number_mapping = do_renumbering(nc_dicts,
                                                                index,
                                                                root_obj_index,
                                                                renumbered_nc_dicts)
            add_objects(cybox_dict, renumbered_nc_dicts)
            process_dict["opened_connection_refs"].append(text_type(number_mapping[root_obj_index]))
            index = current_largest_id
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
            process_dict["extensions"] = extended_properties
    return cybox_dict


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
    if process.security_id:
        ext["owner_sid"] = text_type(process.security_id)
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


def convert_http_client_request(request):
    http_extension = {}

    if request.http_request_line is not None:
        if request.http_request_line.http_method is not None:
            http_extension["request_method"] = text_type(request.http_request_line.http_method.value.lower())
        if request.http_request_line.version is not None:
            http_extension["request_version"] = text_type(request.http_request_line.version.value.lower())

    if request.http_request_header is not None:
        if request.http_request_header.parsed_header is not None:
            header = {}
            if request.http_request_header.parsed_header.accept is not None:
                header["Accept"] = text_type(request.http_request_header.parsed_header.accept.value)
            if request.http_request_header.parsed_header.accept_charset is not None:
                header["Accept-Charset"] = text_type(request.http_request_header.parsed_header.accept_charset.value)
            if request.http_request_header.parsed_header.accept_language is not None:
                header["Accept-Language"] = text_type(request.http_request_header.parsed_header.accept_language.value)
            if request.http_request_header.parsed_header.accept_datetime is not None:
                header["Accept-Datetime"] = text_type(request.http_request_header.parsed_header.accept_datetime.value)
            if request.http_request_header.parsed_header.accept_encoding is not None:
                header["Accept-Encoding"] = text_type(request.http_request_header.parsed_header.accept_encoding.value)
            if request.http_request_header.parsed_header.authorization is not None:
                header["Authorization"] = text_type(request.http_request_header.parsed_header.authorization.value)
            if request.http_request_header.parsed_header.cache_control is not None:
                header["Cache-Control"] = text_type(request.http_request_header.parsed_header.cache_control.value)
            if request.http_request_header.parsed_header.connection is not None:
                header["Connection"] = text_type(request.http_request_header.parsed_header.connection.value)
            if request.http_request_header.parsed_header.cookie is not None:
                header["Cookie"] = text_type(request.http_request_header.parsed_header.cookie.value)
            if request.http_request_header.parsed_header.content_length is not None:
                header["Content-Length"] = text_type(request.http_request_header.parsed_header.content_length.value)
            if request.http_request_header.parsed_header.content_md5 is not None:
                header["Content-MD5"] = text_type(request.http_request_header.parsed_header.content_md5.value)
            if request.http_request_header.parsed_header.content_type is not None:
                header["Content-Type"] = text_type(request.http_request_header.parsed_header.content_type.value)
            if request.http_request_header.parsed_header.date is not None:
                header["Date"] = text_type(request.http_request_header.parsed_header.date)
            if request.http_request_header.parsed_header.expect is not None:
                header["Expect"] = text_type(request.http_request_header.parsed_header.expect.value)
            if request.http_request_header.parsed_header.from_ is not None:
                from_ = request.http_request_header.parsed_header.from_
                if from_.address_value is not None:
                    header["From"] = text_type(from_.address_value.value)
            if request.http_request_header.parsed_header.host is not None:
                host = request.http_request_header.parsed_header.host
                value = ""
                has_domain = False
                if host.domain_name is not None:
                    has_domain = True
                    value += text_type(host.domain_name.value)
                if host.port is not None:
                    if has_domain:
                        value += ":" + text_type(host.port.port_value)
                    else:
                        value += text_type(host.port.port_value)
                if value:
                    header["Host"] = value
            if request.http_request_header.parsed_header.if_match is not None:
                header["If-Match"] = text_type(request.http_request_header.parsed_header.if_match.value)
            if request.http_request_header.parsed_header.if_modified_since is not None:
                header["If-Modified-Since"] = text_type(
                    request.http_request_header.parsed_header.if_modified_since.value)
            if request.http_request_header.parsed_header.if_none_match is not None:
                header["If-None-Match"] = text_type(request.http_request_header.parsed_header.if_none_match.value)
            if request.http_request_header.parsed_header.if_range is not None:
                header["If-Range"] = text_type(request.http_request_header.parsed_header.if_range.value)
            if request.http_request_header.parsed_header.if_unmodified_since is not None:
                header["If-Unmodified-Since"] = text_type(
                    request.http_request_header.parsed_header.if_unmodified_since.value)
            if request.http_request_header.parsed_header.max_forwards is not None:
                header["Max-Forwards"] = text_type(request.http_request_header.parsed_header.max_forwards.value)
            if request.http_request_header.parsed_header.pragma is not None:
                header["Pragma"] = text_type(request.http_request_header.parsed_header.pragma.value)
            if request.http_request_header.parsed_header.proxy_authorization is not None:
                header["Proxy-Authorization"] = text_type(
                    request.http_request_header.parsed_header.proxy_authorization.value)
            if request.http_request_header.parsed_header.range_ is not None:
                header["Range"] = text_type(request.http_request_header.parsed_header.range_.value)
            if request.http_request_header.parsed_header.referer is not None:
                header["Referer"] = text_type(request.http_request_header.parsed_header.referer.value)
            if request.http_request_header.parsed_header.te is not None:
                header["TE"] = text_type(request.http_request_header.parsed_header.te.value)
            if request.http_request_header.parsed_header.user_agent is not None:
                header["User-Agent"] = text_type(request.http_request_header.parsed_header.user_agent.value)
            if request.http_request_header.parsed_header.via is not None:
                header["Via"] = text_type(request.http_request_header.parsed_header.via.value)
            if request.http_request_header.parsed_header.warning is not None:
                header["Warning"] = text_type(request.http_request_header.parsed_header.warning.value)
            if request.http_request_header.parsed_header.dnt is not None:
                header["DNT"] = text_type(request.http_request_header.parsed_header.dnt.value)
            if request.http_request_header.parsed_header.x_requested_with is not None:
                header["X-Requested-With"] = text_type(request.http_request_header.parsed_header.x_requested_with.value)
            if request.http_request_header.parsed_header.x_forwarded_for is not None:
                header["X-Forwarded-For"] = text_type(request.http_request_header.parsed_header.x_forwarded_for.value)
            if request.http_request_header.parsed_header.x_att_deviceid is not None:
                header["X-ATT-DeviceId"] = text_type(request.http_request_header.parsed_header.x_att_deviceid.value)
            if request.http_request_header.parsed_header.x_wap_profile is not None:
                header["X-Wap-Profile"] = text_type(request.http_request_header.parsed_header.x_wap_profile.value)

            http_extension["request_header"] = header
            # http_extension["request_value"]
            # http_extension["message_body_length"]
            # http_extension["message_body_data_length"]
            return http_extension


def convert_http_network_connection_extension(http):
    if http is not None:
        return convert_http_client_request(http.http_client_request)


def convert_network_connection(conn):
    index = 0
    cybox_dict = {}
    cybox_traffic = {}

    def create_domain_name_object(dn):
        return {"type": "domain-name", "value": text_type(dn.value)}

    if conn.creation_time is not None:
        cybox_traffic["start"] = convert_timestamp_to_string(conn.creation_time.value, None, None)

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
            cybox_dict[text_type(index)] = source
            index += 1
        elif conn.source_socket_address.hostname is not None:
            if conn.source_socket_address.hostname.is_domain_name and conn.source_socket_address.hostname.hostname_value is not None:
                source_domain = create_domain_name_object(conn.source_socket_address.hostname.hostname_value)
                cybox_traffic["src_ref"] = str(index)
                cybox_dict[text_type(index)] = source_domain
                index += 1
            elif (conn.source_socket_address.hostname.naming_system is not None and
                    any(x.value == "DNS" for x in conn.source_socket_address.hostname.naming_system)):
                source_domain = create_domain_name_object(conn.source_socket_address.hostname.hostname_value)
                cybox_traffic["src_ref"] = str(index)
                cybox_dict[text_type(index)] = source_domain
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
            cybox_dict[text_type(index)] = destination
            index += 1
        elif conn.destination_socket_address.hostname is not None:
            if conn.destination_socket_address.hostname.is_domain_name and conn.destination_socket_address.hostname.hostname_value is not None:
                destination_domain = create_domain_name_object(conn.destination_socket_address.hostname.hostname_value)
                cybox_traffic["dst_ref"] = str(index)
                cybox_dict[text_type(index)] = destination_domain
                index += 1
            elif (conn.destination_socket_address.hostname.naming_system is not None and
                    any(x.value == "DNS" for x in conn.destination_socket_address.hostname.naming_system)):
                destination_domain = create_domain_name_object(conn.destination_socket_address.hostname.hostname_value)
                cybox_traffic["dst_ref"] = str(index)
                cybox_dict[text_type(index)] = destination_domain
                index += 1

    if conn.layer4_protocol is not None:
        cybox_traffic["protocols"].append(text_type(conn.layer4_protocol.value).lower())

    if conn.layer7_protocol is not None:
        cybox_traffic["protocols"].append(text_type(conn.layer7_protocol.value).lower())

    if conn.layer7_connections is not None:
        if conn.layer7_connections.http_session is not None:
            # HTTP extension
            cybox_traffic["extensions"] = {}
            request_responses = conn.layer7_connections.http_session.http_request_response
            if request_responses:
                cybox_traffic["extensions"] = {
                    "http-request-ext": convert_http_network_connection_extension(request_responses[0])}
                if len(conn.layer7_connections.http_session.http_request_response) > 1:
                    warn("Only one HTTP_Request_Response used for http-request-ext, using first value", 512)
        if conn.layer7_connections.dns_query:
            warn("Layer7_Connections/DNS_Query content not supported in STIX 2.0", 424)

    if cybox_traffic:
        cybox_traffic["type"] = "network-traffic"
        cybox_dict[text_type(index)] = cybox_traffic

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


def split_into_requests_and_responses(req_resp_list):
    requests = []
    responses = []
    for r in req_resp_list:
        if r.http_client_request:
            requests.append(r.http_client_request)
        if r.http_server_response:
            responses.append(r.http_server_response)
    return requests, responses


def convert_http_session(session):
    if session.http_request_response:
        requests, responses = split_into_requests_and_responses(session.http_request_response)
        if len(responses) != 0:
            warn("HTTPServerResponse type is not supported in STIX 2.0", 429)
        if len(requests) >= 1:
            cybox_traffic = {"type": "network-traffic"}
            cybox_traffic["extensions"] = {"http-request-ext": convert_http_client_request(requests[0])}
            if len(requests) > 1:
                warn("Only HTTP_Request_Response used for http-request-ext, using first value", 512)
            return cybox_traffic


def create_icmp_extension(icmp_header):
    imcp_extension = {}
    if icmp_header.type_:
        imcp_extension["icmp_type_hex"] = icmp_header.type_.value
    if icmp_header.code:
        imcp_extension["icmp_code_hex"] = icmp_header.code.value
    if icmp_header.checksum:
        warn("ICMP_Packet/Checksum content not supported in STIX 2.0", 424)
    return imcp_extension


def convert_network_packet(packet):
    if packet.internet_layer:
        internet_layer = packet.internet_layer
        if internet_layer.ipv4 or internet_layer.ipv6:
            warn("Internet_Layer/IP_Packet content not supported in STIX 2.0", 424)
        else:
            if internet_layer.icmpv4:
                icmp_header = internet_layer.icmpv4.icmpv4_header
            elif internet_layer.icmpv6:
                icmp_header = internet_layer.icmpv6.icmpv6_header
            else:
                return None
            cybox_traffic = {"type": "network-traffic"}
            cybox_traffic["extensions"] = {"icmp-ext": create_icmp_extension(icmp_header)}
            return cybox_traffic


def convert_socket_options(options):
    socket_options = {}
    for prop_name in SOCKET_OPTIONS:
        if getattr(options, prop_name):
            socket_options[prop_name.upper()] = getattr(options, prop_name)
    return socket_options


def convert_network_socket(socket):
    cybox_traffic = {"type": "network-traffic"}
    socket_extension = {}
    if socket.is_blocking:
        socket_extension["is_blocking"] = socket.is_blocking
    if socket.is_listening:
        socket_extension["is_listening"] = socket.is_listening
    if socket.address_family:
        if socket.address_family in ADDRESS_FAMILY_ENUMERATION:
            socket_extension["address_family"] = socket.address_family.value
        else:
            warn("%s is not a member of the %s enumeration", 627, socket.address_family, "address family")
    if socket.type_:
        socket_extension["socket_type"] = socket.type_
    if socket.domain and get_option_value("spec_version") == "2.0":
        socket_extension["protocol_family"] = socket.domain
    if socket.options:
        socket_extension["options"] = convert_socket_options(socket.options)
    if socket.socket_descriptor:
        socket_extension["socket_descriptor"] = socket.socket_descriptor
    if socket.local_address:
        warn("Network_Socket.local_address content not supported in STIX 2.0", 424)
    if socket.remote_address:
        warn("Network_Socket.remote_address content not supported in STIX 2.0", 424)
    if socket.protocol:
        cybox_traffic["protocols"] = [socket.protocol.value]
    cybox_traffic["extensions"] = {"socket-ext": socket_extension}
    return cybox_traffic


def convert_cybox_object(obj1x):
    # TODO:  should related objects be handled on a case-by-case basis or just ignored
    prop = obj1x.properties
    objs = {}
    if prop is None:
        return None
    elif isinstance(prop, Address):
        objs["0"] = convert_address(prop)
    elif isinstance(prop, URI):
        objs["0"] = convert_uri(prop)
    elif isinstance(prop, EmailMessage):
        # potentially returns multiple objects
        objs = convert_email_message(prop)
    elif isinstance(prop, File):
        # potentially returns multiple objects
        objs = convert_file(prop)
    elif isinstance(prop, WinRegistryKey):
        objs["0"] = convert_registry_key(prop)
    elif isinstance(prop, Process):
        objs = convert_process(prop)
    elif isinstance(prop, DomainName):
        objs["0"] = convert_domain_name(prop)
    elif isinstance(prop, Mutex):
        objs["0"] = convert_mutex(prop)
    elif isinstance(prop, NetworkConnection):
        # potentially returns multiple objects
        objs = convert_network_connection(prop)
    elif isinstance(prop, Account):
        objs["0"] = convert_account(prop)
    elif isinstance(prop, HTTPSession):
        objs["0"] = convert_http_session(prop)
    elif isinstance(prop, NetworkPacket):
        objs["0"] = convert_network_packet(prop)
    elif isinstance(prop, NetworkSocket):
        objs["0"] = convert_network_socket(prop)
    else:
        warn("CybOX object %s not handled yet", 805, text_type(type(prop)))
        return None
    if not objs:
        warn("%s did not yield any STIX 2.0 object", 417, text_type(type(prop)))
        return None
    else:
        primary_obj = objs["0"]
        if prop.custom_properties:
            for cp in prop.custom_properties.property_:
                primary_obj["x_" + cp.name] = cp.value
        if obj1x.id_:
            add_object_id_value(obj1x.id_, objs)
        return objs


def find_index_of_type(objs, type):
    for k, v in objs.items():
        if v["type"] == type:
            return k
    return None


def add_objects(objects, objs_to_add):
    objects.update(objs_to_add)


def renumber_co(co, number_mapping):
    for k, v in co.items():
        if k.endswith("ref"):
            if co[k] in number_mapping:
                co[k] = number_mapping[co[k]]
        elif k.endswith("refs"):
            new_refs = []
            for ref in co[k]:
                if ref in number_mapping:
                    new_refs.append(number_mapping[ref])
            co[k] = new_refs
    return co


def renumber_objs(objs, number_mapping):

    new_objects = {}
    for k, v in objs.items():
        new_objects[number_mapping[k]] = renumber_co(v, number_mapping)
    return new_objects


def do_renumbering(objs, next_id, root_obj_index, objs_to_add):
    number_mapping = {}
    for k in sorted(objs.keys()):
        number_mapping[text_type(k)] = text_type(next_id)
        next_id += 1
    new_objs = renumber_objs(objs, number_mapping)
    objs_to_add.update(new_objs)
    return next_id, number_mapping


def find_index_of_contents(root_data, objects):
    for index, value in objects.items():
        if value == root_data:
            return index
    return None


def fix_cybox_relationships(observed_data):
    for o in observed_data:
        objs_to_add = {}
        if not o["objects"]:
            continue
        next_id = int(max(o["objects"].keys())) + 1
        for co in o["objects"].values():
            if co["type"] == "email-message":
                if co["is_multipart"]:
                    for mp in co["body_multipart"]:
                        objs = get_object_id_value(mp["body_raw_ref"])
                        if objs:
                            root_obj_index = find_index_of_type(objs, "file")
                            if root_obj_index is not None:  # 0 is a good value
                                mp["content_type"] = "text/plain"
                                info("content_type for body_multipart of %s is assumed to be 'text/plain'", 722,
                                     o["id"])
                                root_data = objs[root_obj_index]
                                if root_data:
                                    present_obj_index = find_index_of_contents(root_data, o["objects"])
                                    if present_obj_index is None:  # 0 is a good value
                                        next_id, number_mapping = do_renumbering(objs,
                                                                                 next_id,
                                                                                 root_obj_index,
                                                                                 objs_to_add)
                                        mp["body_raw_ref"] = text_type(number_mapping[root_obj_index])
                                    else:
                                        mp["body_raw_ref"] = text_type(present_obj_index)
                        # TODO: warnings
        if objs_to_add:
            add_objects(o["objects"], objs_to_add)
