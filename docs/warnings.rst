Warning Messages
=====================

General
---------------

======================================================================= ====    =====
Message                                                                 Code    Level
======================================================================= ====    =====
Results produced by the stix2-elevator are not for production purposes. 201     warn
Observable Expressions should not contain placeholders                  202     error
Placeholder *[id]* should be resolved                                   203     error
Found definition for *[id]*                                             204     info
At least one PLACEHOLDER idref was not resolved in *[id]*               205     warn
At least one observable could not be converted in *[id]*                206     warn
Options not initialized                                                 207     error
EMPTY BUNDLE -- No objects created from 1.x input document!             208     warn
Both console and output log have disabled messages.                     209     warn
OSError *[message]*                                                     210     error
silent option is not compatible with a policy                           211     warn
======================================================================= ====    =====


Adding Content not supported in STIX 2.0 to Description
----------------------------------------------------------------

========================================================================================================================== ====    =====
Message                                                                                                                    Code    Level
========================================================================================================================== ====    =====
The Short_Description property is no longer supported in STIX. The text was appended to the description property of *[id]* 301     warn
Appended *[property_name]* to description of *[id]*                                                                        302     warn
Title *[title]* used for name, appending exploit_target *[id]* title in description property                               303     info
Appended confidence property content to description of *[id]*                                                              304     warn
Appended Statement type content to description of *[id]*                                                                   305     warn
Appended Tool type content to description of *[id]*                                                                        306     warn
========================================================================================================================== ====    =====


Dropping Content not supported in STIX 2.0
---------------------------------------------------

============================================================================================================================================== ====    =====
Message                                                                                                                                        Code    Level
============================================================================================================================================== ====    =====
Information Source on *[id]* is not representable in STIX 2.0                                                                                  401     warn
Related_Packages type in *[id]* not supported in STIX 2.0                                                                                      402     warn
Campaign/Activity type in *[id]* not supported in STIX 2.0                                                                                     403     warn
Structured COAs type in *[id]* are not supported in STIX 2.0                                                                                   404     warn
ExploitTarget/Weaknesses type in *[id]* not supported in STIX 2.0                                                                              405     warn
ExploitTarget/Configurations type in *[id]* not supported in STIX 2.0                                                                          406     warn
Indicator *[id]* has an observable or indicator composite expression which may not supported correctly in STIX 2.0 - please check this pattern 407     warn
TTP/Behavior/Exploits/Exploit in *[id]* not supported in STIX 2.0                                                                              408     warn
Infrastructure in *[id]* not part of STIX 2.0                                                                                                  409     warn
Targeted systems on *[id]* are not a victim target in STIX 2.0                                                                                 410     warn
Targeted information on *[id]* is not a victim target in STIX 2.0                                                                              411     warn
Targeted technical details on *[id]* are not a victim target in STIX 2.0                                                                       412     warn
Kill Chains type in *[id]* not supported in STIX 2.0                                                                                           413     warn
Victim Target in *[id]* did not yield any STIX 2.0 object                                                                                      414     warn
TTP *[id]* did not generate any STIX 2.0 object                                                                                                415     warn
No STIX 2.0 object generated from embedded object *[id]*                                                                                       416     warn
[object type] did not yield any STIX 2.0 object                                                                                                417     warn
The exports property of WinExecutableFileObj is not part of STIX 2.0                                                                           418     warn
The imports property of WinExecutableFileObj is not part of STIX 2.0                                                                           419     warn
Windows Handles are not a part of STIX 2.0                                                                                                     420     warn
The address type [address] is not part of STIX 2.0                                                                                             421     warn
No pattern term was created from *[id]*                                                                                                        422     warn
*[id]* is used as a pattern, therefore it is not included as an onbserved_data instance                                                        423     warn
[xxx] content is not supported in STIX 2.0                                                                                                     424     warn
Could not resolve Marking Structure *[id]*                                                                                                     425     warn
MAEC content in *[id]* cannot be represented in STIX 2.0                                                                                       426     warn
The [relationship name] relationship involving *[id]* is not supported in STIX 2.0                                                             427     warn
============================================================================================================================================== ====    =====

Multiple values are not supported in STIX 2.0
----------------------------------------------------

=========================================================================================================================================== ====    =====
Message                                                                                                                                     Code    Level
=========================================================================================================================================== ====    =====
``NO MESSAGE ASSIGNED``                                                                                                                     501
Only one person name allowed for *[id]* in STIX 2.0, used first one                                                                         502     warn
Only one organization name allowed for *[id]* in STIX 2.0, used first one                                                                   503     warn
YARA/SNORT patterns on *[id]* not supported in STIX 2.0                                                                                     504     warn
``NO MESSAGE ASSIGNED``                                                                                                                     505
Only one alternative test mechanism allowed for *[id]* in STIX 2.0 - used first one, which was *[pattern_lang]*                             506     warn
Only one valid time window allowed for *[id]* in STIX 2.0 - used first one                                                                  507     warn
Only one name for malware is allowed for *[id]* in STIX 2.0 - used first one                                                                508     warn
No STIX 1.x vocab value given for *[property]*, using 'unknown'                                                                             509     warn
Only one *[property]* allowed in STIX 2.0 - used first one                                                                                  510     warn
File size window not allowed in top level observable, using first value                                                                     511     error
Only one Layer7_Connections/HTTP_Request_Response used fot http-request-ext, using first value                                              512     warn
=========================================================================================================================================== ====    =====

Possible issue in original STIX 1.x content
--------------------------------------------------

=========================================================================================================================================== ====    =====
Message                                                                                                                                     Code    Level
=========================================================================================================================================== ====    =====
Dangling source reference *[source]* in *[id]*                                                                                              601     warn
Dangling target reference *[target]* in *[id]*                                                                                              602     warn
1.X ID: *[id]* was not mapped to STIX 2.0 ID                                                                                                603     warn
Unable to determine the STIX 2.0 type for *[id]*                                                                                            604     error
Malformed id *[id]*. Generated a new uuid                                                                                                   605     warn
Identity *[id]* has organization and person names                                                                                           606     error
Dangling kill chain phase id in indicator *[id]*                                                                                            607     error
windows-registry-key is required to have a key property                                                                                     608     error
*[condition]* was used, but two values were not provided.                                                                                   609     error
Trying to associate *[old_key]* with None                                                                                                   610     warn
Could not associate *[old_id]* with None                                                                                                    611     error
Identity *[id]* must have a name, using 'None'                                                                                              612     error
No WinExecutableFile properties found in *[WinExeFile]*                                                                                     613     warn
No ArchiveFile properties found in *[ArchiveFile]*                                                                                          614     warn
No WinProcess properties found in *[WinProcess]*                                                                                            615     warn
No WinService properties found in *[WinService]*                                                                                            616     warn
The custom property name *[property name]* does not adhere to the specification rules                                                       617     warn
No ISO code for *[value]* in *[identifying info]*                                                                                           618     warn
No start time for the first valid time interval is available in *[id]*, other time intervals might be more appropriate                      619     warn
Unable to create a pattern from a File object                                                                                               620     warn
*[stix 1.x property]* contains no value                                                                                                     621     warn
No term was yielded for *[id]*                                                                                                              622     warn
Hive property, *[hive property name]*, is already a prefix of the key property, *[key property name]*                                       623     warn
The custom property name *[id]* contains whitespace, replacing it with underscores                                                          624     warn
Found duplicate marking structure *[id]*                                                                                                    625     info
*[hash_string]* is not a valid *[hash_type]* hash                                                                                           626     warn
=========================================================================================================================================== ====    =====

STIX Elevator conversion based on assumptions
----------------------------------------------------

=========================================================================================================================================== ====    =====
Message                                                                                                                                     Code    Level
=========================================================================================================================================== ====    =====
Threat Actor identity *[id]* being used as basis of attributed-to relationship                                                              701     info
Found STIX 1.X ID: *[old_id]* replaced by *[new_id]*                                                                                        702     info
*[old_id]* is already associated other ids: *[tuple_of_new_ids]*                                                                            703     info
Including rel["id"] in rep["id"] and added the target_ref rel["target_ref"] to the report                                                   704     warn
Including rel["id"] in rep["id"] and added the source_ref rel["source_ref"] to the report                                                   705     warn
Including rel["id"] in rep["id"] although the target_ref is unknown                                                                         706     warn
Including rel["id"] in rep["id"] although the source_ref is unknown                                                                         707     warn
Not including rel["id"] in rep["id"] because there is no corresponding SDO for rel["target_ref"]                                            708     warn
Not including rel["id"] in rep["id"] because there is no corresponding SDO for rel["source_ref"]                                            709     warn
All associated *[xxx]* relationships of *[id]* are assumed to not represent STIX 1.2 versioning                                             710     warn
ciq name found in *[id]*, possibly overriding other name                                                                                    711     warn
Only one type pattern can be specified in *[id]* - using cybox                                                                              712     warn
*[id]* generated an identity associated with a victim                                                                                       713     warn
No condition given for *[current_observable]* - assume '='                                                                                  714     warn
Used MATCHES operator for *[condition]*                                                                                                     715     warn
Based on CIQ information, *[id]* is assumed to be an organization                                                                           716     warn
Threat actor *[id]* title is used for name property                                                                                         717     info
Using related-to for the *[property]* of *[id]*                                                                                             718     warn
Using first Threat Actor motivation as primary_motivation. If more, as secondary_motivation                                                 719     info
=========================================================================================================================================== ====    =====

STIX elevator currently doesn't process this content
-----------------------------------------------------------

=========================================================================================================================================== ==== =====
Message                                                                                                                                     Code Level
=========================================================================================================================================== ==== =====
Could not resolve Marking Structure *[id]*                                                                                                  801  warn
1.x full file paths are not processed, yet                                                                                                  802  warn
process:startup_info not handled yet                                                                                                        803  warn
WinServiceObject.service_dll is not handled, yet.                                                                                           804  warn
CybOX object *[object]* not handled yet                                                                                                     805  warn
Email *[property]* not handled yet                                                                                                          806  warn
`file:extended_properties:windows_pebinary_ext:optional_header` is not implemented yet                                                      807  warn
*[object]* found in *[id]* cannot be converted to a pattern, yet.                                                                           808  warn
Related Objects of cyber observables for *[id]* are not handled yet                                                                         809  warn
Negation of *[id]* is not handled yet                                                                                                       810  warn
Network Connection not implemented, yet.                                                                                                    811  error
Condition on a hive property not handled.                                                                                                   812  warn
Cannot convert CybOX 2.x class name *[name]* to an object_path_root_ne                                                                      813  error
Parameter Observables in *[id]* are not handled, yet.                                                                                       814  warn
*[property]* in *[id]* are not handled, yet.                                                                                                815  info
Ambiguous file path *[path]* was not processed                                                                                              816  warn
=========================================================================================================================================== ==== =====


Missing Required Timestamp
---------------------------------

=========================================================================================================================================== ====    =====
Message                                                                                                                                     Code    Level
=========================================================================================================================================== ====    =====
'first_observed' and 'last_observed' data not available directly on *[id]* - using timestamp                                                901     info
Using parent object timestamp on *[identifying info]*                                                                                       902     info
No valid time position information available in *[id]*, using parent timestamp                                                              903     warn
No 'first_seen' data on *[id]* - using timestamp                                                                                            904     info
Timestamp not available for *[entity]*, using current time                                                                                  905     warn
=========================================================================================================================================== ====    =====
