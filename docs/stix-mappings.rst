​Mappings from STIX 1.x to STIX 2.x
=======================================

This section outlines the disposition of each property of the top-level objects when converted.

For each STIX 1.x object that was converted the following options are possible:

 - **STIX 1.x property mapped directly to a STIX 2.x property.**  This property's value is used unaltered in the conversion to 2.x.
 - **STIX 1.x property translated into STIX 2.x property.**  This property's value must undergo some minor processing to determine the
   corresponding content for 2.x.
 - **STIX 1.x property mapped using STIX 2.x relationships.** This property is used to construct a 2.x relationship object.  The "reverse"
   notation indicates the the STIX 1.x property is found on target object.
 - **STIX 1.x property handled based on the "missing policy" option.**  This property has no corresponding property in STIX 2.x, but its value
   can be (optionally) included using the extension mechanism, custom properties or in the description property of the 2.x object as text,
   depending upon the **--missing-policy** option.
 - **STIX 1.x property not mapped.**  This property will not be included in the converted 2.x object.

All examples were generated using the missing policy of **add-to-description**.

Top Level Object Mappings
-------------------------------

This table describes the mapping between STIX 1.x and STIX 2.x top-level objects.  Notice that certain object types in STIX 1.x
that were not top-level objects are in STIX 2.x (e.g., Malware).  In STIX 2.1, cyber observable objects are also top-level
objects - but their mapping can be found in the :ref:`cyber_observables` section

+-----------------------------+----------------------------+
| **STIX 1.x object**         | **STIX 2.x object**        |
+=============================+============================+
| ``Campaign``                | ``campaign``               |
+-----------------------------+----------------------------+
| ``Course_Of_Action``        | ``course-of-action``       |
+-----------------------------+----------------------------+
| ``et:Vulnerability``        | ``vulnerability``          |
+-----------------------------+----------------------------+
| ``et:Weakness``             | *not converted*            |
+-----------------------------+----------------------------+
| ``et:Configuration``        | *not converted*            |
+-----------------------------+----------------------------+
| ``Incident``                | ``incident`` *in 2.1*      |
+-----------------------------+----------------------------+
| ``Indicator``               | ``indicator``              |
+-----------------------------+----------------------------+
| ``Information_Source/``     | ``location`` *in 2.1*      |
| ``CIQIdentity3_0Instance/`` |                            |
| ``Address``                 |                            |
+-----------------------------+----------------------------+
| ``Report``                  | ``report``                 |
+-----------------------------+----------------------------+
| ``Observable``              | ``observed-data``          |
+-----------------------------+----------------------------+
| ``Package``                 | ``bundle``                 |
+-----------------------------+----------------------------+
| ``Threat Actor``            | ``threat-actor``           |
+-----------------------------+----------------------------+
| ``ttp:Attack_Pattern``      | ``attack-pattern``         |
+-----------------------------+----------------------------+
| ``ttp:Infrastructure``      | ``infrastructure``         |
+-----------------------------+----------------------------+
| ``ttp:Malware``             | ``malware``                |
+-----------------------------+----------------------------+
| ``ttp:Persona``             | *not converted*            |
+-----------------------------+----------------------------+
| ``ttp:Tool``                | ``tool``                   |
+-----------------------------+----------------------------+
| ``ttp:Victim_Targeting``    | ``identity``               |
+-----------------------------+----------------------------+

Common Properties
------------------------

**STIX 1.x Properties Mapped Directly to STIX 2.x Properties**

..  table::
    :align: left

    +-------------------------+-------------------------+
    | **STIX 1.x property**   | **STIX 2.x property**   |
    +=========================+=========================+
    | ``Description``         | ``description``         |
    +-------------------------+-------------------------+
    | ``timestamp``           |   ``modified``          |
    +-------------------------+-------------------------+
    | ``Title``               |   ``name``              |
    +-------------------------+-------------------------+

In STIX 1.x only one timestamp is recorded, whereas in STIX 2.x, there are two properties:  ``created`` and ``modified``.  The ``created`` timestamp
is not stored in objects in STIX 1.x.  The ``timestamp`` property in STIX 1.x holds the ``modified`` timestamp.

**STIX 1.x Properties Translated to STIX 2.x Properties**

..  table::
    :align: left

    +-------------------------+--------------------------------------------------+
    | **STIX 1.x property**   | **STIX 2.x property**                            |
    +=========================+==================================================+
    | ``id``                  | ``id``                                           |
    +-------------------------+--------------------------------------------------+
    | ``Handling``            |   ``object_markings_refs, granular_markings``    |
    +-------------------------+--------------------------------------------------+
    | ``Information_Source``  |   ``created_by_ref``, ``external_references``    |
    +-------------------------+--------------------------------------------------+
    | ``Confidence``          |   ``confidence``                                 |
    +-------------------------+--------------------------------------------------+

In STIX 1.x, an ``id`` contained a "namespace".  This was deemed unnecessary in STIX 2.x, therefore they contain no origin information.

-  Handling

    Data Markings, called Handling in STIX 1.x, have been completely
    redesigned for STIX 2.x. STIX 1.x used *xpath*, which was a reasonable
    choice given its reliance on XML for implementation. However, the
    use of xpath was very difficult to implement, and was more
    expressive than was deemed necessary.

    STIX 2.x introduces two new concepts, object markings and granular
    markings, which simplify the marking of data. Object markings apply
    to a whole object, whereas granular markings are specific to
    particular properties of an object. The selection of which
    properties are to be marked is expressed in a serialization-neutral
    way. The scope of marking definitions is at the object level. There
    is no marking that can apply to a whole bundle, or report.


-  Information_Source

    In STIX 1.x there were several related concepts that were used to
    identify the sources of information and various parties of interest.
    Parties of interest are creators of content, victim targets, and
    other responsible parties. Sources of information could be an
    individual, organization or some software application. Additionally,
    it was possible to make references to source material external to STIX,
    e.g., a citation, URL, or an ID in an external system or repository.

    In STIX 2.x, we have retained the concept of an ``IdentityType`` object,
    but do not rely on the OASIS CIQ standard model as STIX 1.x did.
    The ``Identity`` object type in STIX 2.x contains a
    very streamlined set of properties: ``identity_class`` to specify
    if it is an individual or organization, ``sectors`` to indicate the
    industry sector that the identity belongs to, and a free text
    property, ``contact_information`` to specify such information. Other OASIS CIQ standard model
    propeties are not mapped in the conversion.

    The ``InformationSourceType`` object was used in STIX 1.x to associate
    an object with its creator's identity. In STIX 2.x, the common
    property ``created_by_ref`` is used, and it must contain the
    identifier of an ``Identity`` object.

    The ``InformationSourceType`` object was also used in STIX 1.x to
    specify external information. Other properties like ``capec_id`` of
    ``AttackPatternType``, or ``cve_id`` of ``VulnerabilityType`` were also used
    for external information, holding the ids of items in repositories
    or systems external to STIX. In STIX 2.x, the data type
    ``external-reference`` is used for all external information.

    The ``InformationSourceType`` object was also used in STIX 1.x to
    specify location information.  The ``location`` object will be used when converting to
    STIX 2.1.


-  Type

    In STIX 2.x, the type of an object is defined to be a specific literal, and is recorded in the ``type`` property.
    The type of an object in STIX 1.x was either implicitly defined by its element name or explicitly using xsi:type.

- Kill Chains

    In STIX 1.x, kill chains, with their phases, were defined using the ``KillChainType``, which is found in the ``Kill_Chains`` property of
    a ``TTP``.  These kill chains phases were refered to in the ``TTP`` and ``Indicator`` ``Kill_Chain_Phases`` properties.  In
    STIX 2.x, kill chains and their phases are not explicitly defined, but are referenced using their common names.
    If the Lockheed Martin Cyber Kill Chain™ is used the ``kill_chain_name`` property must be ``lockheed-martin-cyber-kill-chain``,
    according to the specification.


**STIX 1.x Properties Mapped Using STIX 2.x Relationships**

*none*

**STIX 1.x Properties Handled Based by the "missing policy"**

-  ``Short_Description``

-  ``Confidence`` *in STIX 2.0*

    The confidence concept is available only STIX 2.1.

**STIX 1.x Properties Not Mapped**

-  ``idref``

    Relationships in STIX 2.x make use of id references to indicate the
    source and target of the relationship. STIX 2.x objects additionally
    use ``id`` references for any property whose suffix is ``ref`` or ``refs``.
    The facility available in STIX 1.x to specify related objects by
    embedding them in other objects is not available in STIX 2.x.

-  ``Related_Packages``

    STIX 1.x packages correspond to STIX 2.x bundles. However, bundles
    cannot refer to other bundles, so there is no way to express this
    property in STIX 2.x.

-  ``Version``

    Individual STIX objects do not have their own STIX version in STIX
    2.0. A bundle has the property ``spec_version``, which applies to all
    objects that are contained in the bundle.  In STIX 2.1, objects do have
    the property ``spec_version``.  In all cases, the version information
    is not transfered from the STIX 1.x object, but depends upon the --version
    option when invoking the elevator.

Versioning
~~~~~~~~~~~~~~~~~~~

STIX 1.x supported the versioning of objects, but it was a feature that was rarely used.  STIX 2.x support of
versioning is based on two common properties: ``modified`` and ``revoked``.  However, the elevator does not support
converting STIX 1.x versioned objects, in the unlikely inclusion of such objects.

All converted objects will be assumed to be the one and only version of an object. If more than one object is found with
the same id, it will *not* be flagged as an error.

Relationships
--------------

All STIX 1.x relationships were defined explicitly in the specification and they are all embedded as properties of the object.
In STIX 2.x, relationships are top-level objects so they exist independently from their source and target objects.
Additionally, although the STIX 2.x specification suggests certain relationships between object types,
a relationship between any two objects is allowed.

Relationships in STIX 1.x could be specified either using the ``idref`` property,
or by embedding the object within the relationship itself.  In the former case,
the STIX 2.x object should use the original object's ``id`` as the ``source_ref`` property,
and the ``idref`` as the ``target_ref`` property.
In the latter case, the embedded object must first be converted to a top-level STIX 2.x object.
Of course, the embedded object's ``id`` might not present.  In that case, an new id must be created.

**An Example**

STIX 1.x in XML

.. code-block:: xml

        <stix:Campaign id="example:Campaign-e5268b6e-4931-42f1-b379-87f48eb41b1e"
                       timestamp="2014-08-08T15:50:10.983728+00:00"
                       xsi:type='campaign:CampaignType' version="1.2">
            <campaign:Attribution>
                <campaign:Attributed_Threat_Actor>
                    <stixCommon:Threat_Actor idref="example:threatactor-56f3f0db-b5d5-431c-ae56-c18f02caf500"/>
                </campaign:Attributed_Threat_Actor>
            </campaign:Attribution>
        </stix:Campaign>


STIX 2.x in JSON

.. code-block:: json

    {
            "created": "2014-08-08T15:50:10.983Z",
            "id": "relationship--3dcf59c3-30e3-4aa5-9c05-2cbffcee5922",
            "modified": "2014-08-08T15:50:10.983Z",
            "relationship_type": "attributed-to",
            "source_ref": "campaign--e5268b6e-4931-42f1-b379-87f48eb41b1e",
            "target_ref": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500",
            "type": "relationship"
    }

    {
            "id": "campaign--e5268b6e-4931-42f1-b379-87f48eb41b1e"

    }

    {
            "id": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500"

    }

.. _attack_pattern:

Attack Pattern
------------------


**STIX 1.x Properties Mapped Directly to STIX 2.x Properties**

*none*

**STIX 1.x Properties Translated to STIX 2.x Properties**

..  table::
    :align: left

    ============================  ==============================
    **STIX 1.x property**         **STIX 2.x property**
    ============================  ==============================
    ``capec_id``                  ``external_references``
    ``ttp:Kill_Chain_Phases``     ``kill_chain_phases``
    ============================  ==============================


**STIX 1.x Properties Mapped Using STIX 2.x Relationships**


..  table::
    :align: left

    +---------------------------+------------------------------------------------------------------------+
    | **STIX 1.x property**     | **STIX 2.x relationship type**                                         |
    +===========================+========================================================================+
    | ``ttp:Victim_Targeting``  | ``targets``                                                            |
    +---------------------------+------------------------------------------------------------------------+
    | ``ttp:Exploit_Targets``   | ``targets`` (vulnerability, only)                                      |
    +---------------------------+------------------------------------------------------------------------+
    | ``ttp:Related_TTPs``      | ``uses`` (malware, tool), ``related-to`` (when not used for versioning)|
    +---------------------------+------------------------------------------------------------------------+

**STIX 1.x Properties Handled Based on the "missing policy"**

- ``ttp:Intended_Effect``

**STIX 1.x Properties Not Mapped**

- ``ttp:Kill_Chains``

**An Example**

STIX 1.x in XML

.. code-block:: xml

    <stix:TTP id="example:ttp-8ac90ff3-ecf8-4835-95b8-6aea6a623df5" xsi:type='ttp:TTPType'>
       <ttp:Title>Phishing</ttp:Title>
       <ttp:Behavior>
           <ttp:Attack_Patterns>
               <ttp:Attack_Pattern capec_id="CAPEC-98">
                   <ttp:Description>Phishing</ttp:Description>
               </ttp:Attack_Pattern>
           </ttp:Attack_Patterns>
       </ttp:Behavior>
       <ttp:Information_Source>
           <stixCommon:Identity idref="example:identity-f690c992-8e7d-4b9a-9303-3312616c0220"/>
       </ttp:Information_Source>
    </stix:TTP>

STIX 2.x in JSON

.. code-block:: json

    {
       "created": "2017-01-27T13:49:54.326Z",
       "created_by_ref": "identity--f690c992-8e7d-4b9a-9303-3312616c0220"
       "description": "Phishing",
       "external_references": [
           {
               "external_id": "CAPEC-98",
               "source_name": "capec"
           }
       ],
       "id": "attack-pattern--8ac90ff3-ecf8-4835-95b8-6aea6a623df5",
       "modified": "2017-01-27T13:49:54.326Z",
       "name": "Phishing",
       "type": "attack-pattern"
    }

Campaigns
----------------

**STIX 1.x Properties Mapped Directly to STIX 2.x Properties**

..  table::
    :align: left

    +-------------------------+------------------------+
    | **STIX 1.x property**   | **STIX 2.x property**  |
    +=========================+========================+
    | ``Names``               |   ``aliases``          |
    +-------------------------+------------------------+

**STIX 1.x Properties Translated to STIX 2.x Properties**

..  table::
    :align: left

    +-------------------------+------------------------+
    | **STIX 1.x property**   | **STIX 2.x property**  |
    +=========================+========================+
    | ``Intended_Effect``     |   ``objective``        |
    +-------------------------+------------------------+

**​STIX 1.x Properties Mapped Using STIX 2.x Relationships**

..  table::
    :align: left

    +-------------------------+----------------------------------------------+
    | **STIX 1.x property**   | **STIX 2.x relationship type**               |
    +=========================+==============================================+
    | ``Related_TTPs``        | ``uses``                                     |
    +-------------------------+----------------------------------------------+
    | ``Related_Campaign``    | ``indicates`` (reverse)                      |
    +-------------------------+----------------------------------------------+
    | ``Attribution``         | ``attributed-to``                            |
    +-------------------------+----------------------------------------------+
    | ``Associated_Campaigns``| ``related-to`` (when not used for versioning)|
    +-------------------------+----------------------------------------------+

**STIX 1.x Properties Handled Based on the "missing policy"**

-  ``Status``

**STIX 1.x Properties Not Mapped**

-  ``Activity``

-  ``Related_Incidents``

**An Example**

STIX 1.x in XML

.. code-block:: xml

    <stix:Campaign id="example:Campaign-e5268b6e-4931-42f1-b379-87f48eb41b1e"
                   timestamp="2014-08-08T15:50:10.983"
                   xsi:type='campaign:CampaignType' version="1.2">
        <campaign:Title>Operation Bran Flakes</campaign:Title>
        <campaign:Description>A concerted effort to insert false information into the BPP's web pages</campaign:Description>
        <campaign:Names>
            <campaign:Name>OBF</campaign:Name>
        </campaign:Names>
        <campaign:Intended_Effect>Hack www.bpp.bn</campaign:Intended_Effect>
        <campaign:Related_TTPs>
            <campaign:Related_TTP>
                <stixCommon:TTP id="example:ttp-2d1c6ab3-5e4e-48ac-a32b-f0c01c2836a8"
                                timestamp="2014-08-08T15:50:10.983464+00:00"
                                xsi:type='ttp:TTPType' version="1.2">
                     <ttp:Victim_Targeting>
                         <ttp:identity id="example:identity-ddfe7140-2ba4-48e4-b19a-df069432103b">
                            <stixCommon:name>Branistan Peoples Party</stixCommon:name>
                        </ttp:identity>
                     </ttp:Victim_Targeting>
                 </stixCommon:TTP>
             </campaign:Related_TTP>
        </campaign:Related_TTPs>
        <campaign:Attribution>
             <campaign:Attributed_Threat_Actor>
                 <stixCommon:Threat_Actor idref="example:threatactor-56f3f0db-b5d5-431c-ae56-c18f02caf500"/>
             </campaign:Attributed_Threat_Actor>
        </campaign:Attribution>
        <campaign:Information_Source>
            <stixCommon:Identity id="example:identity-f690c992-8e7d-4b9a-9303-3312616c0220">
            <stixCommon:name>The MITRE Corporation - DHS Support Team</stixCommon:name>
            <stixCommon:Role xsi:type="stixVocabs:InformationSourceRoleVocab-1.0">Initial Author</stixCommon:Role>
       </campaign:Information_Source>
    </stix:Campaign>

STIX 2.x in JSON

.. code-block:: json


    {
        "type": "identity",
        "id": "identity--f690c992-8e7d-4b9a-9303-3312616c0220",
        "created": "2016-08-08T15:50:10.983Z",
        "modified": "2016-08-08T15:50:10.983Z",
        "name": "The MITRE Corporation - DHS Support Team",
        "identity_class": "organization"
    }

    {
        "type": "identity",
        "id": "identity--ddfe7140-2ba4-48e4-b19a-df069432103b",
        "created_by_ref": "identity--f690c992-8e7d-4b9a-9303-3312616c0220",
        "created": "2016-08-08T15:50:10.983Z",
        "modified": "2016-08-08T15:50:10.983Z",
        "name": "Branistan Peoples Party",
        "identity_class": "organization"
    }

    {
        "type": "campaign",
        "id": "campaign--e5268b6e-4931-42f1-b379-87f48eb41b1e",
        "created_by_ref": "identity--f690c992-8e7d-4b9a-9303-3312616c0220",
        "created": "2016-08-08T15:50:10.983Z",
        "modified": "2016-08-08T15:50:10.983Z",
        "name": "Operation Bran Flakes",
        "description": "A concerted effort to insert false information into the BPP's web pages",
        "aliases": ["OBF"],
        "first_seen": "2016-01-08T12:50:40.123Z",
        "objective": "Hack www.bpp.bn"
    }

See `Threat Actor`_ for the Threat Actor object.

Course of Action
----------------------

In STIX 2.x the ``course-of-action`` object is defined as a stub. This means that in STIX
2.x this object type is pretty "bare-bones", not containing most of the
properties that were found in STIX 1.x. The property ``action`` is
reserved, but not defined in STIX 2.x.

**STIX 1.x Properties Mapped Directly to STIX 2.x Properties**

..  table::
    :align: left

    +-------------------------+-----------------------+
    | **STIX 1.x property**   | **STIX 2.x property** |
    +=========================+=======================+
    | ``Type``                |   ``labels``          |
    +-------------------------+-----------------------+

**STIX 1.x Properties Translated to STIX 2.x Properties**

*none*

**STIX 1.x Properties Mapped Using STIX 2.x Relationships**

..  table::
    :align: left

    +------------------------------+----------------------------------------------+
    | **STIX 1.x property**        | **STIX 2.x relationship type**               |
    +==============================+==============================================+
    |     ``Related_COAs``         | ``related-to`` (when not used for versioning)|
    +------------------------------+----------------------------------------------+

**STIX 1.x Properties Handled Based on the "missing policy"**

 - ``Stage``
 - ``Objective``
 - ``Impact``
 - ``Cost``
 - ``Efficacy``

**STIX 1.x Properties Not Mapped**

 - ``Parameter_Observables``
 - ``Structured_COA``

**An Example**

STIX 1.x in XML

.. code-block:: xml

        <stix:Course_Of_Action id="example:coa-495c9b28-b5d8-11e3-b7bb-000c29789db9" xsi:type='coa:CourseOfActionType' version="1.2">
            <coa:Title>Block traffic to PIVY C2 Server (10.10.10.10)</coa:Title>
            <coa:Stage xsi:type="stixVocabs:COAStageVocab-1.0">Response</coa:Stage>
            <coa:Type xsi:type="stixVocabs:CourseOfActionTypeVocab-1.0">Perimeter Blocking</coa:Type>
            <coa:Objective>
                <coa:Description>Block communication between the PIVY agents and the C2 Server</coa:Description>
                <coa:Applicability_Confidence>
                    <stixCommon:Value xsi:type="stixVocabs:HighMediumLowVocab-1.0">High</stixCommon:Value>
                </coa:Applicability_Confidence>
            </coa:Objective>
            <coa:Parameter_Observables cybox_major_version="2" cybox_minor_version="1" cybox_update_version="0">
                <cybox:Observable id="example:Observable-356e3258-0979-48f6-9bcf-6823eecf9a7d">
                    <cybox:Object id="example:Address-df3c710c-f05c-4edb-a753-de4862048950">
                        <cybox:Properties xsi:type="AddressObj:AddressObjectType" category="ipv4-addr">
                            <AddressObj:Address_Value>10.10.10.10</AddressObj:Address_Value>
                        </cybox:Properties>
                    </cybox:Object>
                </cybox:Observable>
            </coa:Parameter_Observables>
            <coa:Impact>
                <stixCommon:Value xsi:type="stixVocabs:HighMediumLowVocab-1.0">Low</stixCommon:Value>
                <stixCommon:Description>This IP address is not used for legitimate hosting so there should be no operational impact.</stixCommon:Description>
            </coa:Impact>
            <coa:Cost>
                <stixCommon:Value xsi:type="stixVocabs:HighMediumLowVocab-1.0">Low</stixCommon:Value>
            </coa:Cost>
            <coa:Efficacy>
                <stixCommon:Value xsi:type="stixVocabs:HighMediumLowVocab-1.0">High</stixCommon:Value>
            </coa:Efficacy>
        </stix:Course_Of_Action>

STIX 2.x in JSON

.. code-block:: json

    {
        "id": "bundle--495c4c04-b5d8-11e3-b7bb-000c29789db9",
        "objects": [
            {
                "created": "2017-01-27T13:49:41.298Z",
                "description": "\n\nSTAGE:\n\tResponse\n\n
                                    OBJECTIVE: Block communication between the PIVY agents and the C2 Server\n\n
                                    CONFIDENCE: High\n\n
                                    IMPACT:Low, This IP address is not used for legitimate hosting so there should be no operational impact.\n\n
                                    COST:Low\n\n
                                    EFFICACY:High",
                "id": "course-of-action--495c9b28-b5d8-11e3-b7bb-000c29789db9",
                "labels": [
                    "perimeter-blocking"
                ],
                "modified": "2017-01-27T13:49:41.298Z",
                "name": "Block traffic to PIVY C2 Server (10.10.10.10)",
                "type": "course-of-action"
            }
        ],
        "spec_version": "2.0",
        "type": "bundle"
    }

Notice that the ``spec_version`` property only appears on the bundle in STIX 2.0, but in STIX 2.1, it is *not* a property of the
bundle. It may (optionally) appear on each object.  The elevator will always provides the ``spec_version`` property for
all 2.1 SDOs and SROs, but not on SCOs.

Incident
----------------------

In STIX 2.1 the ``Incident`` object is defined as a stub. This means that in STIX
2.x this object type is pretty "bare-bones", not containing most of the
properties that were found in STIX 1.x.

**STIX 1.x Properties Mapped Directly to STIX 2.x Properties**

*none*

**STIX 1.x Properties Translated to STIX 2.x Properties**

..  table::
    :align: left

    +-------------------------+---------------------------+
    | **STIX 1.x property**   | **STIX 2.x property**     |
    +=========================+===========================+
    | ``Categories``          |   ``labels``              |
    +-------------------------+---------------------------+
    | ``External_ID``         |   ``external_references`` |
    +-------------------------+---------------------------+

**STIX 1.x Properties Mapped Using STIX 2.x Relationships**

- ``Related_Indicators``
- ``Related_Observables``
- ``Leveraged_TTPs``
- ``Attributed_Threat_Actors``
- ``COA_Requested``
- ``COA_Taken``

**STIX 1.x Properties Handled Based on the "missing policy"**

 - ``Reporter``
 - ``Responder``
 - ``Coordinator``
 - ``Victims``
 - ``Status``
 - ``Contact``
 - ``Intended_Effect``

**STIX 1.x Properties Not Mapped**

 - ``Affected_Assets``
 - ``Impact_Assessment``
 - ``History``
 - ``URL``
 - ``Time``

**An Example**

STIX 1.x in XML

.. code-block:: xml

    <stix:Incidents>
        <stix:Incident id="example:incident-1b75ee8f-44d6-819a-d729-09ab52c91fdb" xsi:type='incident:IncidentType' timestamp="2014-05-08T09:00:00.000000Z">
            <incident:Title>Detected Poison Ivy beaconing through perimeter firewalls</incident:Title>
            <incident:Status>New</incident:Status>
            <incident:Contact>
                <stixCommon:Identity>
                    <stixCommon:Name>Fred</stixCommon:Name>
                </stixCommon:Identity>
            </incident:Contact>
            <incident:Contact>
                <stixCommon:Identity>
                    <stixCommon:Name>Barney</stixCommon:Name>
                </stixCommon:Identity>
            </incident:Contact>
            <incident:Leveraged_TTPs>
                <incident:Leveraged_TTP>
                    <stixCommon:Relationship>Uses Malware</stixCommon:Relationship>
                    <stixCommon:TTP idref="example:ttp-e610a4f1-9676-4ab3-bcc6-b2768d58281b"/>
                </incident:Leveraged_TTP>
            </incident:Leveraged_TTPs>
        </stix:Incident>
    </stix:Incidents>

STIX 2.1 in JSON

.. code-block:: json

    {
        "id": "bundle--65184e82-b693-41e3-bfd7-0800271e87d2",
        "objects": [
            {
                "created": "2014-05-08T09:00:00.000Z",
                "id": "identity--8e5febda-ffd0-4ade-8afe-9a7e64894510",
                "modified": "2014-05-08T09:00:00.000Z",
                "name": "Fred",
                "spec_version": "2.1",
                "type": "identity"
            },
            {
                "created": "2014-05-08T09:00:00.000Z",
                "id": "identity--b2557302-99e3-496a-825f-8e8c5501bec8",
                "modified": "2014-05-08T09:00:00.000Z",
                "name": "Barney",
                "spec_version": "2.1",
                "type": "identity"
            },
            {
                "created": "2014-05-08T09:00:00.000Z",
                "extensions": {
                    "extension-definition--7a8eaf47-9b0f-487d-b280-1e6cc4cccee9": {
                        "contacts": [
                            "identity--8e5febda-ffd0-4ade-8afe-9a7e64894510",
                            "identity--b2557302-99e3-496a-825f-8e8c5501bec8"
                        ],
                        "extension_type": "property-extension",
                        "status": "New"
                    }
                },
                "id": "incident--1b75ee8f-44d6-819a-d729-09ab52c91fdb",
                "modified": "2014-05-08T09:00:00.000Z",
                "name": "Detected Poison Ivy beaconing through perimeter firewalls",
                "spec_version": "2.1",
                "type": "incident"
            },
            {
                "created": "2014-05-08T09:00:00.000Z",
                "description": "Uses Malware",
                "id": "relationship--d695b661-62ff-4685-bf88-a449770969ed",
                "modified": "2014-05-08T09:00:00.000Z",
                "relationship_type": "related-to",
                "source_ref": "incident--1b75ee8f-44d6-819a-d729-09ab52c91fdb",
                "spec_version": "2.1",
                "target_ref": "malware--6516102d-b693-41e3-bfd7-0800271e87d2",
                "type": "relationship"
            }
        ],
        "type": "bundle"
    }

Indicator
------------------

STIX 1.x Composite Indicator Expressions and CybOX 2.x Composite
Observable Expressions allow a level of flexibility not present in STIX
2.x patterns. These composite expressions can frequently have ambiguous
interpretations, so STIX 2.x Indicators created by the stix2-elevator from
STIX 1.x Indicators containing composite expressions should be inspected
to ensure the STIX 2.x Indicator has the intended meaning.

**STIX 1.x Properties Mapped Directly to STIX 2.x Properties**

..  table::
    :align: left

    +-------------------------+------------------------------------------------+
    | **STIX 1.x property**   | **STIX 2.x property**                          |
    +=========================+================================================+
    | ``Valid_Time_Position`` |   ``valid_from``, ``valid_until``              |
    +-------------------------+------------------------------------------------+
    | ``Type``                |   ``labels`` in 2.0, ``indicator_type`` in 2.1 |
    +-------------------------+------------------------------------------------+


**STIX 1.x Properties Translated to STIX 2.x Properties**

..  table::
    :align: left

    +-------------------------+---------------------------------------------+
    | **STIX 1.x property**   | **STIX 2.x property**                       |
    +=========================+=============================================+
    | ``Alternative_ID``      |   ``external_references``                   |
    +-------------------------+---------------------------------------------+
    | ``Kill_Chain_Phases``   |   ``kill_chain_phases``                     |
    +-------------------------+---------------------------------------------+
    | ``Indicator_Expression``|   ``pattern``                               |
    +-------------------------+---------------------------------------------+
    | ``Test_Mechanisms``     |   ``pattern``                               |
    +-------------------------+---------------------------------------------+
    | ``Producer``            |   ``created_by_ref``                        |
    +-------------------------+---------------------------------------------+

**STIX 1.x Properties Mapped Using STIX 2.x Relationships**

..  table::
    :align: left

    +-------------------------+----------------------------------------------+
    | **STIX 1.x property**   | **STIX 2.x relationship type**               |
    +=========================+==============================================+
    | ``Indicated_TTP``       | ``detects``                                  |
    +-------------------------+----------------------------------------------+
    | ``Suggested_COAs``      | ``related-to``                               |
    +-------------------------+----------------------------------------------+
    | ``Related_Indicators``  | ``related-to`` (when not used for versioning)|
    +-------------------------+----------------------------------------------+
    | ``Related_Campaigns``   | ``indicates``                                |
    +-------------------------+----------------------------------------------+

**STIX 1.x Properties Handled Based on the "missing policy"**

- ``Likely_Impact``

**STIX 1.x Properties Not Mapped**

- ``negate``


**An Example**

STIX 1.x in XML

.. code-block:: xml

    <stix:Indicator id="example:Indicator-d81f86b9-975b-bc0b-775e-810c5ad45a4f"
                    xsi:type='indicator:IndicatorType'>
        <indicator:Title>Malicious site hosting downloader</indicator:Title>
        <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.0">URL Watchlist</indicator:Type>
        <indicator:Observable id="example:Observable-ee59c28e-d922-480e-9b7b-a79502696505">
            <cybox:Object id="example:URI-b13ae3fc-80af-49c2-9de9-f713abc070ba">
                <cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">
                    <URIObj:Value condition="Equals">http://x4z9arb.cn/4712</URIObj:Value>
                </cybox:Properties>
            </cybox:Object>
        </indicator:Observable>
    </stix:Indicator>

STIX 2.x in JSON

.. code-block:: json

    {
       "created": "2017-01-27T13:49:53.935Z",
       "id": "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f",
       "indicator_types": [
           "url-watchlist"
       ],
       "modified": "2017-01-27T13:49:53.935Z",
       "name": "Malicious site hosting downloader",
       "pattern": "[url:value = 'http://x4z9arb.cn/4712']",
       "pattern_type": "stix",
       "type": "indicator",
       "valid_from": "2017-01-27T13:49:53.935382Z"
    }

``indicator_types`` would be ``labels`` in 2.0

**Sightings**

In STIX 1.x sightings were a property of
``IndicatorType``. In STIX 2.x, sightings are a top-level STIX *relationship*
object. Because they represent the relationship (match) of an indicator
pattern to observed data (or other object), they are more naturally
represented as a STIX 2.x relationship.

For example, suppose the above indicator pattern was matched against an actual cyber observable
("observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"), because a victim (whose
identity is represented by "identity--b67d30ff-02ac-498a-92f9-32f845f448ff") observed that URL.

The STIX 2.x sighting would be:

.. code-block:: json

    {
        "type": "sighting",
        "id": "sighting--ee20065d-2555-424f-ad9e-0f8428623c75",
        "created_by_ref": "identity--f431f809-377b-45e0-aa1c-6a4751cae5ff",
        "created": "2016-04-06T20:08:31.000Z",
        "modified": "2016-04-06T20:08:31.000Z",
        "first_seen": "2015-12-21T19:00:00Z",
        "last_seen": "2015-12-21T19:00:00Z",
        "count": 50,
        "sighting_of_ref": "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f",
        "observed_data_refs": ["observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"],
        "where_sighted_refs": ["identity--b67d30ff-02ac-498a-92f9-32f845f448ff"]
    }


Location
----------------------

In STIX 2.1 the ``location`` object corresponds to any ``Information_Source`` Address objects in STIX 1.x.
``Information_Source`` objects with ``Address`` information can appear in most top-level STIX 1.x objects. However, you cannot
store location information as a property in STIX 2.1, because ``location`` is a top-level object.  To do the conversion, it is necessary to
create a new STIX 2.1 ``location`` object, transfering the STIX 1.x address information into it, and introducing a STIX 2.x
``relationship`` object between that original object and the new ``location`` object.

**STIX 1.x Properties Mapped Directly to STIX 2.x Properties**

..  table::
    :align: left

    +------------------------------+----------------------------------------------+
    | **STIX 1.x property**        | **STIX 2.x relationship type**               |
    +==============================+==============================================+
    |     ``Administrative_Area``  | ``administrative_area``                      |
    +------------------------------+----------------------------------------------+
    |     ``Country``              | ``country``                                  |
    +------------------------------+----------------------------------------------+

**STIX 1.x Properties Translated to STIX 2.x Properties**

*none*

**STIX 1.x Properties Mapped Using STIX 2.x Relationships**

*none*

**STIX 1.x Properties Handled Based on the "missing policy"**

- ``free_text_address``

**STIX 1.x Properties Not Mapped**

*none*


**An Example**

STIX 1.x in XML

.. code-block:: xml

    <ta:Identity id="example:Identity-733c5838-34d9-4fbf-949c-62aba761184c" xsi:type='stix-ciqidentity:CIQIdentity3.0InstanceType'>
        <ExtSch:Specification xmlns:ExtSch="http://stix.mitre.org/extensions/Identity#CIQIdentity3.0-1">
            <xpil:PartyName xmlns:xpil="urn:oasis:names:tc:ciq:xpil:3">
                <xnl:OrganisationName xmlns:xnl="urn:oasis:names:tc:ciq:xnl:3" xnl:Type="CommonUse">
                    <xnl:NameElement>Disco Tean</xnl:NameElement>
                </xnl:OrganisationName>
                <xnl:OrganisationName xmlns:xnl="urn:oasis:names:tc:ciq:xnl:3" xnl:Type="UnofficialName">
                    <xnl:NameElement>Equipo del Discoteca</xnl:NameElement>
                </xnl:OrganisationName>
            </xpil:PartyName>
            <xpil:Addresses xmlns:xpil="urn:oasis:names:tc:ciq:xpil:3">
                <xpil:Address>
                    <xal:Country xmlns:xal="urn:oasis:names:tc:ciq:xal:3">
                        <xal:NameElement>United States</xal:NameElement>
                    </xal:Country>
                    <xal:AdministrativeArea xmlns:xal="urn:oasis:names:tc:ciq:xal:3">
                        <xal:NameElement>California</xal:NameElement>
                    </xal:AdministrativeArea>
                </xpil:Address>
            </xpil:Addresses>
        </ExtSch:Specification>
    </ta:Identity>

STIX 2.1 in JSON

.. code-block:: json

    {
        "id": "bundle--ccd00c4a-1bdb-46ae-9898-ecaca13f1f12",
        "objects": [
            {
              "administrative_area": "California",
              "country": "US",
              "created": "2014-11-19T23:39:03.893Z",
              "id": "location--c1445467-fd92-4532-9161-1c3024ab6467",
              "modified": "2014-11-19T23:39:03.893Z",
              "spec_version": "2.1",
              "type": "location"
            },
            {
              "created": "2014-11-19T23:39:03.893Z",
              "id": "relationship--b1d9c097-a0ac-46e8-997b-291ea3b976f5",
              "modified": "2014-11-19T23:39:03.893Z",
              "relationship_type": "located-at",
              "source_ref": "identity--733c5838-34d9-4fbf-949c-62aba761184c",
              "spec_version": "2.1",
              "target_ref": "location--c1445467-fd92-4532-9161-1c3024ab6467",
              "type": "relationship"
            },
            {
              "created": "2014-11-19T23:39:03.893Z",
              "id": "identity--733c5838-34d9-4fbf-949c-62aba761184c",
              "identity_class": "organization",
              "modified": "2014-11-19T23:39:03.893Z",
              "name": "Disco Tean",
              "spec_version": "2.1",
              "type": "identity"
            }
        ],
        "type": "bundle"
    }


Malware
-------------

The Malware object in STIX 1.x is a stub, which depends up MAEC content for further properties.
The elevator does not support the conversion of MAEC content.
The main properties of malware in STIX 2.0 are not much different than the defined ones in 1.x.
STIX 2.1 included more properties, and additionally the object type ``malware-analysis``, therefore
conversion of MAEC content could be supported in a future release of the elevator.

Malware is not a top-level object in STIX 1.x, but a property of a ``TTP``.

The ``name`` property of the STIX 1.x
Malware object is the preferred property to use to populated the ``name`` property in the STIX 2.x object, although if
missing, the ``title`` property can be used.

**STIX 1.x Properties Mapped Directly to STIX 2.x Properties**

..  table::
    :align: left

    +---------------------------+----------------------------------------------+
    | **STIX 1.x property**     | **STIX 2.x property**                        |
    +===========================+==============================================+
    | ``Type``                  | ``labels`` in 2.0, ``malware_types`` in 2.1  |
    +---------------------------+----------------------------------------------+

**STIX 1.x Properties Translated to STIX 2.x Properties**

..  table::
    :align: left

    +---------------------------+--------------------------------------------------------------------------------+
    | **STIX 1.x property**     | **STIX 2.x property**                                                          |
    +===========================+================================================================================+
    | ``ttp:Kill_Chain_Phases`` |   ``kill_chain_phases``                                                        |
    +---------------------------+--------------------------------------------------------------------------------+

**STIX 1.x Properties Mapped Using STIX 2.x Relationships**

..  table::
    :align: left

    +---------------------------+-------------------------------------------------------------------------------------+
    | **STIX 1.x property**     | **STIX 2.x relationship type**                                                      |
    +===========================+=====================================================================================+
    | ``ttp:Related_TTPs``      | ``variant-of`` (malware), ``related-to`` (when not used for versioning), uses (tool)|
    +---------------------------+-------------------------------------------------------------------------------------+
    | ``ttp:Exploit_Targets``   | ``targets`` (vulnerability, only)                                                   |
    +---------------------------+-------------------------------------------------------------------------------------+
    | ``ttp:Victim_Targeting``  | ``targets``                                                                         |
    +---------------------------+-------------------------------------------------------------------------------------+

**STIX 1.x Properties Handled Based on the "missing policy"**

 - ``ttp:Intended_Effect``

**STIX 1.x Properties Not Mapped**

 - ``ttp:Kill_Chains``

 - any MAEC content

**An Example**

STIX 1.x in XML

.. code-block:: xml

    <stix:TTP id="example:ttp-e610a4f1-9676-eab3-bcc6-b2768d58281a"
              xsi:type='ttp:TTPType'
              timestamp="2014-05-08T09:00:00.000000Z">
       <ttp:Title>Poison Ivy</ttp:Title>
       <ttp:Behavior>
           <ttp:Malware>
               <ttp:Malware_Instance id="example:malware-fdd60b30-b67c-11e3-b0b9-f01faf20d111">
                   <ttp:Type xsi:type="stixVocabs:MalwareTypeVocab-1.0">Remote Access Trojan</ttp:Type>
                   <ttp:Name>Poison Ivy</ttp:Name>
               </ttp:Malware_Instance>
           </ttp:Malware>
       </ttp:Behavior>
    </stix:TTP>

STIX 2.x in JSON

.. code-block:: json

    {
       "created": "2017-01-27T13:49:53.997Z",
       "description": "\n\nTITLE:\n\tPoison Ivy",
       "id": "malware--fdd60b30-b67c-11e3-b0b9-f01faf20d111",
       "malware_types": [
           "remote-access-trojan"
       ],
       "modified": "2017-01-27T13:49:53.997Z",
       "name": "Poison Ivy",
       "type": "malware"
    }

``malware_types`` would be ``labels`` in 2.0


Observed Data
--------------

The Observed Data object in STIX 2.x corresponds to the ``Observable``
object in CybOX 2.x. Each Observed Data object contains or references one or more
*related* cyber observable objects.

STIX 2.x adds two properties: ``first_observed`` and ``last_observed``.
These properties are related to the ``number_observed`` property, because it is possible for
Observed Data to indicate that either one, or multiple instances of the same cyber observable occurred.
If the ``number_observed`` property is 1, then the ``first_observed`` and ``last_observed`` properties
contain the same timestamp, otherwise they are the timestamp of the first and last times that cyber observable occurred.

The ``sighting_count`` property of STIX 1.x may seem to be the same concept as ``number_observed`` property,
but because STIX 2.x has made explicit the difference between sightings and observed data,
this is not the case.  See the STIX 2.x specification for more details.
The sightings count is captured on the ``sighting`` SRO.

**STIX 1.x Properties Mapped Directly to STIX 2.x Properties**

..  table::
    :align: left

    +--------------------------+------------------------------------------------+
    | **STIX 1.x property**    | **STIX 2.x property**                          |
    +==========================+================================================+
    | ``sighting_count``       | not to be confused with **number_observed**    |
    +--------------------------+------------------------------------------------+
    |``Keywords``              | ``labels``                                     |
    +--------------------------+------------------------------------------------+

​**STIX 1.x Properties Translated to STIX 2.x Properties**

..  table::
    :align: left

    +--------------------------+------------------------------------------------+
    | **STIX 1.x property**    | **STIX 2.x property**                          |
    +==========================+================================================+
    | ``Object``               | ``objects`` in 2.0, ``object_refs`` in 2.1     |
    +--------------------------+------------------------------------------------+

**STIX 1.x Properties Mapped Using STIX 2.x Relationships**

*none*

**STIX 1.x Properties Handled Based on the "missing policy"**

*none*

**STIX 1.x Properties Not Mapped**

- ``negate``
- ``Event``
- ``Title``
- ``Description``
- ``Pattern_Fidelity``
- ``Observable_Source``

**An Example**

STIX 1.x in XML

.. code-block:: xml

    <cybox:Observable id="example:observable-c8c32b6e-2ea8-51c4-6446-7f5218072f27">
       <cybox:Object id="example:object-d7fcce87-0e98-4537-81bf-1e7ca9ad3734">
            <cybox:Properties xsi:type="FileObj:FileObjectType">
                <FileObj:File_Name>iprip32.dll</FileObj:File_Name>
                <FileObj:File_Path>/usr/local</FileObj:File_Path>
                <FileObj:Hashes>
                    <cyboxCommon:Hash>
                        <cyboxCommon:Type condition="Equals" xsi:type="cyboxVocabs:HashNameVocab-1.0">SHA256</cyboxCommon:Type>
                        <cyboxCommon:Simple_Hash_Value condition="Equals">e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</cyboxCommon:Simple_Hash_Value>
                    </cyboxCommon:Hash>
                </FileObj:Hashes>
            </cybox:Properties>
       </cybox:Object>
    </cybox:Observable>


STIX 2.0 in JSON

.. code-block:: json

    {
       "created": "2017-01-27T13:49:41.345Z",
       "first_observed": "2017-01-27T13:49:41.345Z",
       "id": "observed-data--c8c32b6e-2ea8-51c4-6446-7f5218072f27",
       "last_observed": "2017-01-27T13:49:41.345Z",
       "modified": "2017-01-27T13:49:41.345Z",
       "number_observed": 1,
       "objects": {
           "0": {
                "hashes": {
                    "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                },
               "name": "iprip32.dll",
               "parent_directory_ref": "1",
               "type": "file"
           },
           "1": {
               "path": "/usr/local",
               "type": "directory"
           }
       },
       "type": "observed-data"
    }

STIX 2.1 in JSON

.. code-block:: json

    {
        "hashes": {
            "SHA-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        "id": "file--49959589-27c4-5873-8e23-82f6c909d4ca",
        "name": "iprip32.dll",
        "parent_directory_ref": "directory--4aa982e3-4aac-5d5b-a699-d08c8c11f5f3",
        "type": "file"
    }

    {
        "id": "directory--4aa982e3-4aac-5d5b-a699-d08c8c11f5f3",
        "path": "/usr/local",
        "type": "directory"
    }

    {
           "created": "2017-01-27T13:49:41.345Z",
           "first_observed": "2017-01-27T13:49:41.345Z",
           "id": "observed-data--c8c32b6e-2ea8-51c4-6446-7f5218072f27",
           "last_observed": "2017-01-27T13:49:41.345Z",
           "modified": "2017-01-27T13:49:41.345Z",
           "number_observed": 1,
           "object_refs": [
                "directory--4aa982e3-4aac-5d5b-a699-d08c8c11f5f3",
                "file--49959589-27c4-5873-8e23-82f6c909d4ca"
           ],
           "type": "observed-data"
    }

In STIX 2.x cyber observables are only used within ``observed-data`` objects to
represent something that has actually been seen.  In STIX 1.x if an ``Observable`` is contained in an ``Indicator``, it is instead
expressing a pattern to match against observed data.

The pattern expression to match the example cyber observable, when it is located in an indicator object, would be:

.. code::

    [(file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' AND (file:name = 'iprip32.dll' AND file:parent_directory_ref.path = '/usr/local'))]",



Report
--------

The Report object in STIX 2.x does not contain objects, but only object references
to STIX objects that are specified elsewhere (the location of the actual
objects may not be contained in the same bundle that contains the ``report``
object).

In STIX 2.x, properties that were associated with the report
header in STIX 1.x are located in the ``report`` object itself. The
``labels`` property (``report_type`` in 2.1) contains vocabulary literals similar to the ones
contain in the ``Intent`` property in STIX 1.x.

The ``published`` property is required in STIX 2.x, so the timestamp of the STIX 1.2 Report is used.

**STIX 1.x Properties Mapped Directly to STIX 2.x Properties**

*none*

**STIX 1.x Properties Translated to STIX 2.x Properties**

..  table::
    :align: left

    +------------------------------+--------------------------------------------+
    | **STIX 1.x property**        | **STIX 2.x property**                      |
    +==============================+============================================+
    | ``Observables``              | ``object_refs``                            |
    +------------------------------+--------------------------------------------+
    | ``Indicators``               | ``object_refs``                            |
    +------------------------------+--------------------------------------------+
    | ``TTPs``                     | ``object_refs``                            |
    +------------------------------+--------------------------------------------+
    | ``Exploit_Targets``          | ``object_refs``                            |
    +------------------------------+--------------------------------------------+
    | ``Courses_Of_Action``        | ``object_refs``                            |
    +------------------------------+--------------------------------------------+
    | ``Campaigns``                | ``object_refs``                            |
    +------------------------------+--------------------------------------------+
    | ``Threat_Actors``            | ``object_refs``                            |
    +------------------------------+--------------------------------------------+
    | ``Report:Header.Intent``     | ``labels`` in 2.0, ``report_types`` in 2.1 |
    +------------------------------+--------------------------------------------+
    | ``Report:Header.Description``| ``description``                            |
    +------------------------------+--------------------------------------------+
    | ``Report:Header.Title``      | ``name``                                   |
    +------------------------------+--------------------------------------------+


​**STIX 1.x Properties Mapped Using STIX 2.x Relationships**

..  table::
    :align: left

    +-------------------------+--------------------------------------------------+
    | **STIX 1.x property**   | **STIX 2.x relationship type**                   |
    +=========================+==================================================+
    | ``Related_Reports``     | ``related-to`` (when not used for versioning)    |
    +-------------------------+--------------------------------------------------+

**An Example**

STIX 1.x in XML

.. code-block:: xml

    <stix:Report timestamp="2015-05-07T14:22:14.760467+00:00"
                 id="example:Report-ab11f431-4b3b-457c-835f-59920625fe65"
                 xsi:type='report:ReportType' version="1.0">
            <report:Header>
                <report:Title>Report on Adversary Alpha's Campaign against the Industrial Control Sector</report:Title>
                <report:Intent xsi:type="stixVocabs:ReportIntentVocab-1.0">Campaign Characterization</report:Intent>
                <report:Description>Adversary Alpha has a campaign against the ICS sector!</report:Description>
            </report:Header>
            <report:Campaigns>
                <report:Campaign idref="example:campaign-1855cb8a-d96c-4859-a450-abb1e7c061f2" xsi:type='campaign:CampaignType'/>
            </report:Campaigns>
        </stix:Report>

STIX 2.x in JSON

.. code-block:: json


    {
            "created": "2015-05-07T14:22:14.760Z",
            "created_by_ref": "identity--c1b58a86-e037-4069-814d-dd0bc75539e3",
            "description": "Adversary Alpha has a campaign against the ICS sector!\n\nINTENT:\nCampaign Characterization",
            "id": "report--ab11f431-4b3b-457c-835f-59920625fe65",
            "report_types": [
                "campaign-characterization"
            ],
            "modified": "2015-05-07T14:22:14.760Z",
            "name": "Report on Adversary Alpha's Campaign against the Industrial Control Sector",
            "object_refs": [
                "campaign--1855cb8a-d96c-4859-a450-abb1e7c061f2"
            ],
            "type": "report"
        }

``report_types`` would be ``labels`` in 2.0

Threat Actor
------------------

**STIX 1.x Properties Mapped Directly to STIX 2.x Properties**

..  table::
    :align: left

    +-------------------------+--------------------------------------------------+
    | **STIX 1.x property**   | **STIX 2.x property**                            |
    +=========================+==================================================+
    | ``Intended_Effects``    | ``goals``                                        |
    +-------------------------+--------------------------------------------------+
    | ``Type``                | ``labels`` in 2.0, ``threat_actor_types`` in 2.1 |
    +-------------------------+--------------------------------------------------+

**STIX 1.x Properties Translated to STIX 2.x Properties**

..  table::
    :align: left

    +-------------------------------------+--------------------------------------------------------------------------------+
    | **STIX 1.x property**               | **STIX 2.x property**                                                          |
    +=====================================+================================================================================+
    | ``Motivation``                      |   ``primary_motivation``, ``secondary_motivations``, ``personal_motivations``  |
    +-------------------------------------+--------------------------------------------------------------------------------+
    | ``Sophistication``                  |   ``sophistication``                                                           |
    +-------------------------------------+--------------------------------------------------------------------------------+

​**STIX 1.x Properties Mapped Using STIX 2.x Relationships**

..  table::
    :align: left

    +-------------------------+----------------------------------------------+
    | **STIX 1.x property**   | **STIX 2.x relationship type**               |
    +=========================+==============================================+
    | ``Identity``            | ``attributed-to``                            |
    +-------------------------+----------------------------------------------+
    | ``Observed_TTPs``       | ``uses``                                     |
    +-------------------------+----------------------------------------------+
    | ``Associated_Campaigns``| ``attributed-to`` (reverse)                  |
    +-------------------------+----------------------------------------------+
    | ``Associated_Actors``   | ``related-to`` (when not used for versioning)|
    +-------------------------+----------------------------------------------+

**STIX 1.x Properties Handled Based on the "missing policy"**

- ``Planning_And_Operational_Support``


**STIX 1.x Properties Not Mapped**

*none*

**An Example**

STIX 1.x in XML

.. code-block:: xml

    <stix:Threat_Actor id="example:threatactor-56f3f0db-b5d5-431c-ae56-c18f02caf500"
                       xsi:type='ta:ThreatActorType'
                       timestamp="2016-08-08T15:50:10.983Z"
                       version="1.2">
         <ta:Title>Fake BPP (Branistan Peoples Party)</ta:Title>
         <ta:Identity id="example:Identity-8c6af861-7b20-41ef-9b59-6344fd872a8f">
            <stixCommon:Name>Franistan Intelligence</stixCommon:Name>
         </ta:Identity>
         <ta:Type>
            <stixCommon:Value xsi:type="stixVocabs:ThreatActorTypeVocab-1.0">State Actor / Agency</stixCommon:Value>
         </ta:Type>
         <ta:Intended_Effect>Influence the election in Branistan</ta:Intended_Effect>
         <ta:Motivation>
            <stixCommon:Value xsi:type="stixVocabs:MotivationVocab-1.1">Political</stixCommon:Value>
         </ta:Motivation>
         <ta:Motivation>
            <stixCommon:Value xsi:type="stixVocabs:MotivationVocab-1.1">Ideological</stixCommon:Value>
         </ta:Motivation>
         <ta:Motivation>
            <stixCommon:Value>Organizational Gain</stixCommon:Value>
         </ta:Motivation>
         <ta:Sophistication>
            <stixCommon:Value>Strategic</stixCommon:Value>
         </ta:Sophistication>
    </stix:Threat_Actor>


STIX 2.x in JSON

.. code-block:: json

    {
          "type": "threat-actor",
          "id": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500",
          "created_by_ref": "identity--f690c992-8e7d-4b9a-9303-3312616c0220",
          "created": "2016-08-08T15:50:10.983Z",
          "modified": "2016-08-08T15:50:10.983Z",
          "threat_actor_types": ["nation-state"],
          "goals": ["Influence the election in Branistan"],
          "primary_motivation": "political",
          "secondary_motivations": ["ideology", "organizational-gain"],
          "name": "Fake BPP (Branistan Peoples Party)",
          "sophistication": "strategic"
    }

    {
          "type": "identity",
          "id": "identity--8c6af861-7b20-41ef-9b59-6344fd872a8f",
          "created_by_ref": "identity--f690c992-8e7d-4b9a-9303-3312616c0220",
          "created": "2016-08-08T15:50:10.983Z",
          "modified": "2016-08-08T15:50:10.983Z",
          "name": "Franistan Intelligence",
          "identity_class": "organization"
    }

    {
          "type": "relationship",
          "id": "relationship--5b271699-d2ad-468c-903d-304ad7a17d71",
          "created": "2016-08-08T15:50:10.983Z",
          "modified": "2016-08-08T15:50:10.983Z",
          "relationship_type": "attributed-to",
          "source_ref": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500",
          "target_ref": "identity--8c6af861-7b20-41ef-9b59-6344fd872a8f"
    }

``threat_actor_types`` would be ``labels`` in 2.0

Tool
-------

**STIX 1.x Properties Mapped Directly to STIX 2.x Properties**

..  table::
    :align: left

    +---------------------------------------+-----------------------------------------------+
    | **STIX 1.x property**                 | **STIX 2.x property**                         |
    +=======================================+===============================================+
    | ``Name`` (from CybOX)                 |   ``name``                                    |
    +---------------------------------------+-----------------------------------------------+
    | ``Type`` (from CybOX)                 |   ``labels`` in 2.0, ``tool_types`` in 2.1    |
    +---------------------------------------+-----------------------------------------------+
    | ``Description`` (from CybOX)          |   ``description``                             |
    +---------------------------------------+-----------------------------------------------+
    | ``Version`` (from CybOX)              |   ``tool_version``                            |
    +---------------------------------------+-----------------------------------------------+

​**STIX 1.x Properties Translated to STIX 2.x Properties**

..  table::
    :align: left

    +---------------------------------------+---------------------------------+
    | **STIX 1.x property**                 | **STIX 2.x property**           |
    +=======================================+=================================+
    | ``ttp:Kill_Chain_Phases``             |   ``kill_chain_phases``         |
    +---------------------------------------+---------------------------------+
    | ``References`` (from CybOX)           |   ``external_references``       |
    +---------------------------------------+---------------------------------+

​**STIX 1.x Properties Mapped Using STIX 2.x Relationships**

..  table::
    :align: left

    +---------------------------+------------------------------------------------------------------------------------+
    | **STIX 1.x property**     | **STIX 2.x relationship type**                                                     |
    +===========================+====================================================================================+
    | ``ttp:Related_TTPs``      | ``uses`` (attack-pattern) (reverse), ``related-to`` (when not used for versioning),|
    |                           | ``targets`` (identity)                                                             |
    +---------------------------+------------------------------------------------------------------------------------+

**STIX 1.x Properties Handled Based on the "missing policy"**

- ``Vendor``

- ``Service_Pack``

**STIX 1.x Properties Not Mapped**

- ``Compensation_Model`` (from CybOX)
- ``Errors`` (from CybOX)
- ``Execution_Environment`` (from CybOX)
- ``ttp:Exploit_Targets``
- ``ttp:Kill_Chains``
- ``Metadata`` (from CybOX)
- ``Tool_Configuration`` (from CybOX)
- ``Tool_Hashes`` (from CybOX)
- ``Tool_Specific_Data`` (from CybOX)
- ``ttp:Victim_Targeting``

**An Example**

STIX 1.x in XML

.. code-block:: xml

    <stix:TTP id=example:tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f
              timestamp="2016-04-06T20:03:48.000Z">
      <ttp:Resources>
          <ttp:Tools>
             <ttp:Tool>
                 <cyboxCommon:Name>VNCConnect</cyboxCommon:Name>
                 <cyboxCommon:Type>remote-access</cyboxCommon:Name>
                 <cyboxCommon:Vendor>RealVNC Ltd</cyboxCommon:Vendor>
                 <cyboxCommon:Version>6.03</cyboxCommon:Version>
             </ttp:Tool>
         </ttp:Tools>
      </ttp:Resources>
    </stix:ttp>


STIX 2.x in JSON

.. code-block:: json

    {
      "type": "tool",
      "id": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
      "created": "2016-04-06T20:03:48.000Z",
      "modified": "2016-04-06T20:03:48.000Z",
      "tool_types": [ "remote-access"],
      "version": "6.03",
      "name": "VNCConnect"
    }

``tool_types`` would be ``labels`` in 2.0

Vulnerability
------------------

**STIX 1.x Properties Mapped Directly to STIX 2.x Properties**

*none*

**STIX 1.x Properties Translated to STIX 2.x Properties**

..  table::
    :align: left

    +--------------------------+------------------------------------+
    | **STIX 1.x property**    | **STIX 2.x mapping**               |
    +==========================+====================================+
    | ``CVE_ID``               |   ``external_references``          |
    +--------------------------+------------------------------------+
    | ``OSVDB_ID``             |   ``external_references``          |
    +--------------------------+------------------------------------+
    | ``References``           |   ``external_references``          |
    +--------------------------+------------------------------------+

**​STIX 1.x Properties Mapped Using STIX 2.x Relationships**

..  table::
    :align: left

    +-------------------------------+-----------------------------------------------+
    | **STIX 1.x property**         | **STIX 2.x relationship type**                |
    +===============================+===============================================+
    | ``et:Potential_COAs``         | ``mitigates``                                 |
    +-------------------------------+-----------------------------------------------+
    | ``et:Related_Exploit_Targets``| ``related-to`` (when not used for versioning) |
    +-------------------------------+-----------------------------------------------+


**STIX 1.x Properties Handled Based on the "missing policy"**

- ``Discovered_DateTime``
- ``Published_DateTime``
- ``Source``

**STIX 1.x Properties Not Mapped**

- ``is_known``
- ``is_publicly_acknowledged``
- ``CVSS_Score``
- ``Affected_Software``


**An Example**


STIX 1.x in XML

.. code-block:: xml

    <stix:Exploit_Targets>
       <stixCommon:Exploit_Target id="example:et-e77c1e36-5b43-4c5c-b8cb-7b36035f2b90" timestamp="2014-06-20T15:16:56.986650+00:00" xsi:type='et:ExploitTargetType' version="1.2">
           <et:Title>Heartbleed</et:Title>
           <et:Vulnerability>
               <et:CVE_ID>CVE-2013-3893</et:CVE_ID>
           </et:Vulnerability>
       </stixCommon:Exploit_Target>
    </stix:Exploit_Targets>

STIX 2.x in JSON

.. code-block:: json

    {
       "created": "2014-06-20T15:16:56.986Z",
       "external_references": [
           {
               "external_id": "CVE-2013-3893",
               "source_name": "cve"
           }
       ],
       "id": "vulnerability--e77c1e36-5b43-4c5c-b8cb-7b36035f2b90",
       "modified": "2017-01-27T13:49:54.310Z",
       "name": "Heartbleed",
       "type": "vulnerability"
    }
