​Mappings from STIX 1.x to STIX 2.0
=======================================

Top Level Object Mappings
-------------------------------

+-------------------------+-------------------------+
| **STIX 1.x object**     | **STIX 2.0 object**     |
+=========================+=========================+
| Campaign                | campaign                |
+-------------------------+-------------------------+
| Course_Of_Action        | course-of-action        |
+-------------------------+-------------------------+
| et:Vulnerability        | vulnerability           |
+-------------------------+-------------------------+
| et:Weakness             | *not converted*         |
+-------------------------+-------------------------+
| et:Configuration        | *not converted*         |
+-------------------------+-------------------------+
| Incident                | *not converted*         |
+-------------------------+-------------------------+
| Indicator               | indicator               |
+-------------------------+-------------------------+
| Report                  | report                  |
+-------------------------+-------------------------+
| Observable              | observed-data           |
+-------------------------+-------------------------+
| Package                 | bundle                  |
+-------------------------+-------------------------+
| Threat Actor            | threat-actor            |
+-------------------------+-------------------------+
| ttp:Attack_Pattern      | attack-pattern          |
+-------------------------+-------------------------+
| ttp:Infrastructure      | *not converted*         |
+-------------------------+-------------------------+
| ttp:Malware             | malware                 |
+-------------------------+-------------------------+
| ttp:Persona             | *not converted*         |
+-------------------------+-------------------------+
| ttp:Tool                | tool                    |
+-------------------------+-------------------------+
| ttp:Victim_Targeting    | identity                |
+-------------------------+-------------------------+


Common Properties
------------------------

**STIX 1.x Properties Mapped Directly to STIX 2.0 Properties**

+-------------------------+-------------------------+
| **STIX 1.x property**   | **STIX 2.0 property**   |
+=========================+=========================+
| Description             | description             |
+-------------------------+-------------------------+
| id                      | id                      |
+-------------------------+-------------------------+
| timestamp               |   created               |
+-------------------------+-------------------------+
| Title                   |   name                  |
+-------------------------+-------------------------+

**STIX 1.x Properties Translated to STIX 2.0 Properties**

+-------------------------+--------------------------------------------------+
| **STIX 1.x property**   | **STIX 2.0 property**                            |
+=========================+==================================================+
| Handling                |   object\_markings\_refs, granular\_markings     |
+-------------------------+--------------------------------------------------+
| Information\_Source     |   created\_by\_ref  ,   external_references      |
+-------------------------+--------------------------------------------------+
| Type                    |   labels                                         |
+-------------------------+--------------------------------------------------+

-  Handling

    Data Markings, called Handling in STIX 1.x, have been completely
    redesigned for STIX 2.0. STIX 1.x used xpath, which was a reasonable
    choice given its reliance on XML for implementation. However, the
    use of xpath was very difficult to implement, and was more
    expressive than was deemed necessary.

    STIX 2.0 introduces two new concepts, object markings and granular
    markings, which simplify the marking of data. Object markings apply
    to a whole object, whereas granular markings are specific to
    particular properties of an object. The selection of which
    properties are to be marked is expressed in a serialization-neutral
    way. The scope of marking definitions is at the object level. There
    is no marking that can apply to a whole bundle, or report.


-  Information\_Source

    In STIX 1.x there were several related concepts that were used to
    identify the sources of information and various parties of interest.
    Parties of interest are creators of content, victim targets, and
    other responsible parties. Sources of information could be an
    individual, organization or some software application. Additionally,
    it was possible to make references to sources external to STIX,
    e.g., a citation, URL, or an ID in an external system or repository.

    In STIX 2.0, we have retained the concept of an IdentityType object,
    but do not rely on the CIQ standard model []
    The CIQ model is very extensive and overly verbose, which
    contradicted our design goal of simplicity, therefore it was not
    used in STIX 2.0. The Identity object type in STIX 2.0 contains a
    very streamlined set of properties: **identity\_class** to specify
    if it is an individual or organization, **sectors** to indicate the
    industry sector that the identity belongs to, and a free text
    property, **contact\_information** to specify such information.

    The InformationSourceType object was used in STIX 1.x to associate
    an object with its creator's identity. In STIX 2.0, the common
    property **created\_by\_ref** is used, and it must contain the
    identifier of an Identity object.

    The InformationSourceType object was also used in STIX 1.x to
    specify external information. Other properties like capec\_id of
    AttackPatternType, or cwe\_id of VulnerabilityType were also used
    for external information, holding the ids of items in repositories
    or systems external to STIX. In STIX 2.0, the data type
    external-reference is used for all external information.


-  Type

    In STIX 2.0, the type of an object is defined to be a specific literal, and is recorded in the type property.
    The type of an object in STIX 1.x was either implicitly defined by its element name or explicitly using xsi:type.

**STIX 1.x Properties Mapped Using STIX 2.0 Relationships**

*none*

**STIX 1.x Properties Recorded in the STIX 2.0 Description Property**

-  Short\_Description

**STIX 1.x Properties Not Mapped**

-  Confidence

    The confidence concept is not present in STIX 2.0. However, the
    property name confidence has been reserved for future STIX versions.

-  Idref

    Relationships in STIX 2.0 make use of id references to indicate the
    source and target of the relationship. STIX objects additionally
    used id references for any property whose suffix is "ref" or "refs".
    The decision available in STIX 1.x to specify related objects by
    embedding them is not available in STIX 2.0.

-  Related\_Packages

    STIX 1.x packages correspond to STIX 2.0 bundles. However, bundles
    cannot refer to other bundles, so there is no way to express this
    property in STIX 2.0.

-  Version

    Individual STIX objects do not have their own STIX version in STIX
    2.0. A bundle has the property "spec\_version", which applies to all
    objects that are contained in the bundle.

Versioning
~~~~~~~~~~~~~~~~~~~

STIX 1.x supported the versioning of objects, but it was a feature that was rarely used.  STIX 2.0 support of
versioning is based on two newly introduced common properties: modified and revoked.  However, the elevator does not support
converting STIX 1.x versioned object, in the unlikely inclusion of such objects.

All converted objects will be assumed to be the one and only version of an object. If more than one object is found with
the same id, it will not be flagged as an error.

Relationships
--------------

All STIX 1.x relationships were defined explicitly in the specification and they are all embedded as properties of the object.
In STIX 2.0, relationships are top-level objects so they exist independently from their source and target objects.
Additionally, although the STIX 2.0 specification suggests certain relationships between object types,
a relationship between any two objects is allowed.

Relationships in STIX 1.x could be specified either using the idref property,
or by embedding the object within the relationship itself.  In the former case,
the STIX 2.0 object should use the original object's id as the source_ref property,
and the idref as the target_ref property.
In the latter case, the embedded object must first be converted to a top-level STIX 2.0 object.
Of course, the embedded object's id might not present.  In that case, an new id must be created.

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


STIX 2.0 in JSON

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
            .
            .
            .
    }

    {
            "id": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500"
            .
            .
            .
    }

Attack Pattern
------------------


**STIX 1.x Properties Mapped Directly to STIX 2.0 Properties**

+---------------------------+-------------------------------------------------------------------+
| **STIX 1.x property**     | **STIX 2.0 mapping**                                              |
+===========================+===================================================================+
| ttp:Kill\_Chain\_Phases   | kill\_chain\_phases                                               |
+---------------------------+-------------------------------------------------------------------+


**STIX 1.x Properties Translated to STIX 2.0 Properties**

+---------------------------+-------------------------------------------------------------------+
| **STIX 1.x property**     | **STIX 2.0 mapping**                                              |
+===========================+===================================================================+
| capec\_id                 |   external\_references                                            |
+---------------------------+-------------------------------------------------------------------+

**STIX 1.x Properties Mapped Using STIX 2.0 Relationships**

+---------------------------+-------------------------------------------------------------------+
| **STIX 1.x property**     | **STIX 2.0 mapping**                                              |
+===========================+===================================================================+
| ttp:Victim\_Targeting     | targets                                                           |
+---------------------------+-------------------------------------------------------------------+
| ttp:Exploit\_Targets      | targets (vulnerability, only)                                     |
+---------------------------+-------------------------------------------------------------------+
| ttp:Related\_TTPs         | uses (malware, tool), related-to (when not used for versioning)   |
+---------------------------+-------------------------------------------------------------------+

**STIX 1.x Properties Recorded in the STIX 2.0 Description Property**

- ttp:Intended\_Effect

**STIX 1.x Properties Not Mapped**

- ttp:Kill\_Chains

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

STIX 2.0 in JSON

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

See Threat Actor section for the Identity object.

Campaigns
----------------

**STIX 1.x Properties Mapped Directly to STIX 2.0 Properties**

+-------------------------+------------------------+
| **STIX 1.x property**   | **STIX 2.0 mapping**   |
+=========================+========================+
| Names                   |   aliases              |
+-------------------------+------------------------+

**STIX 1.x Properties Translated to STIX 2.0 Properties**

+-------------------------+------------------------+
| **STIX 1.x property**   | **STIX 2.0 mapping**   |
+=========================+========================+
| Intended\_Effect        |   objective            |
+-------------------------+------------------------+

**​STIX 1.x Properties Mapped Using STIX 2.0 Relationships**

+-------------------------+---------------------------------------------+
| **STIX 1.x property**   | **STIX 2.0 mapping**                        |
+=========================+=============================================+
| Related\_TTPs           | uses                                        |
+-------------------------+---------------------------------------------+
| Related\_Indicators     | indicates (reverse)                         |
+-------------------------+---------------------------------------------+
| Attribution             | attributed-to                               |
+-------------------------+---------------------------------------------+
| Associated\_Campaigns   | related-to (when not used for versioning)   |
+-------------------------+---------------------------------------------+

**STIX 1.x Properties Recorded in the STIX 2.0 Description Property**

-  Status

**STIX 1.x Properties Not Mapped**

-  Activity

-  Related\_Incidents

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
     <stixCommon:Role
        xsi:type="stixVocabs:InformationSourceRoleVocab-1.0">Initial Author</stixCommon:Role>
       </campaign:Information_Source>
    </stix:Campaign>

STIX 2.0 in JSON

.. code-block:: json


    {
        "type": "identity",
        "id": "identity--f690c992-8e7d-4b9a-9303-3312616c0220",
        "created": "2016-08-08T15:50:10.983Z",
        "modified": "2016-08-08T15:50:10.983Z",
        "name": "The MITRE Corporation - DHS Support Team",
        "identity_class": "organization"
    },

    {
        "type": "identity",
        "id": "identity--ddfe7140-2ba4-48e4-b19a-df069432103b",
        "created_by_ref": "identity--f690c992-8e7d-4b9a-9303-3312616c0220",
        "created": "2016-08-08T15:50:10.983Z",
        "modified": "2016-08-08T15:50:10.983Z",
        "name": "Branistan Peoples Party",
        "identity_class": "organization"
    },

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

See Threat Actor section for the Threat Actor object.

Course of Action
----------------------

In STIX 2.0 the course-of-action object is defined as a stub. This means that in STIX
2.0 this object type is pretty "bare-bones", not containing most of the
properties that were found in STIX 1.x. The property action is
reserved, but not defined in STIX 2.0.

**STIX 1.x Properties Mapped Directly to STIX 2.0 Properties**

*none*

**STIX 1.x Properties Translated to STIX 2.0 Properties**

*none*

**STIX 1.x Properties Mapped Using STIX 2.0 Relationships**

+------------------------------+---------------------------------------------+
| **STIX 1.x property**        | **STIX 2.0 mapping**                        |
+==============================+=============================================+
|     Related\_COAs            | related-to (when not used for versioning)   |
+------------------------------+---------------------------------------------+

**STIX 1.x Properties Recorded in the STIX 2.0 Description Property**

 - Stage
 - Objective
 - Impact
 - Cost
 - Efficacy

**STIX 1.x Properties Not Mapped**

 - Parameter\_Observables
 - Structured\_COA
 - Action

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

STIX 2.0 in JSON

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

Indicator
------------------

STIX 1.x Composite Indicator Expressions and CybOX 2.x Composite
Observable Expressions allow a level of flexibility not present in STIX
2 patterns. These composite expressions can frequently have ambiguous
interpretations, so STIX 2 Indicators created by the stix2-elevator from
STIX 1.x Indicators containing composite expressions should be inspected
to ensure the STIX 2 Indicator has the intended meaning.

**STIX 1.x Properties Mapped Directly to STIX 2.0 Properties**

+-------------------------+---------------------------------------------+
| **STIX 1.x property**   | **STIX 2.0 mapping**                        |
+=========================+=============================================+
| Valid\_Time\_Position   |   valid\_from, valid\_until                 |
+-------------------------+---------------------------------------------+
| Kill\_Chain\_Phases     |   kill\_chain\_phases                       |
+-------------------------+---------------------------------------------+
| Producer                |   created\_by\_ref                          |
+-------------------------+---------------------------------------------+

**STIX 1.x Properties Translated to STIX 2.0 Properties**

+-------------------------+---------------------------------------------+
| **STIX 1.x property**   | **STIX 2.0 mapping**                        |
+=========================+=============================================+
| Alternative\_ID         |   external\_references                      |
+-------------------------+---------------------------------------------+
| IndicatorExpression     |   pattern                                   |
+-------------------------+---------------------------------------------+

**STIX 1.x Properties Mapped Using STIX 2.0 Relationships**

+-------------------------+---------------------------------------------+
| **STIX 1.x property**   | **STIX 2.0 mapping**                        |
+=========================+=============================================+
| Indicated\_TTP          | detects                                     |
+-------------------------+---------------------------------------------+
| Suggested\_COAs         | related-to                                  |
+-------------------------+---------------------------------------------+
| Related\_Indicators     | related-to (when not used for versioning)   |
+-------------------------+---------------------------------------------+
| Related\_Campaigns      | indicates                                   |
+-------------------------+---------------------------------------------+

**STIX 1.x Properties Recorded in the STIX 2.0 Description Property**

*none*

**STIX 1.x Properties Not Mapped**

- negate
- Test\_Mechanisms
- Likely\_Impact

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

STIX 2.0 in JSON

.. code-block:: json

    {
       "created": "2017-01-27T13:49:53.935Z",
       "id": "indicator--d81f86b9-975b-bc0b-775e-810c5ad45a4f",
       "labels": [
           "url-watchlist"
       ],
       "modified": "2017-01-27T13:49:53.935Z",
       "name": "Malicious site hosting downloader",
       "pattern": "[url:value = 'http://x4z9arb.cn/4712']",
       "type": "indicator",
       "valid_from": "2017-01-27T13:49:53.935382Z"
    }

**Sightings**

In STIX 1.x sightings were a property of
IndicatorType. In STIX 2.0, sightings are a top-level STIX *relationship*
object. Because they represent the relationship (match) of an indicator
pattern to observed data (or other object), they are more naturally
represented as an STIX 2.0 relationship.

For example, suppose the above indicator pattern was matched against an actual cyber observable
("observed-data--b67d30ff-02ac-498a-92f9-32f845f448cf"), because a victim (whose
identity is represented by "identity--b67d30ff-02ac-498a-92f9-32f845f448ff") observed that URL.

The STIX 2.0 sighting would be:

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


Malware
-------------

The Malware object in STIX 2.0 is a stub.  STIX 2.0 does not support the inclusion of MAEC content.
The main properties of malware in STIX 2.0 are not much different than the defined ones in 1.x,
however, because of the lack of the ability to include the MAEC content fewer details of
malware are representable in STIX 2.0.

**STIX 1.x Properties Mapped Directly to STIX 2.0 Properties**

*none*

**STIX 1.x Properties Translated to STIX 2.0 Properties**

+---------------------------+--------------------------------------------------------------------------------+
| **STIX 1.x property**     | **STIX 2.0 mapping**                                                           |
+===========================+================================================================================+
| ttp:Kill\_Chain\_Phases   |   kill\_chain\_phases                                                          |
+---------------------------+--------------------------------------------------------------------------------+

**STIX 1.x Properties Mapped Using STIX 2.0 Relationships**

+---------------------------+--------------------------------------------------------------------------------+
| **STIX 1.x property**     | **STIX 2.0 mapping**                                                           |
+===========================+================================================================================+
| ttp:Related\_TTPs         | variant-of (malware), related-to (when not used for versioning), uses (tool)   |
+---------------------------+--------------------------------------------------------------------------------+
| ttp:Exploit\_Targets      | targets (vulnerability, only)                                                  |
+---------------------------+--------------------------------------------------------------------------------+
| ttp:Victim\_Targeting     | targets                                                                        |
+---------------------------+--------------------------------------------------------------------------------+

**STIX 1.x Properties Recorded in the STIX 2.0 Description Property**

 - ttp:Intended\_Effect

**STIX 1.x Properties Not Mapped**

 - ttp:Kill\_Chains

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

STIX 2.0 in JSON

.. code-block:: json

    {
       "created": "2017-01-27T13:49:53.997Z",
       "description": "\n\nTITLE:\n\tPoison Ivy",
       "id": "malware--fdd60b30-b67c-11e3-b0b9-f01faf20d111",
       "labels": [
           "remote-access-trojan"
       ],
       "modified": "2017-01-27T13:49:53.997Z",
       "name": "Poison Ivy",
       "type": "malware"
    }

Observed Data
--------------

The Observed Data object in STIX 2.0 corresponds to the Observable
object in STIX 1.x. Each Observed Data objects contain one or more
*related* cyber observable objects.

STIX 2.0 adds two properties: first_observed and last_observed.
These properties are related to the number_observed property, because it is possible for
Observed Data to indicate that either one, or multiple instances of the same cyber observable occurred.
If the number_observed property is 1, then the first_observed and last_observed properties
contain the same timestamp, otherwise they are the timestamp of the first and last times that cyber observable occurred.

The sighting_count property may seem to be the same concept as number_observed property,
but because STIX 2.0 has made explicit the difference between sightings and observed data,
this is not the case.  The sightings count is captured on the Sighting SRO.


**STIX 1.x Properties Mapped Directly to STIX 2.0 Properties**

+--------------------------+------------------------------------------------+
| **STIX 1.x property**    | **STIX 2.0 mapping**                           |
+==========================+================================================+
| sighting\_count          | not to be confused with **number\_observed**   |
+--------------------------+------------------------------------------------+
| Keywords                 | **labels**                                     |
+--------------------------+------------------------------------------------+


​**STIX 1.x Properties Translated to STIX 2.0 Properties**

+--------------------------+------------------------------------------------+
| **STIX 1.x property**    | **STIX 2.0 mapping**                           |
+==========================+================================================+
| Observable\_Source       | **created\_by\_ref**                           |
+--------------------------+------------------------------------------------+
| Object                   | **objects**                                    |
+--------------------------+------------------------------------------------+

**STIX 1.x Properties Mapped Using STIX 2.0 Relationships**

*none*

**STIX 1.x Properties Recorded in the STIX 2.0 Description Property**

*none*

**STIX 1.x Properties Not Mapped**

- negate
- Event
- Title
- Description
- Pattern\_Fidelity

**An Example**

STIX 1.x in XML

.. code-block:: xml

    <cybox:Observable id="example:observable-c8c32b6e-2ea8-51c4-6446-7f5218072f27">
       <cybox:Object id="example:object-d7fcce87-0e98-4537-81bf-1e7ca9ad3734">
            <cybox:Properties xsi:type="FileObj:FileObjectType">
                <FileObj:File_Name>iprip32.dll</FileObj:File_Name>
                <FileObj:File_Path>/usr/local</FileObj:File_Path>
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
               "file_name": "iprip32.dll",
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

In STIX 2.0 cyber observables are only used within observed data to
represent something that has actually been seen.  If a STIX 1.x Observable is contained in an Indicator, it is instead
expressing a pattern to match against observed data.

The pattern expression to match the example cyber observable, when it is located in an indicator object, would be:

.. code::

    [(file:file_name = 'iprip32.dll' AND file:parent_directory_ref.path = '/usr/local')]


Report
--------

The Report object does not contain objects, but only object references
to STIX objects that are specified elsewhere (the location of the actual
objects may not be contained in the same bundle that contains the report
object). In STIX 2.0, properties that were associated with the report
header in STIX 1.x are located in the report object itself. The
**labels** property contains vocabulary literals similar to the ones
contain in the Intent property in STIX 1.x.

**STIX 1.x Properties Mapped Directly to STIX 2.0 Properties**

*none*

**STIX 1.x Properties Translated to STIX 2.0 Properties**

+-------------------------+--------------------------------------------------+
| **STIX 1.x property**   | **STIX 2.0 mapping**                             |
+=========================+==================================================+
| Observables             | object\_refs                                     |
+-------------------------+--------------------------------------------------+
| Indicators              | object\_refs                                     |
+-------------------------+--------------------------------------------------+
| TTPs                    | object\_refs                                     |
+-------------------------+--------------------------------------------------+
| Exploit\_Targets        | object\_refs                                     |
+-------------------------+--------------------------------------------------+
| Incidents               | object\_refs                                     |
+-------------------------+--------------------------------------------------+
| Courses\_Of\_Action     | object\_refs                                     |
+-------------------------+--------------------------------------------------+
| Campaigns               | object\_refs                                     |
+-------------------------+--------------------------------------------------+
| Threat\_Actors          | object\_refs                                     |
+-------------------------+--------------------------------------------------+


​**STIX 1.x Properties Mapped Using STIX 2.0 Relationships**

+-------------------------+--------------------------------------------------+
| **STIX 1.x property**   | **STIX 2.0 mapping**                             |
+=========================+==================================================+
| Related\_Reports        | related-to (when not used for versioning)        |
+-------------------------+--------------------------------------------------+

Threat Actor
------------------

**STIX 1.x Properties Mapped Directly to STIX 2.0 Properties**

*none*


**STIX 1.x Properties Translated to STIX 2.0 Properties**

+-------------------------------------+--------------------------------------------------------------------------+
| **STIX 1.x property**               | **STIX 2.0 mapping**                                                     |
+=====================================+==========================================================================+
| Identity                            |   name, aliases, roles                                                   |
+-------------------------------------+--------------------------------------------------------------------------+
| Motivation                          |   primary\_motivation, secondary\_motivations, personal\_motivations     |
+-------------------------------------+--------------------------------------------------------------------------+
| Sophistication                      |   sophistication                                                         |
+-------------------------------------+--------------------------------------------------------------------------+

​**STIX 1.x Properties Mapped Using STIX 2.0 Relationships**

+-------------------------+---------------------------------------------+
| **STIX 1.x property**   | **STIX 2.0 mapping**                        |
+=========================+=============================================+
| Observed\_TTPs          | uses                                        |
+-------------------------+---------------------------------------------+
| Associated\_Campaigns   | attributed-to (reverse)                     |
+-------------------------+---------------------------------------------+
| Associated\_Actors      | related-to (when not used for versioning)   |
+-------------------------+---------------------------------------------+

**STIX 1.x Properties Recorded in the STIX 2.0 Description Property**

- Intended\_Effect

- Planning\_And\_Operational\_Support


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


STIX 2.0 in JSON

.. code-block:: json

    {
          "type": "threat-actor",
          "id": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500",
          "created_by_ref": "identity--f690c992-8e7d-4b9a-9303-3312616c0220",
          "created": "2016-08-08T15:50:10.983Z",
          "modified": "2016-08-08T15:50:10.983Z",
          "labels": ["nation-state"],
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

Tool
-------

**STIX 1.x Properties Mapped Directly to STIX 2.0 Properties**

+---------------------------------------+--------------------------------------------------------------------------------------------------+
| **STIX 1.x property**                 | **STIX 2.0 mapping**                                                                             |
+=======================================+==================================================================================================+
| Name (from CybOX)                     |   name                                                                                           |
+---------------------------------------+--------------------------------------------------------------------------------------------------+
| Type (from CybOX)                     |   labels                                                                                         |
+---------------------------------------+--------------------------------------------------------------------------------------------------+
| Description (from CybOX)              |   description                                                                                    |
+---------------------------------------+--------------------------------------------------------------------------------------------------+
| Version (from CybOX)                  |   tool\_version                                                                                  |
+---------------------------------------+--------------------------------------------------------------------------------------------------+
| ttp:Kill\_Chain\_Phases               |   kill\_chain\_phases                                                                            |
+---------------------------------------+--------------------------------------------------------------------------------------------------+


​**STIX 1.x Properties Translated to STIX 2.0 Properties**

+---------------------------------------+--------------------------------------------------------------------------------------------------+
| **STIX 1.x property**                 | **STIX 2.0 mapping**                                                                             |
+=======================================+==================================================================================================+
| References (from CybOX)               |   external\_references                                                                           |
+---------------------------------------+--------------------------------------------------------------------------------------------------+


​**STIX 1.x Properties Mapped Using STIX 2.0 Relationships**

+---------------------------------------+--------------------------------------------------------------------------------------------------+
| **STIX 1.x property**                 | **STIX 2.0 mapping**                                                                             |
+=======================================+==================================================================================================+
| ttp:Related\_TTPs                     | uses (attack-pattern) (reverse), related-to (when not used for versioning), targets (identity)   |
+---------------------------------------+--------------------------------------------------------------------------------------------------+

**STIX 1.x Properties Recorded in the STIX 2.0 Description Property**

- ttp:Intended\_Effect

**STIX 1.x Properties Not Mapped**

- Compensation\_Model (from CybOX)
- Errors (from CybOX)
- Execution\_Environment (from CybOX)
- ttp:Exploit\_Targets
- ttp:Kill\_Chains
- Metadata (from CybOX)
- Service\_Pack (from CybOX)
- Tool\_Configuration (from CybOX)
- Tool\_Hashes (from CybOX)
- Tool\_Specific\_Data (from CybOX)
- Vendor (from CybOX)
- ttp:Victim\_Targeting

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


STIX 2.0 in JSON

.. code-block:: json

    {
      "type": "tool",
      "id": "tool--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
      "created": "2016-04-06T20:03:48.000Z",
      "modified": "2016-04-06T20:03:48.000Z",
      "labels": [ "remote-access"],
      "version": "6.03",
      "name": "VNCConnect"
    }

Vulnerability
------------------

**STIX 1.x Properties Mapped Directly to STIX 2.0 Properties**

*none*

**STIX 1.x Properties Translated to STIX 2.0 Properties**


+-----------------------------------+---------------------------------------------------------------------+
| **STIX 1.x property**             | **STIX 2.0 mapping**                                                |
+===================================+=====================================================================+
| CVE\_ID                           |   external\_references                                              |
+-----------------------------------+---------------------------------------------------------------------+
| OSVDB\_ID                         |   external\_references                                              |
+-----------------------------------+---------------------------------------------------------------------+
| Source                            |   external\_references                                              |
+-----------------------------------+---------------------------------------------------------------------+
| References                        |   external\_references                                              |
+-----------------------------------+---------------------------------------------------------------------+


**​STIX 1.x Properties Mapped Using STIX 2.0 Relationships**


+-------------------------------------------+-------------------------------------------+
| **STIX 1.x property**                     | **STIX 2.0 mapping**                      |
+===========================================+===========================================+
| Exploit\_Target:Potential\_COAs           | mitigates (reverse)                       |
+-------------------------------------------+-------------------------------------------+
| Exploit\_Target:Related\_Exploit\_Targets | related-to (when not used for versioning) |
+-------------------------------------------+-------------------------------------------+


**STIX 1.x Properties Recorded in the STIX 2.0 Description Property**


*none*

**STIX 1.x Properties Not Mapped**


- is\_known
- is\_publicly\_acknowledged
- CVSS\_Score
- Discovered\_DateTime
- Published\_DateTime
- Affected\_Software

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

STIX 2.0 in JSON

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
