# cti-stix-elevator

*This is an [OASIS Open Repository](https://www.oasis-open.org/resources/open-repositories/). See the [Governance](#governance) section for more information.*

The stix-elevator is a software tool for converting STIX 1.2 XML to STIX 2.0 JSON. Due to the differences between STIX 1.2 and STIX 2.0, this conversion is best-effort only, and stix-elevator cannot convert from STIX 2.0 back to STIX 1.2. During the conversion, stix-elevator provides information on the assumptions it needs to make to produce valid STIX 2.0 JSON, and what information was not able to be converted.

The stix-elevator is a work-in-progress.  It should be used to explore how existing STIX 1.x would potentially be represented in STIX 2.0.  Using the current version of the elevator will provide insight to issues that might need to be mitigated to convert your STIX 1.x content.

**_It should not be used in a production environment, and should not be considered final._**

**_STIX 1.x Composite Indicator Expressions and CybOX 2.x Composite Observable Expressions allow a level of flexibility not present in STIX 2 patterns. These composite expressions can frequently have ambiguous interpretations, so STIX 2 Indicators created by the stix-elevator from STIX 1.x Indicators containing composite expressions should be inspected to ensure the STIX 2 Indicator has the intended meaning._**

Please enter any comments on how to improve it into the issue tracker.

## Requirements

For STIX 1.1.1 content;

* Python 2.6/2.7
* python-stix >= 1.1.1.7 (other dependencies inherited from python-stix)

For STIX 1.2 content:

* Python 3.5
* python-stix >= 1.2.0.0 (other dependencies inherited from python-stix)

For both:

* stix2validator >= 0.1.0 (including its dependencies:  jsonschema, colorama, requests)
* pycountry >= 1.20


## Installation

stix-elevator should be installed using the git repository:

```
$ pip install git+https://github.com/oasis-open/cti-stix-elevator.git
```

This will install all necessary dependencies.

## Usage


### As A Script

The elevator comes with a bundled script which you can use to elevate STIX 1.1.1 - 1.2.1 content to STIX 2.0 content:

```
usage: stix_elevator.py [-h] [--incidents] [--no-squirrel-gaps]
                        [--infrastructure]
                        [--package-created-by-id PACKAGE_CREATED_BY_ID]
                        [--default-timestamp DEFAULT_TIMESTAMP]
                        [--validator-args VALIDATOR_ARGS] [-e ENABLE]
                        [-d DISABLE] [-s]
                        [--message-log-directory MESSAGE_LOG_DIRECTORY]
                        file

positional arguments:
  file                  The input STIX 1.x document to be elevated.

optional arguments:
  -h, --help            show this help message and exit

  --incidents           Incidents will be included in the conversion.

  --no-squirrel-gaps    Do not include STIX 1.x content that cannot be
                        represented directly in STIX 2.0 using the description
                        property.

  --infrastructure      Infrastructure will be included in the conversion.

  --package-created-by-id PACKAGE_CREATED_BY_ID
                        Use provided identifier for "created_by_ref"
                        properties.Example: --package-created-by-id "identity
                        --1234abcd-1a12-12a3-0ab4-1234abcd5678"

  --default-timestamp DEFAULT_TIMESTAMP
                        Use provided timestamp for properties that require a
                        timestamp. Example: --default-timestamp
                        "2016-11-15T13:10:35.053000Z"

  --validator-args VALIDATOR_ARGS
                        Arguments to pass stix-validator. Default: --strict-
                        types Example: stix_elevator.py <file> --validator-
                        args "-v --strict-types -d 212"

  -e ENABLE, --enable ENABLE
                        A comma-separated list of the elevator messages to
                        enable. If the --disable option is not used, no other
                        messages will be shown. Example: stix_elevator.py
                        <file> --enable 250

  -d DISABLE, --disable DISABLE
                        A comma-separated list of the elevator messages to
                        disable. Example: stix_elevator.py <file> --disable
                        212,220

  -s, --silent          If this flag is set. All elevator messages will be
                        disabled.

  --message-log-directory MESSAGE_LOG_DIRECTORY
                        If this flag is set. All elevator messages will be
                        saved to file. The name of the file will be the input
                        file with extension .log in the specified directory.
                        Note, make surethe directory already exists. Example:
                        stix_elevator.py <file> --message-log-directory
                        "..\logs"
```

Refer to elevator_log_messages.xlsx for error codes.

### As A Library

You can also use this library to integrate STIX elevation into your own tools. You can elevate a STIX 1.x file:

```
  from stix2elevator import elevate_file

  results = elevate_file("stix_file.xml")
  print(results)
```
Additionally, a similar method exists to accept a string as an argument:

```
  from stix2elevator import elevate_string

  results = elevate_string("...")
  print(results)
```

## Governance

This GitHub public repository ( **[https://github.com/oasis-open/cti-stix-elevator](https://github.com/oasis-open/cti-stix-elevator)** ) was [proposed](https://lists.oasis-open.org/archives/cti/201610/msg00106.html) and [approved](https://lists.oasis-open.org/archives/cti/201610/msg00126.html) [[bis](https://issues.oasis-open.org/browse/TCADMIN-2477)] by the [OASIS Cyber Threat Intelligence (CTI) TC](https://www.oasis-open.org/committees/cti/) as an [OASIS Open Repository](https://www.oasis-open.org/resources/open-repositories/) to support development of open source resources related to Technical Committee work.

While this Open Repository remains associated with the sponsor TC, its development priorities, leadership, intellectual property terms, participation rules, and other matters of governance are [separate and distinct](https://github.com/oasis-open/cti-stix-elevator/blob/master/CONTRIBUTING.md#governance-distinct-from-oasis-tc-process) from the OASIS TC Process and related policies.

All contributions made to this Open Repository are subject to open source license terms expressed in the [BSD-3-Clause License](https://www.oasis-open.org/sites/www.oasis-open.org/files/BSD-3-Clause.txt). That license was selected as the declared ["Applicable License"](https://www.oasis-open.org/resources/open-repositories/licenses) when the Open Repository was created.

As documented in ["Public Participation Invited](https://github.com/oasis-open/cti-stix-elevator/blob/master/CONTRIBUTING.md#public-participation-invited)", contributions to this OASIS Open Repository are invited from all parties, whether affiliated with OASIS or not. Participants must have a GitHub account, but no fees or OASIS membership obligations are required. Participation is expected to be consistent with the [OASIS Open Repository Guidelines and Procedures](https://www.oasis-open.org/policies-guidelines/open-repositories), the open source [LICENSE](https://github.com/oasis-open/cti-stix-elevator/blob/master/LICENSE) designated for this particular repository, and the requirement for an [Individual Contributor License Agreement](https://www.oasis-open.org/resources/open-repositories/cla/individual-cla) that governs intellectual property.

### <a id="maintainers">Maintainers</a>

Open Repository [Maintainers](https://www.oasis-open.org/resources/open-repositories/maintainers-guide) are responsible for oversight of this project's community development activities, including evaluation of GitHub [pull requests](https://github.com/oasis-open/cti-stix-elevator/blob/master/CONTRIBUTING.md#fork-and-pull-collaboration-model) and [preserving](https://www.oasis-open.org/policies-guidelines/open-repositories#repositoryManagement) open source principles of openness and fairness. Maintainers are recognized and trusted experts who serve to implement community goals and consensus design preferences.

Initially, the associated TC members have designated one or more persons to serve as Maintainer(s); subsequently, participating community members may select additional or substitute Maintainers, per [consensus agreements](https://www.oasis-open.org/resources/open-repositories/maintainers-guide#additionalMaintainers).

**<a id="currentMaintainers">Current Maintainers of this Open Repository</a>**

*   [Greg Back](mailto:gback@mitre.org); GitHub ID: [https://github.com/gtback/](https://github.com/gtback/); WWW: [MITRE](https://www.mitre.org/)
*   [Rich Piazza](mailto:rpiazza@mitre.org); GitHub ID: [https://github.com/rpiazza/](https://github.com/rpiazza/); WWW: [MITRE](https://www.mitre.org/)

## <a id="aboutOpenRepos">About OASIS Open Repositories</a>

*   [Open Repositories: Overview and Resources](https://www.oasis-open.org/resources/open-repositories/)
*   [Frequently Asked Questions](https://www.oasis-open.org/resources/open-repositories/faq)
*   [Open Source Licenses](https://www.oasis-open.org/resources/open-repositories/licenses)
*   [Contributor License Agreements (CLAs)](https://www.oasis-open.org/resources/open-repositories/cla)
*   [Maintainers' Guidelines and Agreement](https://www.oasis-open.org/resources/open-repositories/maintainers-guide)

## <a id="feedback">Feedback</a>

Questions or comments about this Open Repository's activities should be composed as GitHub issues or comments. If use of an issue/comment is not possible or appropriate, questions may be directed by email to the Maintainer(s) [listed above](#currentMaintainers). Please send general questions about Open Repository participation to OASIS Staff at [repository-admin@oasis-open.org](mailto:repository-admin@oasis-open.org) and any specific CLA-related questions to [repository-cla@oasis-open.org](mailto:repository-cla@oasis-open.org).
