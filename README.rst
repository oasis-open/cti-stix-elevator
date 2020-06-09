|Build_Status| |Coverage| |Version| |Documentation_Status|

cti-stix-elevator
=================

NOTE: This is an `OASIS TC Open
Repository <https://www.oasis-open.org/resources/open-
repositories/>`_.
See the `Governance`_ section for more information.

The stix2-elevator is a software tool for converting STIX 1.x XML to
STIX
2.0 or 2.1 JSON. Due to the differences between STIX 1.x and STIX 2.x, this
conversion is best-effort only. During the conversion, stix2-
elevator
provides information on the assumptions it needs to make to produce
valid STIX
2.x JSON, and what information was not able to be converted.

To convert STIX 2.x JSON back to STIX 1.x XML use the `stix2-slider`

The stix2-elevator is a "best-effort" attempt to convert STIX 1.x content to STIX 2.x content.
**Caution should be taken if the elevator is to be used in a production environment as warnings
concerning the conversion are often generated.**  Users should determine which warnings are
acceptable and use the --disable option in conjunction with the –error-policy option only to produce
results when no other warnings are emitted.

**STIX 1.x Composite Indicator Expressions and CybOX 2.x Composite
Observable Expressions allow a level of flexibility not present in
STIX
2 patterns. These composite expressions can frequently have ambiguous
interpretations, so STIX 2 Indicators created by the stix2-elevator
from
STIX 1.x Indicators containing composite expressions should be
inspected
to ensure the STIX 2 Indicator has the intended meaning.**

For more information, see `the
documentation <https://stix2-elevator.readthedocs.io/>`__ on
ReadTheDocs.

Please enter any comments on how to improve the elevator into the issue tracker.

Requirements
------------

- Python 3.5+
- `python-stix <https://stix.readthedocs.io/en/stable/>`_ and its dependencies

  .. note::

      Make sure to use either the latest version of python-stix 1.1.1.x or
      1.2.0.x, depending on whether you want to support STIX 1.1.1 or STIX 1.2.

-  `python-stix2 <https://pypi.org/project/stix2/>`_ >= 1.4.0
-  `stix2-validator <https://pypi.org/project/stix2-validator/>`_ >= 2.0.0.dev3
   and its dependencies
-  `pycountry <https://pypi.org/project/pycountry/>`_ >= 19.8.18
-  `stixmarx <https://pypi.org/project/stixmarx/>`_ >= 1.0.6

Installation
------------

Install with pip

.. code-block:: bash

    $ pip install stix2-elevator

This will install all necessary dependencies, including the latest
version of python-stix.

If you need to support older STIX 1.1.1 content, install python-stix
1.1.1.x first

.. code-block:: bash

    $ pip install 'stix<1.2'
    $ pip install stix2-elevator

You can also install the stix2-elevator from GitHub to get the latest
(unstable) version

.. code-block:: bash

    $ pip install git+https://github.com/oasis-open/cti-stix-elevator.git

Usage
-----

It is recommended that you ensure that the input STIX 1.x file is
valid before submitting it to the elevator.
Use the `stix-validator <https://pypi.org/project/stix-validator/>`_.

As A Script
~~~~~~~~~~~

The elevator comes with a bundled script which you can use to elevate
STIX 1.1.1 - 1.2.1 content to STIX 2.0 or 2.1 content:

.. code-block:: text

  usage: stix2_elevator [-h]
              [--missing-policy {use-custom-properties,add-to-description,ignore}]
              [--custom-property-prefix CUSTOM_PROPERTY_PREFIX]
              [--infrastructure]
              [--incidents]
              [--package-created-by-id PACKAGE_CREATED_BY_ID]
              [--default-timestamp DEFAULT_TIMESTAMP]
              [--validator-args VALIDATOR_ARGS]
              [-e ENABLED]
              [-d DISABLED]
              [-s]
              [--message-log-directory MESSAGE_LOG_DIRECTORY]
              [--log-level {DEBUG,INFO,WARN,ERROR,CRITICAL}]
              [-m MARKINGS_ALLOWED]
              [-p {no_policy,strict_policy}]
              [-v {2.0,2.1}]
              file

stix2-elevator v2.1.1



positional arguments:

.. code-block:: text

  file                  The input STIX 1.x document to be elevated.

optional arguments:

.. code-block:: text

  -h, --help            show this help message and exit

  --missing-policy {use-custom-properties,add-to-description,ignore}
                        Policy for including STIX 1.x content that cannot be
                        represented directly in STIX 2.x. The default is 'add-
                        to-description'.

  --custom-property-prefix CUSTOM_PROPERTY_PREFIX
                        Prefix to use for custom property names when missing
                        policy is 'use-custom-properties'. The default is
                        'elevator'.

  --infrastructure      Infrastructure will be included in the conversion.
                        Default for version 2.1 is true.

  --incidents           Incidents will be included in the conversion. **This argument is deprecated.**

  --package-created-by-id PACKAGE_CREATED_BY_ID
                        Use provided identifier for "created_by_ref"
                        properties. Example: --package-created-by-id "identity
                        --1234abcd-1a12-42a3-0ab4-1234abcd5678"

  --default-timestamp DEFAULT_TIMESTAMP
                        Use provided timestamp for properties that require a
                        timestamp. Example: --default-timestamp
                        "2016-11-15T13:10:35.053000Z"

  --validator-args VALIDATOR_ARGS
                        Arguments to pass to stix2-validator. Default:
                        --strict-types Example: stix2_elevator.py <file>
                        --validator-args="-v --strict-types -d 212"

  -e ENABLED, --enable ENABLED
                        A comma-separated list of the stix2-elevator messages
                        to enable. If the --disable option is not used, no
                        other messages will be shown. Example:
                        stix2_elevator.py <file> --enable 250

  -d DISABLED, --disable DISABLED
                        A comma-separated list of the stix2-elevator messages
                        to disable. Example: stix2_elevator.py <file>
                        --disable 212,220

  -s, --silent          If this flag is set, all stix2-elevator messages will
                        be disabled.

  --message-log-directory MESSAGE_LOG_DIRECTORY
                        If this flag is set, all stix2-elevator messages will
                        be saved to file. The name of the file will be the
                        input file with extension .log in the specified
                        directory. Note, make sure the directory already
                        exists. Example: stix2_elevator.py <file> --message-
                        log-directory "../logs"

  --log-level {DEBUG,INFO,WARN,ERROR,CRITICAL}
                        The logging output level.

  -m MARKINGS_ALLOWED, --markings-allowed MARKINGS_ALLOWED
                        Avoid an error exit, if these markings are in the
                        content, but not supported by the elevator. Specify as
                        a comma-separated listExample: stix2_elevator.py <
                        file > --markings-allowed
                        "ISAMarkingsAssertion,ISAMarkings"

  -p {no_policy,strict_policy},
  --error-policy {no_policy,strict_policy},
  --policy {no_policy,strict_policy}   #deprecated
                        The policy to deal with errors. The default is 'no_policy'.

  -v {2.0,2.1}, --version {2.0,2.1}
                        The version of stix 2 to be produced. The default is
                        2.1

Refer to elevator_log_messages.rst for all stix2-elevator messages. Use the
associated code number to --enable or --disable a message. By default, the
stix2-elevator displays all messages. Note: disabling the message does not
disable the functionality.

As A Library
~~~~~~~~~~~~

You can also use this library to integrate STIX elevation into your own tools.

.. code-block:: python

    # Elevate a STIX 1.x via filename
    from stix2elevator import elevate
    from stix2elevator.options import initialize_options

    initialize_options()
    results = elevate("stix_file.xml")
    print(results)

The same method can also accept a string as an argument.

.. code-block:: python

    # Elevate a STIX 1.x via string
    from stix2elevator import elevate
    from stix2elevator.options import initialize_options

    initialize_options()
    results = elevate("<stix:Package...")
    print(results)

To set options, use set_option_value, found in options.py

Using the stepper
~~~~~~~~~~~~~~~~~

The stix-stepper is a simple script that will convert STIX 2.0 content to STIX 2.1 content.

You can invoke it as follows.

.. code-block:: bash

    $ stix_stepper <2.0 file>

The 2.1 content is printed to stdout

Governance
----------

This GitHub public repository (
**https://github.com/oasis-open/cti-stix-elevator** ) was
`proposed <https://lists.oasis-
open.org/archives/cti/201610/msg00106.html>`__
and
`approved <https://lists.oasis-
open.org/archives/cti/201610/msg00126.html>`__
[`bis <https://issues.oasis-open.org/browse/TCADMIN-2477>`__] by the
`OASIS Cyber Threat Intelligence (CTI)
TC <https://www.oasis-open.org/committees/cti/>`__ as an `OASIS TC
Open Repository <https://www.oasis-open.org/resources/open-
repositories/>`__
to support development of open source resources related to Technical
Committee work.

While this TC Open Repository remains associated with the sponsor TC,
its
development priorities, leadership, intellectual property terms,
participation rules, and other matters of governance are `separate and
distinct <https://github.com/oasis-open/cti-stix-
elevator/blob/master/CONTRIBUTING.md#governance-distinct-from-oasis-
tc-process>`__
from the OASIS TC Process and related policies.

All contributions made to this TC Open Repository are subject to open
source license terms expressed in the `BSD-3-Clause
License <https://www.oasis-open.org/sites/www.oasis-
open.org/files/BSD-3-Clause.txt>`__.
That license was selected as the declared `"Applicable
License" <https://www.oasis-open.org/resources/open-
repositories/licenses>`__
when the TC Open Repository was created.

As documented in `"Public Participation
Invited <https://github.com/oasis-open/cti-stix-
elevator/blob/master/CONTRIBUTING.md#public-participation-
invited>`__",
contributions to this OASIS TC Open Repository are invited from all
parties, whether affiliated with OASIS or not. Participants must have
a
GitHub account, but no fees or OASIS membership obligations are
required. Participation is expected to be consistent with the `OASIS
TC Open Repository Guidelines and
Procedures <https://www.oasis-open.org/policies-guidelines/open-
repositories>`__,
the open source
`LICENSE <https://github.com/oasis-open/cti-stix-
elevator/blob/master/LICENSE>`__
designated for this particular repository, and the requirement for an
`Individual Contributor License
Agreement <https://www.oasis-open.org/resources/open-
repositories/cla/individual-cla>`__
that governs intellectual property.

Maintainers
~~~~~~~~~~~

TC Open Repository
`Maintainers <https://www.oasis-open.org/resources/open-
repositories/maintainers-guide>`__
are responsible for oversight of this project's community development
activities, including evaluation of GitHub `pull
requests <https://github.com/oasis-open/cti-stix-
elevator/blob/master/CONTRIBUTING.md#fork-and-pull-collaboration-
model>`__
and
`preserving <https://www.oasis-open.org/policies-guidelines/open-
repositories#repositoryManagement>`__
open source principles of openness and fairness. Maintainers are
recognized and trusted experts who serve to implement community goals
and consensus design preferences.

Initially, the associated TC members have designated one or more
persons
to serve as Maintainer(s); subsequently, participating community
members
may select additional or substitute Maintainers, per `consensus
agreements <https://www.oasis-open.org/resources/open-
repositories/maintainers-guide#additionalMaintainers>`__.

**Current Maintainers of this TC Open Repository**

-  `Chris Lenk <mailto:clenk@mitre.org>`__; GitHub ID:
   https://github.com/clenk/; WWW: `MITRE <https://www.mitre.org/>`__
-  `Rich Piazza <mailto:rpiazza@mitre.org>`__; GitHub ID:
   https://github.com/rpiazza/; WWW: `MITRE
   <https://www.mitre.org/>`__
-  `Jason Keirstead <mailto:Jason.Keirstead@ca.ibm.com>`__; GitHub ID:
   https://github.com/JasonKeirstead; WWW: `IBM <http://www.ibm.com/>`__

About OASIS TC Open Repositories
--------------------------------

-  `TC Open Repositories: Overview and
   Resources <https://www.oasis-open.org/resources/open-
   repositories/>`__
-  `Frequently Asked
   Questions <https://www.oasis-open.org/resources/open-
   repositories/faq>`__
-  `Open Source
   Licenses <https://www.oasis-open.org/resources/open-
   repositories/licenses>`__
-  `Contributor License Agreements
   (CLAs) <https://www.oasis-open.org/resources/open-
   repositories/cla>`__
-  `Maintainers' Guidelines and
   Agreement <https://www.oasis-open.org/resources/open-
   repositories/maintainers-guide>`__

Feedback
--------

Questions or comments about this TC Open Repository's activities
should be
composed as GitHub issues or comments. If use of an issue/comment is
not
possible or appropriate, questions may be directed by email to the
Maintainer(s) `listed above <#currentMaintainers>`__. Please send
general questions about TC Open Repository participation to OASIS
Staff at
repository-admin@oasis-open.org and any specific CLA-related questions
to repository-cla@oasis-open.org.

.. |Build_Status| image:: https://travis-ci.org/oasis-open/cti-stix-elevator.svg?branch=master
   :target: https://travis-ci.org/oasis-open/cti-stix-elevator
.. |Coverage| image:: https://codecov.io/gh/oasis-open/cti-stix-elevator/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/oasis-open/cti-stix-elevator
.. |Version| image:: https://img.shields.io/pypi/v/stix2-elevator.svg?maxAge=3600
   :target: https://pypi.org/project/stix2-elevator/
.. |Documentation_Status| image:: https://readthedocs.org/projects/stix2-elevator/badge/?version=latest
   :target: https://stix2-elevator.readthedocs.io/en/latest/
   :alt: Documentation Status
