stix-elevator
=============

A Python library for upgrading Structured Threat Information eXpression (STIX) and Cyber Observable eXpression (CybOX) to STIX 2.0.


`Requirements`
,,,,,,,,,,,,,,

For STIX 1.1.1 content;

* Python 2.6/2.7
* python-stix = 1.1.1.6 (other dependencies inherited from python-stix)
 

For STIX 1.2 content:

* Python 3.5
* python-stix >= 1.2.0.0 (other dependencies inherited from python-stix)

For both:

* stix2validator (with all of its dependencies:  jsonschema, colorama, nose, tox
* pycountry >= 1.20


`Installation`
,,,,,,,,,,,,,,

Clone the following repositories, or download the zip files and unzip:

* stix-elevator (https://github.com/oasis-open/cti-stix-elevator)
* cti-stix-validator (https://github.com/oasis-open/cti-stix-validator)

**Install stix2validator**

  $ cd cti-stix-validator
  $ python setup.py install

.. _usage:

`Usage`
,,,,,,,

**As A Script**

The validator comes with a bundled script which you can use to validate a JSON file containing STIX content:

::

  $ stix2_validator <stix_file.json>

**As A Library**

You can also use this library to integrate STIX validation into your own tools. You can validate a JSON file:

.. code:: python

  from elevator import convert_file

  results = validate_file("stix_file.xml")
  print(results)

