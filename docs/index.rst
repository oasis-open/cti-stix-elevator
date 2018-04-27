Welcome to stix2-elevator's documentation!
==========================================

The stix2-elevator is a software tool for converting STIX 1.x XML to STIX
2.0 JSON. Due to the differences between STIX 1.x and STIX 2.0, this
conversion is best-effort only, and stix2-elevator cannot convert from
STIX 2.0 JSON back to STIX 1.x XML. During the conversion, stix2-elevator
provides information on the assumptions it needs to make to produce valid STIX
2.0 JSON, and what information was not able to be converted.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   intro
   install
   command-line
   stix-mappings
   cyber-observables
   conversion-issues
   warnings


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
