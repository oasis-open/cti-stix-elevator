Welcome to stix2-elevator's documentation!
==========================================

The stix2-elevator is a software tool for converting STIX 1.x XML to STIX
2.x JSON. Due to the differences between STIX 1.x and STIX 2.x, this
conversion is best-effort only,  During the conversion, stix2-elevator
provides information on the assumptions it needs to make to produce valid STIX
2.x JSON, and what information was not able to be converted.

To convert STIX 2.x JSON back to STIX 1.x XML use the `stix2-slider <https://http://stix2-slider.readthedocs.io/en/stable/>`_.

For more information about STIX 2, see the
`website <http://cti-tc.github.io>`_ of the OASIS Cyber Threat Intelligence
Technical Committee.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   intro
   install
   command-line
   stix-mappings
   cyber-observables
   vocabularies
   conversion-issues
   warnings


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
