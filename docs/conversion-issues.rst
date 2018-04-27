​Conversion Issues
=====================

This section discusses some suggestions to facilitate the conversion of
STIX 1.x data to STIX 2.0. These suggestions cover non-obvious issues
that might present an impediment to re-using STIX 1.x data.

Assumptions
-----------------

Timestamps, Identifiers and Object Creators
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In STIX 1.x most properties were optional. This includes properties that
correspond to required properties in STIX 2.0. In particular, all STIX
Objects in 2.0 are required to have **id**, **created** and **modified**
properties. These are often not specified in a STIX 1.x object, but can
be inferred from another STIX 1.x object in the same package.

Content in STIX 1.x was more hierarchical than content in STIX 2.0, and
this can help to determine required properties. For instance, a
timestamp on a STIX 1.x package could be construed as the timestamp for
all objects it contains. Likewise, an object could assume that its
parent object's timestamp is also the timestamp of that object, unless
that object possessed its own timestamp. Of course, if no timestamp is
present for any of the objects, included the top level package, some
other timestamp outside of the content must be used. In most cases, this
would probably result in using the current timestamp when the conversion
is made.

Most top-level STIX 1.x objects contained an id (or an idref, see
section `*7.1.2* <#relationships>`__ for more details), however when
converting STIX 1.x TTPs and Exploit Targets the id must be assigned to
the STIX 2.0 object that results. For instance, a TTP might have contain
an attack pattern object, but the id was not a property of the attack
pattern, but the TTP.

In certain circumstances, no id is available or in the case of TTPs and
Exploit Targets, there may be more than one STIX 2.0 object created. In
this case, a new **id** must be used.

In STIX 1.x, all top-level objects had a Information\_Source property to
hold information about, among other things, the object creator. However,
this property was optional. **created\_by\_ref**, which is a common
property on all STIX 2.0 Objects, is also optional. It should be noted
however, that the object creator can also be "inherited" from its parent
object, as with the timestamp. This fact can be useful to derive a more
robust STIX 2.0 object.

Special Considerations for TTPs and Exploit Target Conversions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When converting a STIX 1.x TTP or Exploit Target certain properties
exist at the top-level, and not in the subsidiary object which will form
the basis of the STIX 2.0 object. However, those properties must be used
when creating the subsidiary object. See section
`*5.3.2* <#attack-pattern>`__ for an example. The conversion of that
STIX 1.x TTP will yield a STIX 2.0 Attack Pattern, whose **name** and
**created\_by\_ref** are determined from the TTP itself, and not the
STIX 1.x Attack Pattern.

Minor Issues
~~~~~~~~~~~~~~~~~~~~

-  The condition property was optional in STIX 1.x. If it was not
       specified for an Observable used for patterning, the condition
       used in the STIX 2.0 pattern should be assumed to be "=".

-  The title property should be used for the **name** property, when
       necessary.

-  STIX 1.2 introduced versioning of objects. Currently, there is no
       guidance to converting STIX 1.2 versioning to STIX 2.0
       versioning. In most cases, a STIX 1.x relationship between object
       instances of the same type should be converted to a related-to
       relationship in STIX 2.0, unless it is obvious that the
       relationship exists to support STIX 1.x versioning.

Optional vs. Required
---------------------------

Certain fields are required in STIX 2.0 object that were optional in
STIX 1.x. This goes beyond the properties such as ids, created timestamps. The most
frequently occurring example is the labels property, which is also a common
property. Using a default value - unknown, in this case, is recommended.

​Help with Patterns
------------------------

Patterns in STIX 2.0 have certain restrictions that didn't explicitly
appear in STIX 1.x. A pattern in STIX 2.0 has explicit rules about if
the expression can refer to only one or many observed data instances.
Because STIX 1.x patterns did not have any of these restrictions, a
reasonable conversion of the pattern might be illegal in STIX 2.0.

Additionally, the use of the NOT operator in STIX 2.0 is restricted to
be used only with Comparison operators. Therefore, it is not possible to
express a pattern such as NOT (file.name == foo.bar" AND 'file.size ==
123) directly. To yield an equivalent pattern expression in STIX 2.0,
DeMorgan's Law must be used to reduce the scope of the NOT operator:
(file.name != foo.bar" OR 'file.size != 123).

​Single vs. Multiple
-------------------------

Some properties in STIX 1.x allowed for multiple values, but the
corresponding property in STIX 2.0 does not. In these cases, the first
value should be used.

In certain situations, something specific to the properties can be
helpful in handling this issue. For instance, the first entry in the
STIX 1.x Threat Actors motivation property should be assumed to be the
**primary\_motivation**. Any others should be listed in the
**secondary\_motivations** property.
