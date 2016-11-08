<div>
<h1>README</h1>

<div>
<h2><a id="readme-general">OASIS Open Repository: cti-stix-elevator</a></h2>

<p>This GitHub public repository ( <b><a href="https://github.com/oasis-open/cti-stix-elevator">https://github.com/oasis-open/cti-stix-elevator</a></b> ) was created at the request of the <a href="https://www.oasis-open.org/committees/cti/">OASIS Cyber Threat Intelligence (CTI) TC</a> as an <a href="https://www.oasis-open.org/resources/open-repositories/">OASIS Open Repository</a> to support development of open source resources related to Technical Committee work.</p>

<p>While this Open Repository remains associated with the sponsor TC, its development priorities, leadership, intellectual property terms, participation rules, and other matters of governance are <a href="https://github.com/oasis-open/cti-stix-elevator/blob/master/CONTRIBUTING.md#governance-distinct-from-oasis-tc-process">separate and distinct</a> from the OASIS TC Process and related policies.</p>

<p>All contributions made to this Open Repository are subject to open source license terms expressed in the <a href="https://www.oasis-open.org/sites/www.oasis-open.org/files/BSD-3-Clause.txt">BSD-3-Clause License</a>.  That license was selected as the declared <a href="https://www.oasis-open.org/resources/open-repositories/licenses">"Applicable License"</a> when the Open Repository was created.</p>

<p>As documented in <a href="https://github.com/oasis-open/cti-stix-elevator/blob/master/CONTRIBUTING.md#public-participation-invited">"Public Participation Invited</a>", contributions to this OASIS Open Repository are invited from all parties, whether affiliated with OASIS or not.  Participants must have a GitHub account, but no fees or OASIS membership obligations are required.  Participation is expected to be consistent with the <a href="https://www.oasis-open.org/policies-guidelines/open-repositories">OASIS Open Repository Guidelines and Procedures</a>, the open source <a href="https://github.com/oasis-open/cti-stix-elevator/blob/master/LICENSE">LICENSE</a> designated for this particular repository, and the requirement for an <a href="https://www.oasis-open.org/resources/open-repositories/cla/individual-cla">Individual Contributor License Agreement</a> that governs intellectual property.</p>

</div>

<div>
<h2><a id="purposeStatement">Statement of Purpose</a></h2>

<p>Statement of Purpose for this OASIS Open Repository (cti-stix-elevator) as <a href="https://lists.oasis-open.org/archives/cti/201610/msg00106.html">proposed</a> and <a href="https://lists.oasis-open.org/archives/cti/201610/msg00126.html">approved</a> [<a href="https://issues.oasis-open.org/browse/TCADMIN-2477">bis</a>] by the TC:</p>

<p>The stix-elevator is a software tool for converting STIX 1.2 XML to STIX 2.0 JSON. Due to the differences between STIX 1.2 and STIX 2.0, this conversion is best-effort only, and stix-elevator cannot convert from STIX 2.0 back to STIX 1.2. During the conversion, stix-elevator provides information on the assumptions it needs to make to produce valid STIX 2.0 JSON, and what information was not able to be converted.</p>

<!-- OASIS Open Repository: Convert STIX 1.2 XML to STIX 2.0 JSON  -->


</div>

<div><h2><a id="purposeClarifications">Additions to Statement of Purpose</a></h2>

</div>
The stix-elevator is a work-in-progress.  It should be used to explore how existing STIX 1.x would potentially be represented in STIX 2.0.  Using the current version of the elevator will provide insight to issues that might need to be mitigated to convert your STIX 1.x content.

**_It should not be used in a production environment, and should not be considered final._**

Please enter any comments on how to improve it into the issue tracker.


### Requirements

For STIX 1.1.1 content;

* Python 2.6/2.7
* python-stix = 1.1.1.7 (other dependencies inherited from python-stix)
 
For STIX 1.2 content:

* Python 3.5
* python-stix >= 1.2.0.0 (other dependencies inherited from python-stix)

For both:

* stix2validator (with all of its dependencies:  jsonschema, colorama, nose, tox
* pycountry >= 1.20


### Installation

The needed software is located in the following repositories:

* stix-elevator (https://github.com/oasis-open/cti-stix-elevator)
* cti-stix-validator (https://github.com/oasis-open/cti-stix-validator)

#### Install stix2validator

The easiest way to install the STIX validator is with pip:
```
$ pip install git+https://github.com/oasis-open/cti-stix-validator.git
```

Note that if you clone or download the repository and install it that way instead, you will need to set up the submodules before you install it:

```
$ git clone https://github.com/oasis-open/cti-stix-validator.git
$ cd cti-stix-validator/
$ git submodule update --init --recursive
$ python setup.py install
```

#### Install stix-elevator

```
$ pip install git+https://github.com/oasis-open/cti-stix-elevator.git
```

### Usage


#### As A Script

The elevator comes with a bundled script which you can use to elevate STIX 1.1.1 - 1.2.1 content to STIX 2.0 content:

```
$ stix-elevator <stix_file.xml>
```

### As A Library

You can also use this library to integrate STIX elevation into your own tools. You can elevate a STIX 1.x file:

```
  from elevator import elevate_file

  results = elevate_file("stix_file.xml")
  print(results)
```
Additionally, a similar method exists to accept a string as an argument:

```
  from elevator import elevate_string

  results = elevate_string("...")
  print(results)
```


<h2><a id="maintainers">Maintainers</a></h2>

<p>Open Repository <a href="https://www.oasis-open.org/resources/open-repositories/maintainers-guide">Maintainers</a> are responsible for oversight of this project's community development activities, including evaluation of GitHub <a href="https://github.com/oasis-open/cti-stix-elevator/blob/master/CONTRIBUTING.md#fork-and-pull-collaboration-model">pull requests</a> and <a href="https://www.oasis-open.org/policies-guidelines/open-repositories#repositoryManagement">preserving</a> open source principles of openness and fairness. Maintainers are recognized and trusted experts who serve to implement community goals and consensus design preferences.</p>

<p>Initially, the associated TC members have designated one or more persons to serve as Maintainer(s); subsequently, participating community members may select additional or substitute Maintainers, per <a href="https://www.oasis-open.org/resources/open-repositories/maintainers-guide#additionalMaintainers">consensus agreements</a>.</p>

<p><b><a id="currentMaintainers">Current Maintainers of this Open Repository</a></b></p>

<ul>
<li><a href="mailto:gback@mitre.org">Greg Back</a>; GitHub ID: <a href="https://github.com/gtback/">https://github.com/gtback/</a>; WWW: <a href="https://www.mitre.org/">MITRE</a></li>
<li><a href="mailto:rpiazza@mitre.org">Rich Piazza</a>; GitHub ID: <a href="https://github.com/rpiazza/">https://github.com/rpiazza/</a>; WWW: <a href="https://www.mitre.org/">MITRE</a></li>
</ul>

</div>

<div><h2><a id="aboutOpenRepos">About OASIS Open Repositories</a></h2>

<p><ul>
<li><a href="https://www.oasis-open.org/resources/open-repositories/">Open Repositories: Overview and Resources</a></li>
<li><a href="https://www.oasis-open.org/resources/open-repositories/faq">Frequently Asked Questions</a></li>
<li><a href="https://www.oasis-open.org/resources/open-repositories/licenses">Open Source Licenses</a></li>
<li><a href="https://www.oasis-open.org/resources/open-repositories/cla">Contributor License Agreements (CLAs)</a></li>
<li><a href="https://www.oasis-open.org/resources/open-repositories/maintainers-guide">Maintainers' Guidelines and Agreement</a></li>
</ul></p>

</div>

<div><h2><a id="feedback">Feedback</a></h2>

<p>Questions or comments about this Open Repository's activities should be composed as GitHub issues or comments. If use of an issue/comment is not possible or appropriate, questions may be directed by email to the Maintainer(s) <a href="#currentMaintainers">listed above</a>.  Please send general questions about Open Repository participation to OASIS Staff at <a href="mailto:repository-admin@oasis-open.org">repository-admin@oasis-open.org</a> and any specific CLA-related questions to <a href="mailto:repository-cla@oasis-open.org">repository-cla@oasis-open.org</a>.</p>

</div></div>


