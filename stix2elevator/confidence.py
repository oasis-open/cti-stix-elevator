from math import ceil
import sys

from six import text_type

from stix2elevator.options import warn

if sys.version_info > (3,):
    long = int

_NONE_LOW_MED_HIGH = {
    "None": 0,
    "Low": 15,
    "Medium": 50,  # from xsi:type="stixVocabs:HighMediumLowVocab-1.0"
    "Med": 50,
    "High": 85
}

_ADMIRALTY_CREDIBILITY = {
    "6 - Truth cannot be judged": None,
    "5 - Improbable": 10,
    "4 - Doubtful": 30,
    "3 - Possibly True": 50,
    "2 - Probably True": 70,
    "1 - Confirmed by other sources": 90,
}

_WEP = {
    "Impossible": 0,
    "Highly Unlikely/Almost Certainly Not": 10,
    "Unlikely/Probably Not": 30,
    "Even Chance": 50,
    "Likely/Probable": 70,
    "Highly likely/Almost Certain": 90,
    "Certain": 100
}

_DNI = {
    "Almost No Chance / Remote": 5,
    "Very Unlikely / Highly Improbable": 15,
    "Unlikely / Improbable": 30,
    "Roughly Even Chance / Roughly Even Odds": 50,
    "Likely / Probable": 70,
    "Very Likely / Highly Probable": 85,
    "Almost Certain / Nearly Certain": 95
}


def convert_confidence_string(value):
    if value in _NONE_LOW_MED_HIGH:
        # check xsi:type?
        return _NONE_LOW_MED_HIGH[value]
    elif value in _ADMIRALTY_CREDIBILITY:
        return _ADMIRALTY_CREDIBILITY[value]
    elif value in _WEP:
        return _WEP[value]
    elif value in _DNI:
        return _DNI[value]
    else:
        warn(
            "The confidence value %s is not found on one of the confidence scales from the specification. No confidence can be inferred",
            430, value)
        return None


def convert_numeric_string(value):
    if value.find(".") == -1:
        return int(value)
    else:
        return float(value)


def convert_confidence_value(value, id):
    if isinstance(value, (int, long)):
        # look for percentage?
        if value < 0 or value > 100:
            warn(
                "The confidence value %s is not between 0 and 100, which is required for STIX 2.0. No confidence can be inferred",
                431, value)
            return None
        else:
            warn("The confidence value %s assumed to be a value on a scale between 0 and 100", 723, value)
            confidentiality2_1_value = value
    elif isinstance(value, float):
        if value < 0 or value > 100:
            warn(
                "The confidence value %s is not between 0 and 100, which is required for STIX 2.0. No confidence can be inferred",
                431, value)
            return None
        else:
            warn("The confidence value %s in %s has been converted to an integer so it is valid in STIX 2.0", 724,
                 value, id)
            confidentiality2_1_value = ceil(value)
    elif isinstance(value, str):
        value = text_type(value)
        if value.isnumeric():
            confidentiality2_1_value = convert_confidence_value(convert_numeric_string(value), id)
        else:
            confidentiality2_1_value = convert_confidence_string(value)
    elif isinstance(value, object):
        confidentiality2_1_value = convert_confidence_value(value.value, id)
    else:
        warn(
            "The confidence value %s cannot be converted", 432, value)
        return None

    return confidentiality2_1_value


def convert_confidence(confidence2_0, id):
    # should confidence description be included in a note or opinion?
    return convert_confidence_value(confidence2_0.value, id)
