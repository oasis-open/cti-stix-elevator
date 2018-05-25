from stix.indicator import Indicator

from stix2elevator import convert_stix, utils


def test_strftime_with_appropriate_fractional_seconds():
    base_timestamp = "2017-03-29T05:05:05.555Z"
    mili_expected_timestamp = "2017-03-29T05:05:05.555000Z"

    milisecond_timestamp = utils.strftime_with_appropriate_fractional_seconds(base_timestamp, True)
    assert base_timestamp == milisecond_timestamp

    trunc_timestamp = utils.strftime_with_appropriate_fractional_seconds(base_timestamp, False)
    assert mili_expected_timestamp == trunc_timestamp


def test_convert_timestamp_string():
    # Create v1 and v2 indicator, test timestamp pre and post convert_timestamp_call

    # Maybe take a v1 idiom

    # child_timestamp = "2017-03-29T05:05:05.555Z"
    parent_timestamp = "2017-03-29T05:09:09.999Z"
    indicator = Indicator()
    indicator_instance = convert_stix.create_basic_object("indicator", indicator, parent_timestamp)
    assert indicator_instance is not None
