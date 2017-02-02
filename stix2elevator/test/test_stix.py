import stix

from stix2elevator import convert_stix


def test_structured_text_list():

    indicator = stix.indicator.Indicator()
    indicator.descriptions = [
        "First description",
        "Second description",
    ]
    print(indicator.to_xml())
    print(indicator.to_json())

    actual = convert_stix.process_structured_text_list(indicator.descriptions)
    # TODO: do we want a newline in here?
    expected = "First descriptionSecond description"
    assert expected == actual
