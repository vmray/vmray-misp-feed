# pylint: disable=redefined-outer-name

import json

import pytest

from lib.vmray.parser import VMRayParser


def remove_changing_values(event):
    event = event["Event"]
    del event["uuid"]
    del event["timestamp"]
    del event["publish_timestamp"]
    del event["date"]

    for event_obj in event["Object"]:
        if "uuid" in event_obj.keys():
            del event_obj["uuid"]

        if "timestamp" in event_obj.keys():
            del event_obj["timestamp"]

        for attribute in event_obj["Attribute"]:
            if "uuid" in attribute.keys():
                del attribute["uuid"]

            if "timestamp" in attribute.keys():
                del attribute["timestamp"]

    return {"Event": event}


@pytest.fixture
def parser(config):
    return VMRayParser(config)


@pytest.fixture
def expected_event(data_dir):
    event = data_dir / "misp_event.json"
    with event.open("r", encoding="utf-8") as fobj:
        return json.load(fobj)


def test_parser(parser, expected_event):
    sample_id = 12
    misp_event = parser.parse(sample_id)
    event_json = misp_event.to_feed()
    event_json = remove_changing_values(event_json)

    assert event_json == expected_event
