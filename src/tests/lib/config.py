# pylint: disable=redefined-outer-name

import pytest
import toml

from lib.config import Config, config_path


@pytest.fixture
def config():
    cfg = config_path()
    template = cfg.parent / (cfg.name + ".template")
    with open(template, "r") as fobj:
        config = Config(**toml.load(fobj))

    return config


def test_config(config):
    assert config.feed_path == "/var/www/MISP/app/tmp/vmray-misp-feed"
    assert config.logging == "INFO"

    assert config.vmray.host == "https://cloud.vmray.com"
    assert config.vmray.api_key == "your_api_key"
    assert config.vmray.verify_cert is True
    assert config.vmray.last_submission_id == 0
    assert config.vmray.chunk_size == 100

    assert config.misp_event.include_report is False
    assert config.misp_event.use_vmray_tags is True
    assert config.misp_event.include_vtis is False
    assert config.misp_event.ioc_only is True
