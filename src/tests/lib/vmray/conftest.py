# pylint: disable=redefined-outer-name

import json
import re

import pytest

from lib.config import Config, MISPEventConfig, VMRayConfig


@pytest.fixture(scope="module")
def config():
    return Config(
        feed_path="/tmp/test",
        logging="DEBUG",
        vmray=VMRayConfig(
            host="test",
            api_key="test",
            verify_cert=False,
            last_submission_id=10,
            chunk_size=10,
        ),
        misp_event=MISPEventConfig(
            include_report=False,
            use_vmray_tags=True,
            include_vtis=True,
            ioc_only=False,
        ),
    )


@pytest.fixture(scope="module")
def api_dir(data_dir):
    return data_dir / "api_response"


@pytest.fixture(autouse=True)
def mock_vmray_server(requests_mock, api_dir):
    with open(api_dir / "analyses.json", "r", encoding="utf-8") as fobj:
        analyses = json.load(fobj)
    requests_mock.get("https://test/rest/analysis?_limit=1", json=analyses)

    with open(api_dir / "system_info.json", "r", encoding="utf-8") as fobj:
        analyses = json.load(fobj)
    requests_mock.get("https://test/rest/system_info", json=analyses)

    with open(api_dir / "summary_v2.json", "r", encoding="utf-8") as fobj:
        summary_v2 = json.load(fobj)
    requests_mock.get(
        "https://test/rest/analysis/82/archive/logs/summary_v2.json", json=summary_v2
    )

    with open(api_dir / "analysis_submission_id.json", "r", encoding="utf-8") as fobj:
        analysis_submission = json.load(fobj)
    requests_mock.get(
        "https://test/rest/analysis?analysis_submission_id=12", json=analysis_submission
    )

    with open(api_dir / "submission.json", "r", encoding="utf-8") as fobj:
        submission = json.load(fobj)
    requests_mock.get("https://test/rest/submission/12", json=submission)

    with open(api_dir / "sample.json", "r", encoding="utf-8") as fobj:
        sample = json.load(fobj)

    requests_mock.get(re.compile(r"test/rest/sample/\d+"), json=sample)
