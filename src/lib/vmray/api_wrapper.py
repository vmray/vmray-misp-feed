from typing import BinaryIO, List, Optional

from packaging.version import Version
from requests.exceptions import ConnectionError as ConnectionErr

from vmray.rest_api import VMRayRESTAPI, VMRayRESTAPIError

try:
    from vmray.rest_api.rest_api import (  # pylint: disable=unused-import
        DEFAULT_USER_AGENT,
    )

    HAS_USER_AGENT = True
except ImportError:
    HAS_USER_AGENT = False


class VMRay(VMRayRESTAPI):
    def __init__(self, server, api_key, verify_cert, limit: Optional[int] = None):
        if HAS_USER_AGENT:
            super().__init__(
                server, api_key, verify_cert=verify_cert, connector_name="MISP feed"
            )
        else:
            super().__init__(server, api_key, verify_cert=verify_cert)

        try:
            self.call("GET", "/rest/analysis", params={"_limit": "1"})
        except ConnectionErr as exc:
            raise VMRayRESTAPIError("Could not connect to host") from exc
        except VMRayRESTAPIError as exc:
            raise VMRayRESTAPIError(
                "Could not authenticate. Maybe the API key is invalid."
            ) from exc

        try:
            system_info = self.system_info()
        except VMRayRESTAPIError as exc:
            raise VMRayRESTAPIError("Could not get system info") from exc

        if not limit:
            self.limit = system_info.get("api_items_per_request", 100)
        else:
            self.limit = limit

        self.version = Version(system_info["version"])

    def system_info(self) -> dict:
        return self.call("GET", "/rest/system_info")

    def get_submissions(self, last_submission_id: Optional[int]) -> List[dict]:
        params = {"_order": "asc", "_limit": self.limit}

        if last_submission_id:
            if self.version >= Version("4.0.1"):
                # _last_id parameter was introduced in 4.0 and fixed in 4.0.1
                # greater than
                params["_last_id"] = last_submission_id
            else:
                # greater than or equals
                params["_min_id"] = last_submission_id + 1

        data = self.call("GET", "/rest/submission", params=params)
        return data

    def get_submission(self, submission_id: int) -> dict:
        return self.call("GET", f"/rest/submission/{submission_id}")

    def get_file_from_archive(self, analysis_id: int, rel_path: str) -> BinaryIO:
        data = self.call(
            "GET",
            f"/rest/analysis/{analysis_id}/archive/{rel_path}",
            raw_data=True,
        )

        return data

    def get_analyses_by_submission(self, submission_id: int) -> List[dict]:
        return self.call(
            "GET", f"/rest/analysis?analysis_submission_id={submission_id}"
        )

    def get_analyses(self, sample_id: int) -> List[dict]:
        return self.call("GET", f"/rest/analysis/sample/{sample_id}")

    def get_sample_info(self, sample_id: int) -> dict:
        return self.call("GET", f"/rest/sample/{sample_id}")

    def get_summary(self, analysis_id: int) -> BinaryIO:
        return self.get_file_from_archive(analysis_id, "logs/summary.json")

    def get_summary_v2(self, analysis_id: int) -> BinaryIO:
        return self.get_file_from_archive(analysis_id, "logs/summary_v2.json")

    def get_report(self, analysis_id: int) -> BinaryIO:
        try:
            return self.get_summary_v2(analysis_id)
        except VMRayRESTAPIError:
            return self.get_summary(analysis_id)

    def get_analysis(self, analysis_id: int) -> dict:
        return self.call("GET", f"/rest/analysis/{analysis_id}")

    def get_vtis(self, sample_id: int) -> List[dict]:
        vti_data = self.call("GET", f"/rest/sample/{sample_id}/vtis")
        return vti_data.get("threat_indicators", [])

    def get_iocs(self, sample_id: int) -> dict:
        ioc_data = self.call("GET", f"/rest/sample/{sample_id}/iocs")
        return ioc_data.get("iocs", {})

    def get_mitre_attack(self, sample_id: int) -> List[dict]:
        mitre_attack_data = self.call("GET", f"/rest/sample/{sample_id}/mitre_attack")
        return mitre_attack_data.get("mitre_attack_techniques", [])
