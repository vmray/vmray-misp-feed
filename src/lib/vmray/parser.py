import base64
import json
import re

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import PureWindowsPath
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union

from pymisp import MISPAttribute, MISPEvent, MISPObject
from pymisp.mispevent import MISPOrganisation
from vmray.rest_api import VMRayRESTAPIError

from lib.config import Config
from .api_wrapper import VMRay


USER_RE = re.compile(r".:.Users\\(.*?)\\", re.IGNORECASE)
DOC_RE = re.compile(r".:.DOCUME~1.\\(.*?)\\", re.IGNORECASE)
DOC_AND_SETTINGS_RE = re.compile(r".:.Documents and Settings\\(.*?)\\", re.IGNORECASE)
USERPROFILES = [USER_RE, DOC_RE, DOC_AND_SETTINGS_RE]


def classifications_to_str(classifications: List[str]) -> Optional[str]:
    if classifications:
        return "Classifications: " + ", ".join(classifications)
    return None


def merge_lists(target: List[Any], source: List[Any]):
    return list({*target, *source})


@dataclass
class Artifact:
    is_ioc: bool
    verdict: Optional[str]

    @abstractmethod
    def to_misp_object(self, tag: bool) -> MISPObject:
        raise NotImplementedError()

    @abstractmethod
    def merge(self, other: "Artifact") -> None:
        raise NotImplementedError()

    @abstractmethod
    def __eq__(self, other: "Artifact") -> bool:
        raise NotImplementedError()

    def tag_artifact_attribute(self, attribute: MISPAttribute) -> None:
        if self.is_ioc:
            if attribute:
                attribute.add_tag('vmray:artifact="IOC"')

        if self.verdict:
            if attribute:
                attribute.add_tag(f'vmray:verdict="{self.verdict}"')


@dataclass
class DomainArtifact(Artifact):
    domain: str
    sources: List[str]
    ips: List[str] = field(default_factory=list)
    classifications: List[str] = field(default_factory=list)

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="domain-ip")

        classifications = classifications_to_str(self.classifications)
        attr = obj.add_attribute(
            "domain", value=self.domain, to_ids=self.is_ioc, comment=classifications
        )
        if tag:
            self.tag_artifact_attribute(attr)

        for ip in self.ips:
            obj.add_attribute("ip", value=ip, to_ids=self.is_ioc)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, DomainArtifact):
            return

        self.ips = merge_lists(self.ips, other.ips)
        self.classifications = merge_lists(self.classifications, other.classifications)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, DomainArtifact):
            return NotImplemented

        return self.domain == other.domain


@dataclass
class EmailArtifact(Artifact):
    sender: Optional[str]
    subject: Optional[str]
    recipients: List[str] = field(default_factory=list)
    classifications: List[str] = field(default_factory=list)

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="email")

        if self.sender:
            classifications = classifications_to_str(self.classifications)
            attr = obj.add_attribute(
                "from", value=self.sender, to_ids=self.is_ioc, comment=classifications
            )
            if tag:
                self.tag_artifact_attribute(attr)

        if self.subject:
            obj.add_attribute("subject", value=self.subject, to_ids=False)

        for recipient in self.recipients:
            obj.add_attribute("to", value=recipient, to_ids=False)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, EmailArtifact):
            return

        self.recipients = merge_lists(self.recipients, other.recipients)
        self.classifications = merge_lists(self.classifications, other.classifications)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, EmailArtifact):
            return NotImplemented

        return self.sender == other.sender and self.subject == other.subject


@dataclass
class FileArtifact(Artifact):
    filenames: List[str]
    operations: List[str]
    md5: str
    sha1: str
    sha256: str
    ssdeep: Optional[str]
    imphash: Optional[str]
    classifications: List[str]
    size: Optional[int]
    mimetype: Optional[str] = None

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="file")

        if self.size:
            obj.add_attribute("size-in-bytes", value=self.size)

        classifications = classifications_to_str(self.classifications)
        hashes = [
            ("md5", self.md5),
            ("sha1", self.sha1),
            ("sha256", self.sha256),
            ("ssdeep", self.ssdeep),
        ]
        for (key, value) in hashes:
            if not value:
                continue

            attr = obj.add_attribute(
                key, value=value, to_ids=self.is_ioc, comment=classifications
            )

            if tag:
                self.tag_artifact_attribute(attr)

        if self.mimetype:
            obj.add_attribute("mimetype", value=self.mimetype, to_ids=False)

        operations = None
        if self.operations:
            operations = "Operations: " + ", ".join(self.operations)

        for filename in self.filenames:
            filename = PureWindowsPath(filename)
            obj.add_attribute("filename", value=filename.name, comment=operations)

            fullpath = str(filename)
            for regex in USERPROFILES:
                fullpath = regex.sub(r"%USERPROFILE%\\", fullpath)

            obj.add_attribute("fullpath", fullpath)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, FileArtifact):
            return

        self.filenames = merge_lists(self.filenames, other.filenames)
        self.operations = merge_lists(self.operations, other.operations)
        self.classifications = merge_lists(self.classifications, other.classifications)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, FileArtifact):
            return NotImplemented

        return self.sha256 == other.sha256


@dataclass
class IpArtifact(Artifact):
    ip: str
    sources: List[str]
    classifications: List[str] = field(default_factory=list)

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="ip-port")

        classifications = classifications_to_str(self.classifications)
        attr = obj.add_attribute(
            "ip", value=self.ip, comment=classifications, to_ids=self.is_ioc
        )
        if tag:
            self.tag_artifact_attribute(attr)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, IpArtifact):
            return

        self.sources = merge_lists(self.sources, other.sources)
        self.classifications = merge_lists(self.classifications, other.classifications)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, IpArtifact):
            return NotImplemented

        return self.ip == other.ip


@dataclass
class MutexArtifact(Artifact):
    name: str
    operations: List[str]
    classifications: List[str] = field(default_factory=list)

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="mutex")

        classifications = classifications_to_str(self.classifications)
        attr = obj.add_attribute(
            "name",
            value=self.name,
            category="External analysis",
            to_ids=False,
            comment=classifications,
        )
        if tag:
            self.tag_artifact_attribute(attr)

        operations = None
        if self.operations:
            operations = "Operations: " + ", ".join(self.operations)
        obj.add_attribute("description", value=operations, to_ids=False)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, MutexArtifact):
            return

        self.operations = merge_lists(self.operations, other.operations)
        self.classifications = merge_lists(self.classifications, other.classifications)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, MutexArtifact):
            return NotImplemented

        return self.name == other.name


@dataclass
class ProcessArtifact(Artifact):
    filename: str
    pid: Optional[int] = None
    parent_pid: Optional[int] = None
    cmd_line: Optional[str] = None
    operations: List[str] = field(default_factory=list)
    classifications: List[str] = field(default_factory=list)

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="process")

        if self.pid:
            obj.add_attribute("pid", value=self.pid, category="External analysis")

        if self.parent_pid:
            obj.add_attribute(
                "parent-pid", value=self.parent_pid, category="External analysis"
            )

        classifications = classifications_to_str(self.classifications)
        name_attr = obj.add_attribute(
            "name", self.filename, category="External analysis", comment=classifications
        )

        cmd_attr = obj.add_attribute("command-line", value=self.cmd_line)

        if tag:
            self.tag_artifact_attribute(name_attr)
            self.tag_artifact_attribute(cmd_attr)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, ProcessArtifact):
            return

        self.operations = merge_lists(self.operations, other.operations)
        self.classifications = merge_lists(self.classifications, other.classifications)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, ProcessArtifact):
            return NotImplemented

        return self.filename == other.filename and self.cmd_line == other.cmd_line


@dataclass
class RegistryArtifact(Artifact):
    key: str
    operations: List[str]

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="registry-key")

        operations = None
        if self.operations:
            operations = "Operations: " + ", ".join(self.operations)

        attr = obj.add_attribute(
            "key", value=self.key, to_ids=self.is_ioc, comment=operations
        )
        if tag:
            self.tag_artifact_attribute(attr)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, RegistryArtifact):
            return

        self.operations = merge_lists(self.operations, other.operations)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, RegistryArtifact):
            return NotImplemented

        return self.key == other.key


@dataclass
class UrlArtifact(Artifact):
    url: str
    operations: List[str]
    domain: Optional[str] = None
    ips: List[str] = field(default_factory=list)

    def to_misp_object(self, tag: bool) -> MISPObject:
        obj = MISPObject(name="url")

        operations = None
        if self.operations:
            operations = "Operations: " + ", ".join(self.operations)

        attr = obj.add_attribute(
            "url",
            value=self.url,
            comment=operations,
            category="External analysis",
            to_ids=False,
        )
        if tag:
            self.tag_artifact_attribute(attr)

        if self.domain:
            obj.add_attribute(
                "domain", self.domain, category="External analysis", to_ids=False
            )

        for ip in self.ips:
            obj.add_attribute("ip", ip, category="External analysis", to_ids=False)

        return obj

    def merge(self, other: Artifact) -> None:
        if not isinstance(other, UrlArtifact):
            return

        self.ips = merge_lists(self.ips, other.ips)
        self.operations = merge_lists(self.operations, other.operations)

    def __eq__(self, other: Artifact) -> bool:
        if not isinstance(other, UrlArtifact):
            return NotImplemented

        return self.url == other.url and self.domain == other.domain


@dataclass
class MitreAttack:
    description: str
    id: str

    def to_misp_galaxy(self) -> str:
        return f'misp-galaxy:mitre-attack-pattern="{self.description} - {self.id}"'


@dataclass
class VTI:
    category: str
    operation: str
    technique: str
    score: int


class VMRayParseError(Exception):
    pass


class ReportParser(ABC):
    @abstractmethod
    def is_static_report(self) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def artifacts(self) -> Iterator[Artifact]:
        raise NotImplementedError()

    @abstractmethod
    def classifications(self) -> Optional[str]:
        raise NotImplementedError()

    @abstractmethod
    def details(self) -> Iterator[str]:
        raise NotImplementedError()

    @abstractmethod
    def mitre_attacks(self) -> Iterator[MitreAttack]:
        raise NotImplementedError()

    @abstractmethod
    def sandbox_type(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def score(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def vtis(self) -> Iterator[VTI]:
        raise NotImplementedError()


class Summary(ReportParser):
    def __init__(self, analysis_id: int, api: VMRay):
        self.analysis_id = analysis_id

        data = api.get_summary(analysis_id)
        self.report = json.load(data)

    @staticmethod
    def to_verdict(score: Union[int, str]) -> Optional[str]:
        if isinstance(score, int):
            if 0 <= score <= 24:
                return "clean"
            if 25 <= score <= 74:
                return "suspicious"
            if 75 <= score <= 100:
                return "malicious"
            return "n/a"
        if isinstance(score, str):
            score = score.lower()
            if score in ("not_suspicious", "whitelisted"):
                return "clean"
            if score == "blacklisted":
                return "malicious"
            if score in ("not_available", "unknown"):
                return "n/a"
            return score
        return None

    def is_static_report(self) -> bool:
        return self.report["vti"]["vti_rule_type"] == "Static"

    def artifacts(self) -> Iterator[Artifact]:
        artifacts = self.report["artifacts"]
        domains = artifacts.get("domains", [])
        for domain in domains:
            classifications = domain.get("classifications", [])
            is_ioc = domain.get("ioc", False)
            verdict = self.to_verdict(domain.get("severity"))
            ips = domain.get("ip_addresses", [])
            artifact = DomainArtifact(
                domain=domain["domain"],
                sources=domain["sources"],
                ips=ips,
                classifications=classifications,
                is_ioc=is_ioc,
                verdict=verdict,
            )
            yield artifact

        emails = artifacts.get("emails", [])
        for email in emails:
            sender = email.get("sender")
            subject = email.get("subject")
            verdict = self.to_verdict(email.get("severity"))
            recipients = email.get("recipients", [])
            classifications = email.get("classifications", [])
            is_ioc = email.get("ioc", False)

            artifact = EmailArtifact(
                sender=sender,
                subject=subject,
                verdict=verdict,
                recipients=recipients,
                classifications=classifications,
                is_ioc=is_ioc,
            )
            yield artifact

        files = artifacts.get("files", [])
        for file_ in files:
            if file_["filename"] is None:
                continue

            filenames = [file_["filename"]]
            if "filenames" in file_:
                filenames += file_["filenames"]

            hashes = file_["hashes"]
            classifications = file_.get("classifications", [])
            operations = file_.get("operations", [])
            is_ioc = file_.get("ioc", False)
            mimetype = file_.get("mime_type")
            verdict = self.to_verdict(file_.get("severity"))

            for hash_dict in hashes:
                imp = hash_dict.get("imp_hash")

                artifact = FileArtifact(
                    filenames=filenames,
                    imphash=imp,
                    md5=hash_dict["md5_hash"],
                    ssdeep=hash_dict.get("ssdeep_hash"),
                    sha256=hash_dict["sha256_hash"],
                    sha1=hash_dict["sha1_hash"],
                    operations=operations,
                    classifications=classifications,
                    size=file_.get("file_size"),
                    is_ioc=is_ioc,
                    mimetype=mimetype,
                    verdict=verdict,
                )
                yield artifact

        ips = artifacts.get("ips", [])
        for ip in ips:
            is_ioc = ip.get("ioc", False)
            verdict = self.to_verdict(ip.get("severity"))
            classifications = ip.get("classifications", [])
            artifact = IpArtifact(
                ip=ip["ip_address"],
                sources=ip["sources"],
                classifications=classifications,
                verdict=verdict,
                is_ioc=is_ioc,
            )
            yield artifact

        mutexes = artifacts.get("mutexes", [])
        for mutex in mutexes:
            verdict = self.to_verdict(mutex.get("severity"))
            is_ioc = mutex.get("ioc", False)
            artifact = MutexArtifact(
                name=mutex["mutex_name"],
                operations=mutex["operations"],
                classifications=[],
                verdict=verdict,
                is_ioc=is_ioc,
            )
            yield artifact

        processes = artifacts.get("processes", [])
        for process in processes:
            classifications = process.get("classifications", [])
            cmd_line = process.get("cmd_line")
            name = process["image_name"]
            verdict = self.to_verdict(process.get("severity"))
            is_ioc = process.get("ioc", False)

            artifact = ProcessArtifact(
                filename=name,
                classifications=classifications,
                cmd_line=cmd_line,
                verdict=verdict,
                is_ioc=is_ioc,
            )
            yield artifact

        registry = artifacts.get("registry", [])
        for reg in registry:
            is_ioc = reg.get("ioc", False)
            verdict = self.to_verdict(reg.get("severity"))
            artifact = RegistryArtifact(
                key=reg["reg_key_name"],
                operations=reg["operations"],
                verdict=verdict,
                is_ioc=is_ioc,
            )
            yield artifact

        urls = artifacts.get("urls", [])
        for url in urls:
            ips = url.get("ip_addresses", [])
            is_ioc = url.get("ioc", False)
            verdict = self.to_verdict(url.get("severity"))

            artifact = UrlArtifact(
                url=url["url"],
                operations=url["operations"],
                ips=ips,
                is_ioc=is_ioc,
                verdict=verdict,
            )
            yield artifact

    def classifications(self) -> Optional[str]:
        classifications = self.report["classifications"]
        if classifications:
            str_classifications = ", ".join(classifications)
            return f"Classifications: {str_classifications}"
        return None

    def details(self) -> Iterator[str]:
        details = self.report["analysis_details"]
        execution_successful = details["execution_successful"]
        termination_reason = details["termination_reason"]
        result = details["result_str"]

        analysis = f" {self.analysis_id}" if self.analysis_id != 0 else ""

        yield f"Analysis{analysis}: execution_successful: {execution_successful}"
        yield f"Analysis{analysis}: termination_reason: {termination_reason}"
        yield f"Analysis{analysis}: result: {result}"

    def mitre_attacks(self) -> Iterator[MitreAttack]:
        mitre_attack = self.report["mitre_attack"]
        techniques = mitre_attack.get("techniques", [])

        for technique in techniques:
            mitre_attack = MitreAttack(
                description=technique["description"], id=technique["id"]
            )
            yield mitre_attack

    def sandbox_type(self) -> str:
        vm_name = self.report["vm_and_analyzer_details"]["vm_name"]
        sample_type = self.report["sample_details"]["sample_type"]
        return f"{vm_name} | {sample_type}"

    def score(self) -> str:
        vti_score = self.report["vti"]["vti_score"]
        return self.to_verdict(vti_score)

    def vtis(self) -> Iterator[VTI]:
        try:
            vtis = self.report["vti"]["vti_rule_matches"]
        except KeyError:
            vtis = []

        for vti in vtis:
            new_vti = VTI(
                category=vti["category_desc"],
                operation=vti["operation_desc"],
                technique=vti["technique_desc"],
                score=vti["rule_score"],
            )

            yield new_vti


class SummaryV2(ReportParser):
    def __init__(self, analysis_id: int, api: VMRay):
        self.analysis_id = analysis_id

        data = api.get_summary_v2(analysis_id)
        self.report = json.load(data)

    def _resolve_refs(
        self, data: Union[List[Dict[str, Any]], Dict[str, Any]]
    ) -> Iterator[Dict[str, Any]]:
        if isinstance(data, dict):
            data = [data]

        for ref in data:
            yield self._resolve_ref(ref)

    def _resolve_ref(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if data == {}:
            return {}

        if data["_type"] != "reference" or data["source"] != "logs/summary_v2.json":
            return {}

        resolved_ref = self.report
        paths = data["path"]
        for path_part in paths:
            try:
                resolved_ref = resolved_ref[path_part]
            except KeyError:
                return {}

        return resolved_ref

    @staticmethod
    def convert_verdict(verdict: Optional[str]) -> str:
        if verdict == "not_available" or not verdict:
            return "n/a"

        return verdict

    def is_static_report(self) -> bool:
        return self.report["vti"]["score_type"] == "static"

    def artifacts(self) -> Iterator[Artifact]:
        artifacts = self.report["artifacts"]

        ref_domains = artifacts.get("ref_domains", [])
        for domain in self._resolve_refs(ref_domains):
            classifications = domain.get("classifications", [])
            artifact = DomainArtifact(
                domain=domain["domain"],
                sources=domain["sources"],
                classifications=classifications,
                is_ioc=domain["is_ioc"],
                verdict=domain["verdict"],
            )

            ref_ip_addresses = domain.get("ref_ip_addresses", [])
            if not ref_ip_addresses:
                continue

            for ip_address in self._resolve_refs(ref_ip_addresses):
                #print (ip_address)
                if "ip_address" in ip_address:
                    artifact.ips.append(ip_address["ip_address"])

            yield artifact

        ref_emails = artifacts.get("ref_emails", [])
        for email in self._resolve_refs(ref_emails):
            sender = email.get("sender")
            subject = email.get("subject")
            recipients = email.get("recipients", [])
            verdict = email["verdict"]
            is_ioc = email["is_ioc"]
            classifications = email.get("classifications", [])

            artifact = EmailArtifact(
                sender=sender,
                subject=subject,
                recipients=recipients,
                classifications=classifications,
                verdict=verdict,
                is_ioc=is_ioc,
            )

            yield artifact

        ref_files = artifacts.get("ref_files", [])
        for file_ in self._resolve_refs(ref_files):
            filenames = []

            if "ref_filenames" in file_:
                for filename in self._resolve_refs(file_["ref_filenames"]):
                    if not filename:
                        continue
                    filenames.append(filename["filename"])

            artifact = FileArtifact(
                operations=file_.get("operations", []),
                md5=file_["hash_values"]["md5"],
                sha1=file_["hash_values"]["sha1"],
                sha256=file_["hash_values"]["sha256"],
                ssdeep=file_["hash_values"].get("ssdeep"),
                imphash=None,
                mimetype=file_.get("mime_type"),
                filenames=filenames,
                is_ioc=file_["is_ioc"],
                classifications=file_.get("classifications", []),
                size=file_["size"],
                verdict=file_["verdict"],
            )
            yield artifact

        ref_ip_addresses = artifacts.get("ref_ip_addresses", [])
        for ip in self._resolve_refs(ref_ip_addresses):
            classifications = ip.get("classifications", [])
            verdict = ip["verdict"]
            is_ioc = ip["is_ioc"]
            artifact = IpArtifact(
                ip=ip["ip_address"],
                sources=ip["sources"],
                classifications=classifications,
                verdict=verdict,
                is_ioc=is_ioc,
            )
            yield artifact

        ref_mutexes = artifacts.get("ref_mutexes", [])
        for mutex in self._resolve_refs(ref_mutexes):
            is_ioc = mutex["is_ioc"]
            classifications = mutex.get("classifications", [])
            artifact = MutexArtifact(
                name=mutex["name"],
                operations=mutex["operations"],
                verdict=mutex["verdict"],
                classifications=classifications,
                is_ioc=is_ioc,
            )
            yield artifact

        ref_processes = artifacts.get("ref_processes", [])
        for process in self._resolve_refs(ref_processes):
            cmd_line = process.get("cmd_line")
            classifications = process.get("classifications", [])
            verdict = process.get("verdict")
            artifact = ProcessArtifact(
                pid=process["os_pid"],
                parent_pid=process["origin_monitor_id"],
                filename=process["filename"],
                is_ioc=process["is_ioc"],
                cmd_line=cmd_line,
                classifications=classifications,
                verdict=verdict,
            )
            yield artifact

        ref_registry_records = artifacts.get("ref_registry_records", [])
        for reg in self._resolve_refs(ref_registry_records):
            artifact = RegistryArtifact(
                key=reg["reg_key_name"],
                operations=reg["operations"],
                is_ioc=reg["is_ioc"],
                verdict=reg["verdict"],
            )
            yield artifact

        url_refs = artifacts.get("ref_urls", [])
        for url in self._resolve_refs(url_refs):
            domain = None
            ref_domain = url.get("ref_domain", {})
            if ref_domain:
                if "domain" in ref_domain:
                    domain = self._resolve_ref(ref_domain)["domain"]

            ips = []
            ref_ip_addresses = url.get("ref_ip_addresses", [])
            for ip_address in self._resolve_refs(ref_ip_addresses):
                if "ip_address" in ip_address:
                    ips.append(ip_address["ip_address"])

            artifact = UrlArtifact(
                url=url["url"],
                operations=url.get("operations", []),
                is_ioc=url["is_ioc"],
                domain=domain,
                ips=ips,
                verdict=url["verdict"],
            )
            yield artifact

    def classifications(self) -> Optional[str]:
        try:
            classifications = ", ".join(self.report["classifications"])
            return f"Classifications: {classifications}"
        except KeyError:
            return None

    def details(self) -> Iterator[str]:
        details = self.report["analysis_metadata"]
        is_execution_successful = details["is_execution_successful"]
        termination_reason = details["termination_reason"]
        result = details["result_str"]

        yield f"Analysis {self.analysis_id}: execution_successful: {is_execution_successful}"
        yield f"Analysis {self.analysis_id}: termination_reason: {termination_reason}"
        yield f"Analysis {self.analysis_id}: result: {result}"

    def mitre_attacks(self) -> Iterator[MitreAttack]:
        mitre_attack = self.report["mitre_attack"]
        techniques = mitre_attack["v4"]["techniques"]

        for technique_id, technique in techniques.items():
            mitre_attack = MitreAttack(
                description=technique["description"],
                id=technique_id.replace("technique_", ""),
            )
            yield mitre_attack

    def sandbox_type(self) -> str:
        sample_type = self.report["analysis_metadata"]["sample_type"]

        try:
            vm_information = self.report["virtual_machine"]["name"]
        except KeyError:
            return sample_type

        return f"{vm_information} | {sample_type}"

    def score(self) -> str:
        verdict = self.report["analysis_metadata"]["verdict"]
        return self.convert_verdict(verdict)

    def vtis(self) -> Iterator[VTI]:
        if "matches" not in self.report["vti"]:
            return

        vti_matches = self.report["vti"]["matches"]
        for vti in vti_matches.values():
            new_vti = VTI(
                category=vti["category_desc"],
                operation=vti["operation_desc"],
                technique=vti["technique_desc"],
                score=vti["analysis_score"],
            )

            yield new_vti


class VMRayMISPOrg(MISPOrganisation):  # pylint: disable=too-many-ancestors
    def __init__(self):
        super().__init__()

        self.name = "VMRay"
        self.uuid = "df351423-4bd8-497a-9ca1-0a749d5373ba"


class VMRayParserError(Exception):
    pass


class VMRayParser:
    def __init__(self, config: Config) -> None:
        vmray_conf = config.vmray
        self.api = VMRay(
            vmray_conf.host,
            vmray_conf.api_key,
            vmray_conf.verify_cert,
            vmray_conf.chunk_size,
        )
        self.last_submission_id = vmray_conf.last_submission_id

        self.misp_config = config.misp_event

    @staticmethod
    def _analysis_score_to_taxonomies(analysis_score: int) -> Optional[str]:
        mapping = {
            -1: "-1",
            1: "1/5",
            2: "2/5",
            3: "3/5",
            4: "4/5",
            5: "5/5",
        }

        try:
            return mapping[analysis_score]
        except KeyError:
            return None

    def _detector_analyses_only(self, submission_id: int) -> bool:
        analysis_results = self.api.get_analyses_by_submission(submission_id)
        return all(a["analysis_billing_type"] == "detector" for a in analysis_results)

    def _set_hash_and_verdict(self, event: MISPEvent, submissions_id: int) -> MISPEvent:
        verdict = self._get_sample_verdict(submissions_id)
        submission = self.api.get_submission(submissions_id)
        sample_id = submission["submission_sample_id"]
        sample_info = self.api.get_sample_info(sample_id)

        if verdict:
            is_ioc = verdict in ("malicious", "suspicious")

        # create file object
        file_artifact = FileArtifact(
            filenames=[sample_info["sample_filename"]],
            operations=[],
            md5=sample_info["sample_md5hash"],
            sha1=sample_info["sample_sha1hash"],
            sha256=sample_info["sample_sha256hash"],
            ssdeep=sample_info.get("sample_ssdeephash"),
            imphash=None,
            classifications=sample_info.get("sample_classifications", []),
            size=sample_info.get("sample_filesize", 0),
            mimetype=sample_info.get("sample_type"),
            verdict=verdict,
            is_ioc=is_ioc,
        )

        artifact_obj = file_artifact.to_misp_object(self.misp_config.use_vmray_tags)
        event.add_object(artifact_obj)

        # tag event
        if self.misp_config.use_vmray_tags and verdict:
            event.add_tag(f'vmray:verdict="{verdict}"')

        return event

    def _reports(
        self, submissions_id: int
    ) -> Iterator[Tuple[ReportParser, Optional[str]]]:
        analysis_results = self.api.get_analyses_by_submission(submissions_id)
        for analysis in analysis_results:
            # skip on error
            if analysis["analysis_result_str"] != "Operation completed successfully.":
                continue

            analysis_id = analysis["analysis_id"]
            permalink = analysis["analysis_webif_url"]

            try:
                report_parser = SummaryV2(api=self.api, analysis_id=analysis_id)
            except VMRayRESTAPIError:
                try:
                    report_parser = Summary(api=self.api, analysis_id=analysis_id)
                except VMRayRESTAPIError:
                    continue

            if report_parser.is_static_report():
                continue

            yield report_parser, permalink

    def _get_sample_verdict(self, submission_id: int) -> Optional[str]:
        data = self.api.get_submission(submission_id)

        if "submission_verdict" in data:
            verdict = SummaryV2.convert_verdict(data["submission_verdict"])
            return verdict

        if "submission_severity" in data:
            verdict = Summary.to_verdict(data["submission_severity"])
            return verdict

        return None

    def last_submissions(self) -> Iterator[dict]:
        submissions = self.api.get_submissions(self.last_submission_id)
        for submission in submissions:
            yield submission

    def parse(self, submission_id: int) -> MISPEvent:
        """ Convert analysis results to MISP Objects """

        event = MISPEvent()
        event.info = f"VMRay Platform report for submission {submission_id}"
        event.orgc = VMRayMISPOrg()
        mitre_attacks = []
        vtis = []
        artifacts = []

        # add sandbox signature
        sb_sig = MISPObject(name="sb-signature")
        sb_sig.add_attribute("software", "VMRay Platform")

        reports = list(self._reports(submission_id))
        if self._detector_analyses_only(submission_id) or len(reports) == 0:
            return self._set_hash_and_verdict(event, submission_id)

        for report, permalink in reports:
            # create sandbox object
            obj = MISPObject(name="sandbox-report")
            obj.add_attribute("on-premise-sandbox", "vmray")

            if permalink:
                obj.add_attribute("permalink", permalink)

            if self.misp_config.include_report:
                report_data = base64.b64encode(
                    json.dumps(report.report, indent=2).encode("utf-8")
                ).decode("utf-8")
                obj.add_attribute(
                    "sandbox-file", value="summary.json", data=report_data
                )

            score = report.score()
            attr_score = obj.add_attribute("score", score)

            if self.misp_config.use_vmray_tags:
                attr_score.add_tag(f'vmray:verdict="{score}"')

            sandbox_type = report.sandbox_type()
            obj.add_attribute("sandbox-type", sandbox_type)

            classifications = report.classifications()
            if classifications:
                obj.add_attribute("results", classifications)

            event.add_object(obj)

            if self.misp_config.include_vtis:
                for vti in report.vtis():
                    if vti not in vtis:
                        vtis.append(vti)

            for artifact in report.artifacts():
                if self.misp_config.ioc_only and not artifact.is_ioc:
                    continue

                if artifact not in artifacts:
                    artifacts.append(artifact)
                else:
                    idx = artifacts.index(artifact)
                    dup = artifacts[idx]
                    dup.merge(artifact)

            for mitre_attack in report.mitre_attacks():
                if mitre_attack not in mitre_attacks:
                    mitre_attacks.append(mitre_attack)

        # process VTI's
        for vti in vtis:
            vti_text = f"{vti.category}: {vti.operation}. {vti.technique}"
            vti_attr = sb_sig.add_attribute("signature", value=vti_text)

            if self.misp_config.use_vmray_tags:
                value = self._analysis_score_to_taxonomies(vti.score)
                if value:
                    vti_attr.add_tag(f'vmray:vti_analysis_score="{value}"')

        if self.misp_config.include_vtis:
            event.add_object(sb_sig)

        # process artifacts
        for artifact in artifacts:
            artifact_obj = artifact.to_misp_object(self.misp_config.use_vmray_tags)
            event.add_object(artifact_obj)

        # tag event with Mitre Att&ck
        for mitre_attack in mitre_attacks:
            event.add_tag(mitre_attack.to_misp_galaxy())

        # tag event
        if self.misp_config.use_vmray_tags:
            verdict = self._get_sample_verdict(submission_id)
            if verdict:
                event.add_tag(f'vmray:verdict="{verdict}"')

        return event
