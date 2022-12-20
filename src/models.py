# pylint: disable=no-self-argument, arguments-differ
import json
from datetime import datetime
from enum import Enum
from typing import Union, Any, Optional
from abc import ABCMeta, abstractmethod

from pydantic import (
    BaseModel,
    Field,
    AnyHttpUrl,
    validator,
    conint,
    PositiveInt,
    PositiveFloat,
    IPvAnyAddress,
    EmailStr,
)

import internals
import services.aws


class DAL(metaclass=ABCMeta):
    @abstractmethod
    def load(self, **kwargs) -> Union[BaseModel, None]:
        raise NotImplementedError

    @abstractmethod
    def save(self, **kwargs) -> bool:
        raise NotImplementedError


class MemberAccount(BaseModel, DAL):
    name: str
    display: Optional[str]
    primary_email: Optional[EmailStr]
    billing_email: Optional[EmailStr]
    api_key: Optional[str]
    ip_addr: Union[IPvAnyAddress, None] = Field(default=None)
    user_agent: Union[str, None] = Field(default=None)
    timestamp: Optional[int]

    def exists(self, account_name: Union[str, None] = None) -> bool:
        return self.load(account_name) is not None

    def load(
        self, account_name: Union[str, None] = None
    ) -> Union["MemberAccount", None]:
        if account_name:
            self.name = account_name
        if not self.name:
            return
        object_key = f"{internals.APP_ENV}/accounts/{self.name}/registration.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing account object: {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing account data for object: {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/accounts/{self.name}/registration.json"
        return services.aws.store_s3(
            object_key,
            json.dumps(self.dict(), default=str),
            storage_class=services.aws.StorageClass.STANDARD,
        )

    def delete(self) -> Union[bool, None]:
        object_key = f"{internals.APP_ENV}/accounts/{self.name}/registration.json"
        return services.aws.delete_s3(object_key)


class MemberAccountRedacted(MemberAccount):
    class Config:
        validate_assignment = True

    @validator("api_key")
    def set_api_key(cls, _):
        return None


class DefaultInfo(BaseModel):
    generator: str = Field(default="trivialscan")
    version: Union[str, None] = Field(
        default=None, description="trivialscan CLI version"
    )
    account_name: Union[str, None] = Field(
        default=None, description="Trivial Security account name"
    )
    client_name: Union[str, None] = Field(
        default=None, description="Machine name where trivialscan CLI executes"
    )


class ConfigDefaults(BaseModel):
    use_sni: bool
    cafiles: Union[str, None] = Field(default=None)
    tmp_path_prefix: str = Field(default=internals.CACHE_DIR)
    http_path: str = Field(default="/")
    checkpoint: Optional[bool]


class OutputType(str, Enum):
    JSON = "json"
    CONSOLE = "console"


class OutputWhen(str, Enum):
    FINAL = "final"
    PER_HOST = "per_host"
    PER_CERTIFICATE = "per_certificate"


class CertificateType(str, Enum):
    ROOT = "root"
    INTERMEDIATE = "intermediate"
    LEAF = "leaf"
    CLIENT = "client"


class ValidationLevel(str, Enum):
    DOMAIN_VALIDATION = "Domain Validation (DV)"
    ORGANIZATION_VALIDATION = "Organization Validation (OV)"
    EXTENDED_VALIDATION = "Extended Validation (EV)"


class PublicKeyType(str, Enum):
    RSA = "RSA"
    DSA = "DSA"
    EC = "EC"
    DH = "DH"


class GraphLabelRanges(str, Enum):
    WEEK = "week"
    MONTH = "month"
    YEAR = "year"


class GraphLabel(str, Enum):
    PCIDSS3 = "PCI DSS v3.2.1"
    PCIDSS4 = "PCI DSS v4.0"
    NISTSP800_131A_STRICT = "NIST SP800-131A (strict mode)"
    NISTSP800_131A_TRANSITION = "NIST SP800-131A (transition mode)"
    FIPS1402 = "FIPS 140-2 Annex A"


class ClientInfo(BaseModel):
    operating_system: Optional[str]
    operating_system_release: Optional[str]
    operating_system_version: Optional[str]
    architecture: Optional[str]


class ConfigOutput(BaseModel):
    type: OutputType
    use_icons: Union[bool, None]
    when: OutputWhen = Field(default=OutputWhen.FINAL)
    path: Union[str, None] = Field(default=None)


class ConfigTarget(BaseModel):
    hostname: str
    port: PositiveInt = Field(default=443)
    client_certificate: Union[str, None] = Field(default=None)
    http_request_paths: list[str] = Field(default=["/"])


class Config(BaseModel):
    account_name: Union[str, None] = Field(
        default=None, description="Trivial Security account name"
    )
    client_name: Union[str, None] = Field(
        default=None, description="Machine name where trivialscan CLI execcutes"
    )
    project_name: Union[str, None] = Field(
        default=None, description="Trivial Scanner project assignment for the report"
    )
    defaults: ConfigDefaults
    outputs: list[ConfigOutput]
    targets: list[ConfigTarget]


class Flags(BaseModel):
    hide_progress_bars: Optional[bool]
    synchronous_only: Optional[bool]
    hide_banner: Optional[bool]
    track_changes: Optional[bool]
    previous_report: Union[str, None]
    quiet: Optional[bool]


class HostTLSProtocol(BaseModel):
    negotiated: str
    preferred: str
    offered: list[str]


class HostTLSCipher(BaseModel):
    forward_anonymity: Union[bool, None] = Field(default=False)
    offered: list[str]
    offered_rfc: list[str]
    negotiated: str
    negotiated_bits: PositiveInt
    negotiated_rfc: str


class HostTLSClient(BaseModel):
    certificate_mtls_expected: Union[bool, None] = Field(default=False)
    certificate_trusted: Union[bool, None] = Field(default=False)
    certificate_match: Union[bool, None] = Field(default=False)
    expected_client_subjects: list[str] = Field(default=[])


class HostTLSSessionResumption(BaseModel):
    cache_mode: str
    tickets: bool
    ticket_hint: bool


class HostTLS(BaseModel):
    certificates: list[str] = Field(default=[])
    client: HostTLSClient
    cipher: HostTLSCipher
    protocol: HostTLSProtocol
    session_resumption: HostTLSSessionResumption


class HostHTTP(BaseModel):
    title: str
    status_code: conint(ge=100, le=599)  # type: ignore
    headers: dict[str, str]
    body_hash: str


class HostTransport(BaseModel):
    error: Optional[tuple[str, str]]
    hostname: str = Field(title="Domain Name")
    port: PositiveInt = Field(default=443)
    sni_support: Optional[bool]
    peer_address: Optional[IPvAnyAddress]
    certificate_mtls_expected: Union[bool, None] = Field(default=False)


class Host(BaseModel, DAL):
    last_updated: Optional[datetime]
    transport: HostTransport
    tls: Optional[HostTLS]
    http: Optional[list[HostHTTP]]

    def load(
        self,
        hostname: Union[str, None] = None,
        port: Union[int, None] = 443,
        peer_address: Union[str, None] = None,
        last_updated: Union[datetime, None] = None,
    ) -> Union["Host", None]:
        if last_updated:
            self.last_updated = last_updated
        if hostname:
            self.transport = HostTransport(hostname=hostname, port=port, peer_address=peer_address)  # type: ignore

        prefix_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}"
        if self.transport.peer_address and self.last_updated:
            scan_date = self.last_updated.strftime("%Y%m%d")
            object_key = f"{prefix_key}/{self.transport.peer_address}/{scan_date}.json"
        else:
            object_key = f"{prefix_key}/latest.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing Host {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing Host {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        scan_date = self.last_updated.strftime("%Y%m%d")  # type: ignore
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/{self.transport.peer_address}/{scan_date}.json"
        if not services.aws.store_s3(object_key, json.dumps(self.dict(), default=str)):
            return False
        object_key = f"{internals.APP_ENV}/hosts/{self.transport.hostname}/{self.transport.port}/latest.json"
        return services.aws.store_s3(object_key, json.dumps(self.dict(), default=str))


class Certificate(BaseModel, DAL):
    authority_key_identifier: Union[str, None] = Field(default=None)
    expired: Optional[bool]
    expiry_status: Optional[str]
    extensions: Optional[list] = Field(default=[])
    external_refs: Optional[dict[str, Union[AnyHttpUrl, None]]] = Field(default={})
    is_self_signed: Optional[bool]
    issuer: Optional[str]
    known_compromised: Optional[bool]
    md5_fingerprint: Optional[str]
    not_after: Optional[datetime]
    not_before: Optional[datetime]
    public_key_curve: Union[str, None] = Field(default=None)
    public_key_exponent: Union[PositiveInt, None] = Field(default=None)
    public_key_modulus: Union[PositiveInt, None] = Field(default=None)
    public_key_size: Optional[PositiveInt]
    public_key_type: Optional[PublicKeyType]
    revocation_crl_urls: Optional[list[AnyHttpUrl]] = Field(default=[])
    san: Optional[list[str]] = Field(default=[])
    serial_number: Optional[str]
    serial_number_decimal: Optional[Any]
    serial_number_hex: Optional[str]
    sha1_fingerprint: str
    sha256_fingerprint: Optional[str]
    signature_algorithm: Optional[str]
    spki_fingerprint: Optional[str]
    subject: Optional[str]
    subject_key_identifier: Optional[str]
    validation_level: Union[ValidationLevel, None] = Field(default=None)
    validation_oid: Union[str, None] = Field(default=None)
    version: Optional[Any] = Field(default=None)
    type: Optional[CertificateType]

    def load(
        self, sha1_fingerprint: Union[str, None] = None
    ) -> Union["Certificate", None]:
        if sha1_fingerprint:
            self.sha1_fingerprint = sha1_fingerprint

        object_key = f"{internals.APP_ENV}/certificates/{self.sha1_fingerprint}.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing Certificate {object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(f"Missing Certificate {object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        object_key = f"{internals.APP_ENV}/certificates/{self.sha1_fingerprint}.json"
        return services.aws.store_s3(object_key, json.dumps(self.dict(), default=str))


class ComplianceItem(BaseModel):
    requirement: Union[str, None] = Field(default=None)
    title: Union[str, None] = Field(default=None)
    description: Union[str, None] = Field(default=None)


class ComplianceName(str, Enum):
    PCI_DSS = "PCI DSS"
    NIST_SP800_131A = "NIST SP800-131A"
    FIPS_140_2 = "FIPS 140-2"


class ComplianceGroup(BaseModel):
    compliance: Optional[ComplianceName]
    version: Optional[str]
    items: Union[list[ComplianceItem], None] = Field(default=[])


class ThreatItem(BaseModel):
    standard: str
    version: str
    tactic_id: Union[str, None] = Field(default=None)
    tactic_url: Union[AnyHttpUrl, None] = Field(default=None)
    tactic: Union[str, None] = Field(default=None)
    description: Union[str, None] = Field(default=None)
    technique_id: Union[str, None] = Field(default=None)
    technique_url: Union[AnyHttpUrl, None] = Field(default=None)
    technique: Union[str, None] = Field(default=None)
    technique_description: Union[str, None] = Field(default=None)
    sub_technique_id: Union[str, None] = Field(default=None)
    sub_technique_url: Union[AnyHttpUrl, None] = Field(default=None)
    sub_technique: Union[str, None] = Field(default=None)
    sub_technique_description: Union[str, None] = Field(default=None)
    data_source_id: Union[str, None] = Field(default=None)
    data_source_url: Union[AnyHttpUrl, None] = Field(default=None)
    data_source: Union[str, None] = Field(default=None)


class ReferenceItem(BaseModel):
    name: str
    url: Union[AnyHttpUrl, None]


class ScanRecordType(str, Enum):
    MONITORING = "Managed Monitoring"
    ONDEMAND = "Managed On-demand"
    SELF_MANAGED = "Customer-managed"

class ScanRecordCategory(str, Enum):
    ASM = "Attack Surface Monitoring"
    RECONNAISSANCE = "Reconnaissance"
    OSINT = "Public Data Sources"
    INTEGRATION_DATA = "Third Party Integration"

class ReportSummary(DefaultInfo):
    report_id: str
    project_name: Union[str, None]
    targets: Union[list[str], list[Host]] = Field(default=[])
    date: Optional[datetime]
    execution_duration_seconds: Union[PositiveFloat, None] = Field(default=None)
    score: int = Field(default=0)
    results: Optional[dict[str, int]]
    certificates: Union[list[str], list[Certificate]] = Field(default=[])
    results_uri: Optional[str]
    flags: Union[Flags, None] = Field(default=None)
    config: Union[Config, None] = Field(default=None)
    client: Optional[Union[ClientInfo, None]] = Field(default=None)
    type: Union[ScanRecordType, None] = Field(default=None)
    category: Union[ScanRecordCategory, None] = Field(default=None)
    is_passive: Optional[bool] = Field(default=True)

class EvaluationItem(DefaultInfo):
    class Config:
        validate_assignment = True

    report_id: str
    rule_id: int
    group_id: int
    key: str
    name: str
    group: str
    observed_at: Union[datetime, None] = Field(default=None)
    result_value: Union[bool, str, None]
    result_label: str
    result_text: str
    result_level: Union[str, None] = Field(default=None)
    score: int = Field(default=0)
    description: Optional[str]
    metadata: dict[str, Any] = Field(default={})
    cve: Union[list[str], None] = Field(default=[])
    cvss2: Union[str, Any] = Field(default=None)
    cvss3: Union[str, Any] = Field(default=None)
    references: Union[list[ReferenceItem], None] = Field(default=[])
    compliance: Union[list[ComplianceGroup], None] = Field(default=[])
    threats: Union[list[ThreatItem], None] = Field(default=[])
    transport: Optional[HostTransport]
    certificate: Optional[Certificate]

    @validator("references")
    def set_references(cls, references):
        return [] if not isinstance(references, list) else references

    @validator("cvss2")
    def set_cvss2(cls, cvss2):
        return None if not isinstance(cvss2, str) else cvss2

    @validator("cvss3")
    def set_cvss3(cls, cvss3):
        return None if not isinstance(cvss3, str) else cvss3


class FullReport(ReportSummary, DAL):
    evaluations: Optional[list[EvaluationItem]] = Field(default=[])

    def load(
        self, report_id: Union[str, None] = None, account_name: Union[str, None] = None
    ) -> Union["FullReport", None]:
        if report_id:
            self.report_id = report_id
        if account_name:
            self.account_name = account_name

        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        raw = services.aws.get_s3(path_key=object_key)
        if not raw:
            internals.logger.warning(f"Missing FullReport {object_key}")
            return
        data = json.loads(raw)
        if data:
            super().__init__(**data)
        return self

    def save(self) -> bool:
        results: list[bool] = []
        object_key = f"{internals.APP_ENV}/accounts/{self.account_name}/results/{self.report_id}/full-report.json"
        results.append(
            services.aws.store_s3(
                object_key,
                json.dumps(self.dict(), default=str),
            )
        )
        return all(results)

class MonitorHostname(BaseModel):
    hostname: str
    timestamp: int
    enabled: bool = Field(default=False)

class ScannerRecord(BaseModel, DAL):
    account: MemberAccountRedacted
    monitored_targets: list[MonitorHostname] = Field(default=[])
    history: list[ReportSummary] = Field(default=[])

    @property
    def object_key(self):
        return f"{internals.APP_ENV}/accounts/{self.account.name}/scanner-record.json"

    def exists(self, account_name: Union[str, None] = None) -> bool:
        if account_name:
            self.account = MemberAccount(name=account_name).load()  # type: ignore
        return services.aws.object_exists(self.object_key) is True

    def load(self, account_name: Union[str, None] = None) -> Union['ScannerRecord', None]:
        if account_name:
            self.account = MemberAccount(name=account_name).load()  # type: ignore
        raw = services.aws.get_s3(path_key=self.object_key)
        if not raw:
            internals.logger.warning(f"Missing Queue {self.object_key}")
            return
        try:
            data = json.loads(raw)
        except json.decoder.JSONDecodeError as err:
            internals.logger.debug(err, exc_info=True)
            return
        if not data or not isinstance(data, dict):
            internals.logger.warning(
                f"Missing Queue {self.object_key}")
            return
        super().__init__(**data)
        return self

    def save(self) -> bool:
        return services.aws.store_s3(
            self.object_key,
            json.dumps(self.dict(), default=str)
        )

    def delete(self) -> bool:
        return services.aws.delete_s3(self.object_key)
