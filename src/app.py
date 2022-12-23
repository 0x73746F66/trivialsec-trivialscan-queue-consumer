import json
from copy import deepcopy
from pathlib import Path
from datetime import datetime
from secrets import token_urlsafe
from typing import Optional

from pusher import Pusher
from trivialscan import trivialscan
from trivialscan.cli.__main__ import __version__ as trivialscan_version
from pydantic import (
    BaseModel,
    AnyHttpUrl,
    PositiveInt,
    PositiveFloat,
    EmailStr,
)
from pydantic.networks import (
    IPv4Address,
    IPv6Address,
)

import internals
import models
import services.aws
import services.sendgrid


class EventAttributes(BaseModel):
    ApproximateReceiveCount: int
    SentTimestamp: datetime
    SenderId: str
    ApproximateFirstReceiveTimestamp: datetime

class Event(BaseModel):
    messageId: str
    receiptHandle: str
    eventSource: str
    eventSourceARN: str
    awsRegion: str
    hostname: str
    port: int
    type: models.ScanRecordType
    md5OfBody: str
    http_paths: list[str]
    attributes: EventAttributes
    account_name: str
    queued_by: Optional[str]
    queued_timestamp: datetime

    def __init__(self, **kwargs):
        body = json.loads(kwargs["body"])
        kwargs["account_name"] = kwargs["messageAttributes"]["account"]["stringValue"]
        kwargs["http_paths"] = kwargs["messageAttributes"]["http_paths"]["stringValue"].split(',')
        if kwargs["messageAttributes"].get("queued_by"):
            kwargs["queued_by"] = kwargs["messageAttributes"]["queued_by"]["stringValue"]
        kwargs["queued_timestamp"] = int(kwargs["messageAttributes"]["queued_timestamp"]["stringValue"])
        kwargs["hostname"] = body['hostname']
        kwargs["port"] = body['port']
        kwargs["type"] = body['type']
        super().__init__(**kwargs)

class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(o, (
            PositiveInt,
            PositiveFloat,
        )):
            return int(o)
        if isinstance(o, (
            AnyHttpUrl,
            IPv4Address,
            IPv6Address,
            EmailStr,
        )):
            return str(o)

        return super(JSONEncoder, self).default(o)

def handler(event, context):
    pusher_client = Pusher(
        app_id='1529125',
        key='b8b37751841a44557ab2',
        secret='40e4e05c9f207f2cf3cc',
        cluster='ap4',
        ssl=True,
        json_encoder=JSONEncoder
    )
    for _record in event["Records"]:
        record = Event(**_record)
        internals.logger.info(f"Triggered by {record}")
        account = models.MemberAccountRedacted(name=record.account_name).load()
        scanner_record = models.ScannerRecord(account=account).load()  # type: ignore
        if not scanner_record or len(scanner_record.monitored_targets) == 0:
            internals.logger.warning("No queue data, so why did this trigger?")
            continue
        internals.logger.info(f"SCANNING {record.hostname}:{record.port}")
        pusher_client.trigger(scanner_record.account.name, 'trivial-scanner-status', {
            "status": "Started",
            "hostname": record.hostname,
            "port": record.port,
        })
        run_start = datetime.utcnow()
        transport = trivialscan(
            hostname=record.hostname,
            port=record.port,
            http_request_paths=record.http_paths,
        )
        execution_duration_seconds = (datetime.utcnow() - run_start).total_seconds()
        pusher_client.trigger(scanner_record.account.name, 'trivial-scanner-status', {
            "status": "Processing Result",
            "hostname": record.hostname,
            "port": record.port,
            "execution_duration_seconds": execution_duration_seconds,
        })
        data = transport.store.to_dict()
        if not data.get("tls"):
            internals.logger.info(
                f"No response from target: {record.hostname}:{record.port}"
            )
            continue

        internals.logger.info(
            f"Negotiated {transport.store.tls_state.negotiated_protocol} {transport.store.tls_state.peer_address}"
        )
        if internals.BUILD_ENV == "local":
            file_path = f".{internals.BUILD_ENV}/reports/{record.hostname}-{record.port}/scan.json"
            internals.logger.info(f"Save local file: {file_path}")
            handle = Path(file_path)
            handle.write_text(json.dumps(data, indent=4, default=str), "utf8")

        certificates: dict[str, models.Certificate] = {}
        if "certificates" in data:
            del data["certificates"]
        for cert_data in data["tls"].get("certificates", []):
            cert = models.Certificate(**cert_data)  # type: ignore
            internals.logger.info(f"Storing certificate data {cert.sha1_fingerprint}")
            if not cert.save():
                internals.logger.warning(
                    f"Certificate failed to save {cert.sha1_fingerprint}"
                )
            internals.logger.info(f"Storing certificate PEM {cert.sha1_fingerprint}")
            if not services.aws.store_s3(f"{internals.APP_ENV}/certificates/{cert.sha1_fingerprint}.pem", cert_data["pem"]):  # type: ignore
                internals.logger.warning(
                    f"Certificate PEM failed to save {cert.sha1_fingerprint}"
                )
            certificates[cert.sha1_fingerprint] = cert

        if "targets" in data:
            del data["targets"]
        host_data = deepcopy(data)
        host_data["tls"]["certificates"] = list(certificates.keys())
        host = models.Host(**host_data)  # type: ignore
        if not host.save():
            internals.logger.info(
                f"Storing Host {record.hostname}:{record.port} {host.transport.peer_address}"
            )

        report_id = token_urlsafe(56)
        report = models.ReportSummary(
            generator=internals.APP_NAME,
            version=trivialscan_version,
            date=datetime.utcnow().replace(microsecond=0).isoformat(),
            execution_duration_seconds=execution_duration_seconds,
            report_id=report_id,
            results_uri=f"/result/{report_id}/detail",
            account_name=scanner_record.account.name,
            targets=[host],
            certificates=list(certificates.values()),
            type=record.type,
            category=models.ScanRecordCategory.RECONNAISSANCE,
            is_passive=True,
            **data,
        )
        if internals.BUILD_ENV == "local":
            file_path = f".{internals.BUILD_ENV}/reports/{record.hostname}-{record.port}/summary.json"
            internals.logger.info(f"Save local file: {file_path}")
            handle = Path(file_path)
            handle.write_text(json.dumps(report.dict(), indent=4, default=str), "utf8")

        groups = {
            (data["compliance"], data["version"])
            for evaluation in data["evaluations"]
            for data in evaluation["compliance"]
            if isinstance(data, dict)
        }
        full_report = models.FullReport(**report.dict())  # type: ignore
        for evaluation in data["evaluations"]:
            if evaluation.get("description"):
                del evaluation["description"]

            compliance_results = []
            for uniq_group in groups:
                name, ver = uniq_group
                group = models.ComplianceGroup(compliance=name, version=ver, items=[])
                for compliance_data in evaluation["compliance"]:
                    if (
                        compliance_data["compliance"] != name
                        or compliance_data["version"] != ver
                    ):
                        continue
                    group.items.append(
                        models.ComplianceItem(
                            requirement=compliance_data.get("requirement"),
                            title=compliance_data.get("title"),
                        )
                    )
                if len(group.items) > 0:
                    compliance_results.append(group)

            evaluation["compliance"] = compliance_results

            threats = []
            for threat in evaluation.get("threats", []) or []:
                if threat.get("description"):
                    del threat["description"]
                if threat.get("technique_description"):
                    del threat["technique_description"]
                if threat.get("sub_technique_description"):
                    del threat["sub_technique_description"]
                threats.append(models.ThreatItem(**threat))
            evaluation["threats"] = threats
            references = evaluation.get("references", []) or []
            del evaluation["references"]
            item = models.EvaluationItem(
                generator=full_report.generator,
                version=full_report.version,
                account_name=scanner_record.account.name,  # type: ignore
                client_name=full_report.client_name,
                report_id=report_id,
                observed_at=full_report.date,
                transport=host.transport,
                references=[
                    models.ReferenceItem(name=ref["name"], url=ref["url"])
                    for ref in references
                ],
                **evaluation,
            )
            if item.group == "certificate" and item.metadata.get("sha1_fingerprint"):
                if item.metadata.get("sha1_fingerprint") not in certificates:
                    certificates[item.metadata.get("sha1_fingerprint")] = models.Certificate(sha1_fingerprint=item.metadata.get("sha1_fingerprint")).load()  # type: ignore
                item.certificate = certificates[item.metadata.get("sha1_fingerprint")]

            full_report.evaluations.append(item)
        if not full_report.save():
            internals.logger.critical(f"Error storing full report: {report_id}")
            continue
        if internals.BUILD_ENV == "local":
            file_path = f".{internals.BUILD_ENV}/reports/{record.hostname}-{record.port}/full.json"
            internals.logger.info(f"Save local file: {file_path}")
            handle = Path(file_path)
            handle.write_text(json.dumps(full_report.dict(), indent=4, default=str), "utf8")

        internals.logger.info(f"SUCCESS {report_id}")
        scanner_record.history.append(report)
        if not scanner_record.save():
            internals.logger.error(
                "ScannerRecord failed to delete target and save history, this will cause duplicate scanning issues"
            )
            continue
        if record.queued_by:
            internals.logger.info("Emailing result")
            sendgrid = services.sendgrid.send_email(
                subject=f"On-demand scanning complete {record.hostname}:{record.port}",
                recipient=record.queued_by,
                template="scan_completed",
                data={
                    'hostname': record.hostname,
                    'port': record.port,
                    'results_uri': report.results_uri,
                    'score': report.score,
                    'pass_result': report.results.get('pass', 0),
                    'info_result': report.results.get('info', 0),
                    'warn_result': report.results.get('warn', 0),
                    'fail_result': report.results.get('fail', 0),
                },
            )
            if sendgrid._content:  # pylint: disable=protected-access
                res = json.loads(
                    sendgrid._content.decode()  # pylint: disable=protected-access
                )
                if isinstance(res, dict) and res.get("errors"):
                    internals.logger.error(res.get("errors"))
                    continue

        internals.logger.info("Push result")
        pusher_client.trigger(scanner_record.account.name, 'trivial-scanner-status', {
            "status": "Complete",
            "generator": report.generator,
            "version": report.version,
            "report_id": report.report_id,
            "targets": [{
                "transport": {
                    'hostname': record.hostname,
                    'port': record.port,
                }
            }],
            "date": report.date,
            "results": report.results,
            "certificates": [cert.sha1_fingerprint for cert in report.certificates],
            "results_uri": report.results_uri,
            "type": report.type,
            "category": report.category,
            "is_passive": report.is_passive,
        })
