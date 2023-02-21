import json
from copy import deepcopy
from uuid import uuid5
from datetime import datetime, timezone
from secrets import token_urlsafe
from typing import Optional

from pusher import Pusher
from trivialscan import trivialscan
from trivialscan.cli.__main__ import __version__ as trivialscan_version
from pydantic import BaseModel

import internals
import models
import services.aws
import services.sendgrid
import services.webhook


class EventAttributes(BaseModel):
    ApproximateReceiveCount: int
    SentTimestamp: datetime
    SenderId: str
    ApproximateFirstReceiveTimestamp: datetime


class EventRecord(BaseModel):
    messageId: str
    receiptHandle: str
    eventSource: str
    eventSourceARN: str
    awsRegion: str
    hostname: str
    ports: list[int]
    type: models.ScanRecordType
    md5OfBody: str
    path_names: list[str]
    attributes: EventAttributes
    account_name: str
    queued_by: Optional[str]
    queued_timestamp: datetime

    def __init__(self, **kwargs):
        body = json.loads(kwargs["body"])
        kwargs["account_name"] = kwargs["messageAttributes"]["account"]["stringValue"]
        kwargs["path_names"] = body.get("path_names", ["/"])
        if kwargs["messageAttributes"].get("queued_by"):
            kwargs["queued_by"] = kwargs["messageAttributes"]["queued_by"]["stringValue"]
        kwargs["queued_timestamp"] = int(kwargs["messageAttributes"]["queued_timestamp"]["stringValue"])
        kwargs["hostname"] = body['hostname']
        kwargs["ports"] = body.get('ports', [body.get("port", 443)])
        kwargs["type"] = body['type']
        super().__init__(**kwargs)

def save_certificates(data: dict):
    for cert_data in data["tls"].get("certificates", []):
        cert = models.Certificate(**cert_data)  # type: ignore
        internals.logger.info(f"Storing certificate data {cert.sha1_fingerprint}")
        if not cert.save():
            internals.logger.error(
                f"Certificate failed to save {cert.sha1_fingerprint}"
            )
        internals.logger.info(f"Storing certificate PEM {cert.sha1_fingerprint}")
        if not services.aws.store_s3(f"{internals.APP_ENV}/certificates/{cert.sha1_fingerprint}.pem", cert_data["pem"]):  # type: ignore
            internals.logger.error(
                f"Certificate PEM failed to save {cert.sha1_fingerprint}"
            )

def process_certificates(data: dict) -> dict[str, models.Certificate]:
    certificates = {}
    for cert_data in data["tls"].get("certificates", []):
        cert = models.Certificate(**cert_data)  # type: ignore
        certificates[cert.sha1_fingerprint] = cert
    return certificates

def process_host(data: dict, event: EventRecord, port: int) -> models.Host:
    host_data = deepcopy(data)
    host_data["tls"]["certificates"] = list(process_certificates(data).keys())
    host = models.Host(**host_data)  # type: ignore
    if not host.save():
        internals.logger.error(
            f"Storing Host {event.hostname}:{port} {host.transport.peer_address}"
        )
    return host

def process_summary(
        certificates: list[models.Certificate],
        event: EventRecord,
        hosts: list[models.Host],
        report_id: str,
        observed_at: str,
        execution_duration_seconds: int,
        score: int,
        results: dict
    ) -> models.ReportSummary:
    return models.ReportSummary(
        generator=internals.APP_NAME,
        version=trivialscan_version,
        date=observed_at,
        execution_duration_seconds=execution_duration_seconds,
        report_id=report_id,
        results_uri=f"/result/{report_id}/detail",
        account_name=event.account_name,
        targets=hosts,
        certificates=certificates,
        type=event.type,
        category=models.ScanRecordCategory.RECONNAISSANCE,
        is_passive=True,
        score=score,
        results=results,
    )


def process_evaluations(data: dict, event: EventRecord, host: models.Host, report_id: str, observed_at: str) -> models.FullReport:
    groups = {
        (data["compliance"], data["version"])
        for evaluation in data["evaluations"]
        for data in evaluation["compliance"]
        if isinstance(data, dict)
    }
    evaluations = []
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
            generator=internals.APP_NAME,
            version=trivialscan_version,
            account_name=event.account_name,  # type: ignore
            report_id=report_id,
            observed_at=observed_at,
            transport=host.transport,
            references=[
                models.ReferenceItem(name=ref["name"], url=ref["url"])
                for ref in references
            ],
            **evaluation,
        )
        certificates = process_certificates(data)
        if item.group == "certificate" and item.metadata.get("sha1_fingerprint"):
            item.certificate = certificates[item.metadata.get("sha1_fingerprint")]

        evaluations.append(item)
    return evaluations

def handler(event, context):
    pusher_client = Pusher(
        app_id=services.aws.get_ssm(f"/{internals.APP_ENV}/{internals.APP_NAME}/Pusher/app-id"),
        key=services.aws.get_ssm(f"/{internals.APP_ENV}/{internals.APP_NAME}/Pusher/key"),
        secret=services.aws.get_ssm(f"/{internals.APP_ENV}/{internals.APP_NAME}/Pusher/secret", WithDecryption=True),
        cluster='ap4',
        ssl=True,
        json_encoder=internals.JSONEncoder
    )
    for _record in event["Records"]:
        record = EventRecord(**_record)
        internals.logger.info(f"Triggered by {record}")
        account_secret = models.MemberAccount(name=record.account_name)
        if not account_secret.load():
            internals.logger.info(f"Missing account {record.account_name}")
            continue
        account = models.MemberAccountRedacted(**account_secret.dict())
        report_id = token_urlsafe(32)
        observed_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
        hosts = []
        all_evaluations = []
        all_certificates = {}
        run_start = datetime.now(timezone.utc)
        scores = []
        all_results = {
            "pass": 0,
            "info": 0,
            "warn": 0,
            "fail": 0,
        }
        for port in record.ports:
            internals.logger.info(f"SCANNING {record.hostname}:{port}")
            pusher_client.trigger(record.account_name, 'trivial-scanner-status', {
                "status": "Started",
                "type": record.type.value,
                "hostname": record.hostname,
                "port": port,
            })
            services.webhook.send(
                event_name=models.WebhookEvent.HOSTED_SCANNER
                if record.type == models.ScanRecordType.ONDEMAND
                else models.WebhookEvent.HOSTED_MONITORING,
                account=account_secret,
                data={
                    "hostname": record.hostname,
                    "port": port,
                    "type": record.type.value,
                    'status': "starting",
                    'account': record.account_name,
                    'queued_timestamp': datetime.now(timezone.utc).timestamp()
                    * 1000,
                },
            )
            transport = trivialscan(
                hostname=record.hostname,
                port=port,
                http_request_paths=record.path_names,
            )
            pusher_client.trigger(
                record.account_name,
                'trivial-scanner-status',
                {
                    "status": "Processing Result",
                    "type": record.type.value,
                    "hostname": record.hostname,
                    "port": port,
                    "elapsed_duration_seconds": (
                        datetime.now(timezone.utc) - run_start
                    ).total_seconds(),
                },
            )
            data = transport.store.to_dict()
            if "certificates" in data:
                del data["certificates"]
            if "targets" in data:
                del data["targets"]
            services.webhook.send(
                event_name=models.WebhookEvent.HOSTED_SCANNER
                if record.type == models.ScanRecordType.ONDEMAND
                else models.WebhookEvent.HOSTED_MONITORING,
                account=account_secret,
                data={
                    "hostname": record.hostname,
                    "port": port,
                    "type": record.type.value,
                    'status': "result",
                    'account': record.account_name,
                    'queued_timestamp': datetime.now(timezone.utc).timestamp()
                    * 1000,
                    'result': data,
                },
            )
            if data.get("tls"):
                internals.logger.info(
                    f"Negotiated {transport.store.tls_state.negotiated_protocol} {transport.store.tls_state.peer_address}"
                )
                scores.append(int(data.get('score', 0)))
                all_results["pass"] += data.get('results', {}).get("pass", 0)
                all_results["fail"] += data.get('results', {}).get("fail", 0)
                all_results["warn"] += data.get('results', {}).get("warn", 0)
                all_results["info"] += data.get('results', {}).get("info", 0)
                host = process_host(data, record, port)
                hosts.append(host)
                all_evaluations.extend(process_evaluations(data, record, host, report_id, observed_at))
                certificates = process_certificates(data)
                all_certificates = {**all_certificates, **certificates}

        execution_duration_seconds = (
            datetime.now(timezone.utc) - run_start
        ).total_seconds()
        report = process_summary(list(all_certificates.values()), record, hosts, report_id, observed_at, execution_duration_seconds, sum(scores), all_results)
        full_report = models.FullReport(**report.dict())
        full_report.evaluations = all_evaluations
        if not full_report.save():
            internals.logger.error(
                f"Storing FullReport {report.report_id}"
            )

        internals.logger.info(f"SUCCESS {report.report_id}")
        if record.type == models.ScanRecordType.INTERNAL:
            continue
        if not services.aws.put_dynamodb(table_name=services.aws.Tables.REPORT_HISTORY, item=report.dict()):
            internals.logger.error(
                "ReportSummary failed to save, this will cause duplicate scanning issues"
            )
            continue

        for host in full_report.targets:
            item = models.ObservedIdentifier(
                id=uuid5(namespace=internals.NAMESPACE, name=f"{account.name}{host.transport.peer_address}"),
                account_name=account.name,
                source=models.ObservedSource.TRIVIAL_SCANNER,
                source_data={
                    'hostname': host.transport.hostname,
                    'report_id': report.report_id,
                    'cli_version': report.version,
                    'report_date': report.date,
                },
                address=host.transport.peer_address,
                date=datetime.now(timezone.utc).timestamp() * 1000
            )
            services.aws.put_dynamodb(
                table_name=services.aws.Tables.OBSERVED_IDENTIFIERS,
                item=item.dict()
            )

        if record.queued_by and account.notifications.scan_completed:
            internals.logger.info("Emailing result")
            sendgrid = services.sendgrid.send_email(
                subject=f"On-demand scanning complete {record.hostname}",
                recipient=record.queued_by,
                template="scan_completed",
                data={
                    'hostname': record.hostname,
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

        if account.notifications.monitor_completed and report.type == models.ScanRecordType.MONITORING:
            internals.logger.info("Emailing result")
            email_subject = f"Monitoring scanner complete {record.hostname}"
            sendgrid = services.sendgrid.send_email(
                subject=email_subject,
                recipient=account.primary_email,
                template="scan_completed",
                data={
                    'hostname': record.hostname,
                    'results_uri': report.results_uri,
                    'execution_duration_seconds': execution_duration_seconds,
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
        if record.type != models.ScanRecordType.INTERNAL:
            internals.logger.info("Push result")
            pusher_client.trigger(full_report.account_name, 'trivial-scanner-status', {
                "status": "Complete",
                "generator": full_report.generator,
                "version": full_report.version,
                "report_id": full_report.report_id,
                "execution_duration_seconds": execution_duration_seconds,
                "targets": [{
                    "transport": {
                        'hostname': h.transport.hostname,
                        'port': h.transport.port,
                    }
                } for h in full_report.targets],
                "date": full_report.date,
                "results": full_report.results,
                "certificates": [cert.sha1_fingerprint for cert in full_report.certificates],
                "results_uri": full_report.results_uri,
                "type": full_report.type,
                "category": full_report.category,
                "is_passive": full_report.is_passive,
            })
            services.webhook.send(
                event_name=models.WebhookEvent.HOSTED_SCANNER
                if record.type == models.ScanRecordType.ONDEMAND
                else models.WebhookEvent.HOSTED_MONITORING,
                account=account_secret,
                data={
                    "generator": full_report.generator,
                    "version": full_report.version,
                    "type": record.type.value,
                    "category": full_report.category,
                    "is_passive": full_report.is_passive,
                    "status": "complete",
                    'account': record.account_name,
                    'queued_timestamp': datetime.now(timezone.utc).timestamp()
                    * 1000,
                    "report_id": full_report.report_id,
                    "results_uri": full_report.results_uri,
                    "targets": [
                        {
                            "transport": {
                                'hostname': h.transport.hostname,
                                'port': h.transport.port,
                            }
                        }
                        for h in full_report.targets
                    ],
                    "execution_duration_seconds": execution_duration_seconds,
                },
            )
