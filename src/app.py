import json
from copy import deepcopy
from pathlib import Path
from datetime import datetime
from secrets import token_urlsafe

from trivialscan import trivialscan
from trivialscan.cli.__main__ import __version__ as trivialscan_version

import internals
import services.aws


def handler(event, context):
    trigger_object: str = event["Records"][0]["s3"]["object"]["key"]
    internals.logger.info(f"Triggered by {trigger_object}")
    if not trigger_object.startswith(internals.APP_ENV):
        internals.logger.critical(f"Wrong APP_ENV, expected {internals.APP_ENV}")
        return
    if not trigger_object.startswith(f"{internals.APP_ENV}/accounts/"):
        internals.logger.critical("Bad prefix path")
        return
    if not trigger_object.endswith("on-demand-queue.json"):
        internals.logger.critical("Bad suffix path")
        return

    queue = None
    if raw := services.aws.get_s3(path_key=trigger_object):
        try:
            model_data = json.loads(raw)
            queue = internals.Queue(**model_data)
        except json.JSONDecodeError as err:
            internals.logger.warning(err, exc_info=True)
    if not queue or len(queue.targets) == 0:
        internals.logger.warning("No queue data, so why did this trigger?")
        return
    scan_target = None
    for target in queue.targets:
        if not target.scan_timestamp:
            target.scan_timestamp = datetime.utcnow().timestamp() * 1000
            scan_target = target.copy()
            break
    if not scan_target:
        internals.logger.warning(
            "Nothing to scan, the next line is probably what triggered this"
        )
        return
    if not queue.save():
        internals.logger.error(
            "Queue failed to save, this will cause duplicate scanning issues"
        )

    internals.logger.info(f"SCANNING {scan_target.hostname}:{scan_target.port}")
    run_start = datetime.utcnow()
    transport = trivialscan(
        hostname=scan_target.hostname,
        port=scan_target.port,
        http_request_paths=scan_target.http_paths,
    )
    execution_duration_seconds = (datetime.utcnow() - run_start).total_seconds()
    data = transport.store.to_dict()
    if not data.get("tls"):
        internals.logger.info(
            f"No response from target: {scan_target.hostname}:{scan_target.port}"
        )
        queue_targets = []
        for target in queue.targets:
            if (
                target.hostname == scan_target.hostname
                and target.port == scan_target.port
            ):
                continue
            queue_targets.append(target)
        queue.targets = queue_targets
        if not queue.save():
            internals.logger.error(
                "Queue failed to save, this will cause duplicate scanning issues"
            )
        return

    internals.logger.info(
        f"Negotiated {transport.store.tls_state.negotiated_protocol} {transport.store.tls_state.peer_address}"
    )
    if internals.BUILD_ENV == "local":
        internals.logger.info(f"Save local file: .{internals.BUILD_ENV}/report.json")
        handle = Path(f"./.{internals.BUILD_ENV}/report.json")
        handle.write_text(json.dumps(data, indent=4, default=str), "utf8")

    certificates = {}
    for certdata in data["tls"].get("certificates", []):
        cert = internals.Certificate(**certdata)  # type: ignore
        internals.logger.info(f"Storing certificate data {cert.sha1_fingerprint}")
        if not cert.save():
            internals.logger.warning(
                f"Certificate failed to save {cert.sha1_fingerprint}"
            )
        internals.logger.info(f"Storing certificate PEM {cert.sha1_fingerprint}")
        if not services.aws.store_s3(f"{internals.APP_ENV}/certificates/{cert.sha1_fingerprint}.pem", certdata["pem"]):  # type: ignore
            internals.logger.warning(
                f"Certificate PEM failed to save {cert.sha1_fingerprint}"
            )
        certificates[cert.sha1_fingerprint] = cert

    host_data = deepcopy(data)
    host_data["tls"]["certificates"] = list(certificates.keys())
    host = internals.Host(**host_data)  # type: ignore
    if not host.save():
        internals.logger.info(
            f"Storing Host {host.transport.hostname}:{host.transport.port} {host.transport.peer_address}"
        )

    report_id = token_urlsafe(56)
    report = internals.ReportSummary(
        generator=internals.APP_NAME,
        version=trivialscan_version,
        date=datetime.utcnow().replace(microsecond=0).isoformat(),
        execution_duration_seconds=execution_duration_seconds,
        report_id=report_id,
        results_uri=f"/result/{report_id}/detail",
        account_name=queue.account.name,
        targets=[host],
        **data,
    )
    if not report.save():
        internals.logger.critical(f"Error storing full report: {report_id}")
        return

    groups = {
        (data["compliance"], data["version"])
        for evaluation in data["evaluations"]
        for data in evaluation["compliance"]
        if isinstance(data, dict)
    }
    full_report = internals.FullReport(**report.dict())  # type: ignore
    for evaluation in data["evaluations"]:
        if evaluation.get("description"):
            del evaluation["description"]

        compliance_results = []
        for uniq_group in groups:
            name, ver = uniq_group
            group = internals.ComplianceGroup(compliance=name, version=ver, items=[])
            for compliance_data in evaluation["compliance"]:
                if (
                    compliance_data["compliance"] != name
                    or compliance_data["version"] != ver
                ):
                    continue
                group.items.append(
                    internals.ComplianceItem(
                        requirement=compliance_data.get("requirement"),
                        title=compliance_data.get("title"),
                    )
                )
            if len(group.items) > 0:
                compliance_results.append(group)

        evaluation["compliance"] = compliance_results

        threats = []
        for threat in data.get("threats", []) or []:
            if threat.get("description"):
                del threat["description"]
            if threat.get("technique_description"):
                del threat["technique_description"]
            if threat.get("sub_technique_description"):
                del threat["sub_technique_description"]
            threats.append(internals.ThreatItem(**threat))
        evaluation["threats"] = threats
        references = evaluation.get("references", []) or []
        del evaluation["references"]
        item = internals.EvaluationItem(
            generator=full_report.generator,
            version=full_report.version,
            account_name=queue.account.name,  # type: ignore
            client_name=full_report.client_name,
            report_id=report_id,
            observed_at=full_report.date,
            transport=host.transport,
            references=[
                internals.ReferenceItem(name=ref["name"], url=ref["url"])
                for ref in references
            ],
            **evaluation,
        )
        if item.group == "certificate" and item.metadata.get("sha1_fingerprint"):
            if item.metadata.get("sha1_fingerprint") not in certificates:
                certificates[item.metadata.get("sha1_fingerprint")] = internals.Certificate(sha1_fingerprint=item.metadata.get("sha1_fingerprint")).load()  # type: ignore
            item.certificate = certificates[item.metadata.get("sha1_fingerprint")]

        full_report.evaluations.append(item)
    if not full_report.save():
        internals.logger.critical(f"Error storing full report: {report_id}")
        return

    internals.logger.info(f"SUCCESS {report_id}")
    queue_targets = []
    for target in queue.targets:
        if target.hostname == scan_target.hostname and target.port == scan_target.port:
            continue
        queue_targets.append(target)
    queue.targets = queue_targets
    if not queue.save():
        internals.logger.error(
            "Queue failed to save, this will cause duplicate scanning issues"
        )

    scans_map: dict[str, dict[str, list[str]]] = {}
    object_key = f"{internals.APP_ENV}/accounts/{queue.account.name}/scan-history.json"  # type: ignore
    if history_raw := services.aws.get_s3(path_key=object_key):
        scans_map: dict[str, dict[str, list[str]]] = json.loads(history_raw)
    for _target in full_report.targets or []:
        target = f"{_target.transport.hostname}:{_target.transport.port}"
        scans_map.setdefault(target, {"reports": []})  # type: ignore
        scans_map[target]["reports"].append(report.report_id)  # type: ignore
    if not services.aws.store_s3(object_key, json.dumps(scans_map, default=str)):
        internals.logger.error(
            f"Error storing scan-history.json for account {queue.account.name}"
        )
