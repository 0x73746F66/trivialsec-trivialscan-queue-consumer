import contextlib
import sys
import json
import logging
import argparse
from datetime import datetime, timezone
from os import getenv
from pathlib import Path
from uuid import uuid4

from rich.logging import RichHandler

import app
import internals

AWS_ACCOUNT = getenv("AWS_ACCOUNT", default="984310022655")
AWS_REGION = getenv("AWS_REGION", default="ap-southeast-2")

def cli():
    now = datetime.now(tz=timezone.utc)
    invoke_payload = Path(".development/invoke-payload.json")
    event = json.loads(invoke_payload.read_text(encoding="utf8"))
    context = {
        "aws_request_id": uuid4(),
        "log_group_name": f"/aws/lambda/{internals.APP_NAME}",
        "log_stream_name": f"{now.strftime('%Y/%m/%d')}/[$LATEST]efedd01b329b4041b660f9ce510228cc",
        "function_name": internals.APP_NAME,
        "memory_limit_in_mb": 128,
        "function_version": "$LATEST",
        "invoked_function_arn": f"arn:aws:lambda:{AWS_REGION}:{AWS_ACCOUNT}:function:{internals.APP_NAME}",
        "client_context": None,
        "identity": None,
    }
    app.handler(event, context)

def run():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-v",
        "--errors-only",
        help="set logging level to ERROR (default INFO)",
        dest="log_level_error",
        action="store_true",
    )
    group.add_argument(
        "-vv",
        "--warning",
        help="set logging level to WARNING (default INFO)",
        dest="log_level_warning",
        action="store_true",
    )
    group.add_argument(
        "-vvv",
        "--info",
        help="set logging level to INFO (default INFO)",
        dest="log_level_info",
        action="store_true",
    )
    group.add_argument(
        "-vvvv",
        "--debug",
        help="set logging level to DEBUG (default INFO)",
        dest="log_level_debug",
        action="store_true",
    )
    log_level = logging.INFO
    if parser.parse_args().log_level_error:
        log_level = logging.ERROR
    if parser.parse_args().log_level_warning:
        log_level = logging.WARNING
    if parser.parse_args().log_level_info:
        log_level = logging.INFO
    if parser.parse_args().log_level_debug:
        log_level = logging.DEBUG
    if sys.stdout.isatty():
        logging.basicConfig(
            format="%(message)s",
            level=log_level,
            handlers=[RichHandler(rich_tracebacks=True, markup=True)],
        )
    internals.logger.setLevel(log_level)
    with contextlib.suppress(KeyboardInterrupt):
        cli()

if __name__ == "__main__":
    run()
