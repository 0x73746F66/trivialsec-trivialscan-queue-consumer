# pylint: disable=no-self-argument, arguments-differ
import logging
import boto3
import threading
import json
from datetime import datetime
from os import getenv
from ipaddress import (
    IPv4Address,
    IPv6Address,
)

import requests
from pydantic import (
    HttpUrl,
    AnyHttpUrl,
    PositiveInt,
    PositiveFloat,
    EmailStr,
)


DEFAULT_LOG_LEVEL = logging.WARNING
LOG_LEVEL = getenv("LOG_LEVEL", 'WARNING')
CACHE_DIR = getenv("CACHE_DIR", "/tmp")
BUILD_ENV = getenv("BUILD_ENV", "development")
APP_ENV = getenv("APP_ENV", "Dev")
APP_NAME = getenv("APP_NAME", "trivialscan-queue-consumer")
DASHBOARD_URL = "https://www.trivialsec.com"
logger = logging.getLogger(__name__)
if getenv("AWS_EXECUTION_ENV") is not None:
    boto3.set_stream_logger('boto3', getattr(logging, LOG_LEVEL, DEFAULT_LOG_LEVEL))
logger.setLevel(getattr(logging, LOG_LEVEL, DEFAULT_LOG_LEVEL))


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.isoformat()
        if isinstance(
            o,
            (
                PositiveInt,
                PositiveFloat,
            ),
        ):
            return int(o)
        if isinstance(
            o,
            (
                AnyHttpUrl,
                IPv4Address,
                IPv6Address,
                EmailStr,
            ),
        ):
            return str(o)
        if hasattr(o, "dict"):
            return json.dumps(o.dict(), cls=JSONEncoder)

        return super().default(o)


def _request_task(url, body, headers):
    try:
        requests.post(url, data=json.dumps(body, cls=JSONEncoder), headers=headers, timeout=(5, 15))
    except requests.exceptions.ConnectionError:
        pass

def post_beacon(url: HttpUrl, body: dict, headers: dict = {"Content-Type": "application/json"}):
    """
    A beacon is a fire and forget HTTP POST, the response is not
    needed so we do not even wait for one, so there is no
    response to discard because it was never received
    """
    threading.Thread(target=_request_task, args=(url, body, headers)).start()
