# pylint: disable=no-self-argument, arguments-differ
import logging
import boto3
from os import getenv

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
