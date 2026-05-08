"""Logging helpers for sensor telemetry."""

import json
import logging

LOG_FILE = "ebpf_sensor.log"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(message)s")


def emit_log(log_dict):
    json_log = json.dumps(log_dict)
    logging.info(json_log)
    print(json_log)
