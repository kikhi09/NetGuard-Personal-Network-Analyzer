"""Central configuration values for NetGuard.

All tunable paths, buffering values, UI timings, detection thresholds, and
security-score weights are defined here so application logic never hard-codes
them.
"""

import os
from pathlib import Path
from typing import Any

from database.path_resolver import resolve_database_path


DEVELOPMENT_MODE = os.getenv("NETGUARD_DEVELOPMENT_MODE", "").lower() in {
    "1",
    "true",
    "yes",
    "on",
}

PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = str(
    resolve_database_path(
        project_root=PROJECT_ROOT,
        development_mode=DEVELOPMENT_MODE,
    )
)

RETENTION_ENABLED = os.getenv("NETGUARD_RETENTION_ENABLED", "").lower() in {
    "1",
    "true",
    "yes",
    "on",
}
RETENTION_PACKET_DAYS = int(os.getenv("NETGUARD_RETENTION_PACKET_DAYS", "30"))
RETENTION_CONNECTION_DAYS = int(
    os.getenv("NETGUARD_RETENTION_CONNECTION_DAYS", "30")
)
RETENTION_STATISTICS_DAYS = int(
    os.getenv("NETGUARD_RETENTION_STATISTICS_DAYS", "90")
)
RETENTION_SCORE_DAYS = int(os.getenv("NETGUARD_RETENTION_SCORE_DAYS", "365"))
_retention_alert_days = os.getenv("NETGUARD_RETENTION_ALERT_DAYS", "").strip()
RETENTION_ALERT_DAYS = (
    int(_retention_alert_days) if _retention_alert_days else None
)
_retention_session_days = os.getenv(
    "NETGUARD_RETENTION_SESSION_DAYS", ""
).strip()
RETENTION_SESSION_DAYS = (
    int(_retention_session_days) if _retention_session_days else None
)
RETENTION_MAX_DAYS = 36_500

CAPTURE_BUFFER_MAX_SIZE = 200
CAPTURE_BUFFER_FLUSH_INTERVAL_SEC = 1
CAPTURE_QUEUE_MAX_SIZE = 2000
CAPTURE_THREAD_JOIN_TIMEOUT_SEC = 3
PROCESSING_THREAD_JOIN_TIMEOUT_SEC = 10
STATISTICS_SNAPSHOT_INTERVAL_SEC = 60
FILE_JOB_MAX_WORKERS = 2
FILE_JOB_PENDING_CAPACITY = 2

STATS_WINDOW_SECONDS = 60

PORT_SCAN_WINDOW_SEC = 10
PORT_SCAN_PORT_THRESHOLD_MEDIUM = 8
PORT_SCAN_PORT_THRESHOLD_HIGH = 15
DEV_PORT_SCAN_PORT_THRESHOLD_MEDIUM = 5
DEV_PORT_SCAN_PORT_THRESHOLD_HIGH = 10
UDP_FLOW_REPLY_WINDOW_SEC = 30
WINDOWS_EPHEMERAL_PORT_MIN = 49152
UDP_STRONG_SCAN_MULTIPLIER = 2

TRAFFIC_SPIKE_CHECK_WINDOW_SEC = 5
TRAFFIC_SPIKE_BASELINE_WINDOW_SEC = 60
TRAFFIC_SPIKE_MULTIPLIER = 3.0
TRAFFIC_SPIKE_MULTIPLIER_HIGH = 6.0
TRAFFIC_SPIKE_MIN_BASELINE_PPS = 20
TRAFFIC_SPIKE_MIN_BASELINE_OBSERVATIONS = 100
TRAFFIC_SPIKE_MIN_BASELINE_AGE_SEC = 30
TRAFFIC_SPIKE_CONTINUATION_WINDOW_SEC = 300
TRAFFIC_SPIKE_ESCALATION_SUSTAIN_SEC = 3
TRAFFIC_SPIKE_UPDATE_INTERVAL_SEC = 30
DEV_TRAFFIC_SPIKE_MULTIPLIER = 2.0
DEV_TRAFFIC_SPIKE_MULTIPLIER_HIGH = 4.0
DEV_TRAFFIC_SPIKE_MIN_BASELINE_PPS = 0.2
DEV_TRAFFIC_SPIKE_MIN_BASELINE_OBSERVATIONS = 10
DEV_TRAFFIC_SPIKE_MIN_BASELINE_AGE_SEC = 5

REPEATED_CONN_WINDOW_SEC = 10
REPEATED_CONN_SYN_THRESHOLD = 20
REPEATED_CONN_SYN_THRESHOLD_HIGH = 40
DEV_REPEATED_CONN_SYN_THRESHOLD = 10
DEV_REPEATED_CONN_SYN_THRESHOLD_HIGH = 20

HTTP_FLOOD_WINDOW_SEC = 10
HTTP_FLOOD_REQUEST_THRESHOLD = 100
HTTP_FLOOD_REQUEST_THRESHOLD_HIGH = 300
DEV_HTTP_FLOOD_REQUEST_THRESHOLD = 10
DEV_HTTP_FLOOD_REQUEST_THRESHOLD_HIGH = 25

DNS_FLOOD_WINDOW_SEC = 10
DNS_FLOOD_QUERY_THRESHOLD = 200
DNS_FLOOD_QUERY_THRESHOLD_HIGH = 500
DEV_DNS_FLOOD_QUERY_THRESHOLD = 15
DEV_DNS_FLOOD_QUERY_THRESHOLD_HIGH = 40

OUTBOUND_WINDOW_SEC = 30
OUTBOUND_BYTES_THRESHOLD_MB = 25
OUTBOUND_BYTES_THRESHOLD_HIGH_MB = 100
OUTBOUND_MIN_PACKET_COUNT = 10
DEV_OUTBOUND_BYTES_THRESHOLD_MB = 0.25
DEV_OUTBOUND_BYTES_THRESHOLD_HIGH_MB = 1
DEV_OUTBOUND_MIN_PACKET_COUNT = 2

SUSPICIOUS_PORTS = {4444, 31337, 12345, 1337, 6666, 6667, 9001}

ALERT_COOLDOWN_SEC = 30
INCIDENT_CONTINUATION_WINDOW_SEC = 300
NOTEWORTHY_PORT_ESCALATION_WINDOW_SEC = 60
NOTEWORTHY_PORT_REPEAT_THRESHOLD = 3

SCORE_WINDOW_MINUTES = 10
SCORE_WEIGHT_HIGH = 15
SCORE_WEIGHT_MEDIUM = 7
SCORE_WEIGHT_LOW = 3

RISK_WINDOW_MINUTES = 10
RISK_WEIGHT_INFO = 1
RISK_WEIGHT_LOW = 3
RISK_WEIGHT_MEDIUM = 8
RISK_WEIGHT_HIGH = 18
PROCESS_MAP_REFRESH_SECONDS = 5

HTTP_METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"}

NORMAL_DETECTION_SETTINGS: dict[str, dict[str, Any]] = {
    "port_scan": {
        "window_seconds": PORT_SCAN_WINDOW_SEC,
        "medium_threshold": PORT_SCAN_PORT_THRESHOLD_MEDIUM,
        "high_threshold": PORT_SCAN_PORT_THRESHOLD_HIGH,
    },
    "traffic_spike": {
        "check_window_seconds": TRAFFIC_SPIKE_CHECK_WINDOW_SEC,
        "baseline_window_seconds": TRAFFIC_SPIKE_BASELINE_WINDOW_SEC,
        "multiplier": TRAFFIC_SPIKE_MULTIPLIER,
        "high_multiplier": TRAFFIC_SPIKE_MULTIPLIER_HIGH,
        "minimum_baseline_pps": TRAFFIC_SPIKE_MIN_BASELINE_PPS,
        "minimum_baseline_observations": TRAFFIC_SPIKE_MIN_BASELINE_OBSERVATIONS,
        "minimum_baseline_age_seconds": TRAFFIC_SPIKE_MIN_BASELINE_AGE_SEC,
        "continuation_window_seconds": TRAFFIC_SPIKE_CONTINUATION_WINDOW_SEC,
        "escalation_sustain_seconds": TRAFFIC_SPIKE_ESCALATION_SUSTAIN_SEC,
        "update_interval_seconds": TRAFFIC_SPIKE_UPDATE_INTERVAL_SEC,
    },
    "repeated_connections": {
        "window_seconds": REPEATED_CONN_WINDOW_SEC,
        "medium_threshold": REPEATED_CONN_SYN_THRESHOLD,
        "high_threshold": REPEATED_CONN_SYN_THRESHOLD_HIGH,
    },
    "http_flood": {
        "window_seconds": HTTP_FLOOD_WINDOW_SEC,
        "medium_threshold": HTTP_FLOOD_REQUEST_THRESHOLD,
        "high_threshold": HTTP_FLOOD_REQUEST_THRESHOLD_HIGH,
    },
    "dns_flood": {
        "window_seconds": DNS_FLOOD_WINDOW_SEC,
        "medium_threshold": DNS_FLOOD_QUERY_THRESHOLD,
        "high_threshold": DNS_FLOOD_QUERY_THRESHOLD_HIGH,
    },
    "high_outbound": {
        "window_seconds": OUTBOUND_WINDOW_SEC,
        "medium_threshold_mb": OUTBOUND_BYTES_THRESHOLD_MB,
        "high_threshold_mb": OUTBOUND_BYTES_THRESHOLD_HIGH_MB,
        "minimum_packet_count": OUTBOUND_MIN_PACKET_COUNT,
    },
    "cooldown_seconds": {"default": ALERT_COOLDOWN_SEC},
}

DEVELOPMENT_DETECTION_SETTINGS: dict[str, dict[str, Any]] = {
    **NORMAL_DETECTION_SETTINGS,
    "port_scan": {
        **NORMAL_DETECTION_SETTINGS["port_scan"],
        "medium_threshold": DEV_PORT_SCAN_PORT_THRESHOLD_MEDIUM,
        "high_threshold": DEV_PORT_SCAN_PORT_THRESHOLD_HIGH,
    },
    "traffic_spike": {
        **NORMAL_DETECTION_SETTINGS["traffic_spike"],
        "multiplier": DEV_TRAFFIC_SPIKE_MULTIPLIER,
        "high_multiplier": DEV_TRAFFIC_SPIKE_MULTIPLIER_HIGH,
        "minimum_baseline_pps": DEV_TRAFFIC_SPIKE_MIN_BASELINE_PPS,
        "minimum_baseline_observations": DEV_TRAFFIC_SPIKE_MIN_BASELINE_OBSERVATIONS,
        "minimum_baseline_age_seconds": DEV_TRAFFIC_SPIKE_MIN_BASELINE_AGE_SEC,
    },
    "repeated_connections": {
        **NORMAL_DETECTION_SETTINGS["repeated_connections"],
        "medium_threshold": DEV_REPEATED_CONN_SYN_THRESHOLD,
        "high_threshold": DEV_REPEATED_CONN_SYN_THRESHOLD_HIGH,
    },
    "http_flood": {
        **NORMAL_DETECTION_SETTINGS["http_flood"],
        "medium_threshold": DEV_HTTP_FLOOD_REQUEST_THRESHOLD,
        "high_threshold": DEV_HTTP_FLOOD_REQUEST_THRESHOLD_HIGH,
    },
    "dns_flood": {
        **NORMAL_DETECTION_SETTINGS["dns_flood"],
        "medium_threshold": DEV_DNS_FLOOD_QUERY_THRESHOLD,
        "high_threshold": DEV_DNS_FLOOD_QUERY_THRESHOLD_HIGH,
    },
    "high_outbound": {
        **NORMAL_DETECTION_SETTINGS["high_outbound"],
        "medium_threshold_mb": DEV_OUTBOUND_BYTES_THRESHOLD_MB,
        "high_threshold_mb": DEV_OUTBOUND_BYTES_THRESHOLD_HIGH_MB,
        "minimum_packet_count": DEV_OUTBOUND_MIN_PACKET_COUNT,
    },
}


def validate_detection_settings(settings: dict[str, dict[str, Any]]) -> None:
    """Reject invalid thresholds before capture starts."""
    for rule_name, values in settings.items():
        for key, value in values.items():
            if isinstance(value, (int, float)) and value < 0:
                raise ValueError(f"{rule_name}.{key} cannot be negative")
        medium = values.get("medium_threshold", values.get("medium_threshold_mb"))
        high = values.get("high_threshold", values.get("high_threshold_mb"))
        if medium is not None and high is not None and high < medium:
            raise ValueError(f"{rule_name} high threshold must be >= medium")


validate_detection_settings(NORMAL_DETECTION_SETTINGS)
validate_detection_settings(DEVELOPMENT_DETECTION_SETTINGS)
