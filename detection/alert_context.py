"""Stable detector grouping keys and cautious normal-activity context."""

from __future__ import annotations

import json


RULE_CONTEXT: dict[str, tuple[str, tuple[str, ...]]] = {
    "NG-PORT-SCAN": (
        "Suspicious behaviour",
        (
            "hotspot reply traffic",
            "QUIC or 4K streaming traffic",
            "DNS-related traffic",
            "short-lived application connections",
            "normal UDP replies",
            "authorized security test",
        ),
    ),
    "NG-REPEATED-CONNECTIONS": (
        "Unusual behaviour",
        (
            "unstable Internet connection",
            "application retries",
            "unavailable server",
            "background synchronization retries",
        ),
    ),
    "NG-HTTP-FLOOD": (
        "Unusual behaviour",
        (
            "browser automation",
            "local development testing",
            "an application making many clear-text HTTP requests",
        ),
    ),
    "NG-DNS-FLOOD": (
        "Unusual behaviour",
        (
            "opening many browser tabs",
            "application startup",
            "software update",
            "ad-heavy websites",
        ),
    ),
    "NG-TRAFFIC-SPIKE": (
        "Informational activity",
        (
            "4K video streaming",
            "video call",
            "large download",
            "software update",
            "cloud synchronization",
        ),
    ),
    "NG-HIGH-OUTBOUND": (
        "Unusual behaviour",
        (
            "file upload",
            "cloud backup",
            "video call",
            "cloud synchronization",
            "software update",
        ),
    ),
    "NG-SUSPICIOUS-PORT": (
        "Suspicious behaviour",
        ("developer tools", "local test server", "Tor", "IRC", "custom application"),
    ),
}


def make_group_key(rule_id: str, *parts: object) -> str:
    """Return a readable canonical key without unstable temporary fields."""
    return json.dumps([rule_id, *parts], separators=(",", ":"), ensure_ascii=True)


def context_for_rule(rule_id: str) -> tuple[str, tuple[str, ...]]:
    return RULE_CONTEXT.get(
        rule_id,
        ("Unusual behaviour", ("expected application activity",)),
    )
