TRACKERS = [
    "google-analytics.com",
    "doubleclick.net",
    "facebook.com",
    "tracking",
    "analytics"
]


def detect_tracker_domains(dns_logs):
    alerts = []

    for entry in dns_logs:
        query = entry.get("query", "").lower()

        if any(tracker in query for tracker in TRACKERS):
            alerts.append({
                "message": f"Connection to tracker domain: {query}",
                "source_ip": entry.get("id.orig_h"),
                "dest_ip": None,
                "uri": query,
                "risk": "LOW"
            })

    return alerts
