def detect_weak_tls(ssl_logs):
    alerts = []
    weak_versions = ["TLSv10", "TLSv11", "SSLv3"]

    for entry in ssl_logs:
        version = entry.get("version", "")

        if version in weak_versions:
            alerts.append({
                "message": f"Weak TLS version detected: {version}",
                "source_ip": entry.get("id.orig_h"),
                "dest_ip": entry.get("id.resp_h"),
                "uri": None,
                "risk": "MEDIUM"
            })

    return alerts
