def detect_tokens_in_url(http_logs):
    alerts = []
    keywords = ["token=", "auth=", "session=", "key="]

    for entry in http_logs:
        uri = entry.get("uri", "").lower()

        if any(k in uri for k in keywords):
            alerts.append({
                "message": "Sensitive token found in URL",
                "source_ip": entry.get("id.orig_h"),
                "dest_ip": entry.get("id.resp_h"),
                "uri": uri,
                "risk": "HIGH"
            })

    return alerts
