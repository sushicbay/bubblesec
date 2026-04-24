def detect_plaintext_credentials(http_logs):
    alerts = []

    for entry in http_logs:
        method = entry.get("method", "")
        uri = entry.get("uri", "").lower()

        if method == "POST" and any(x in uri for x in ["login", "auth", "signin"]):
            alerts.append({
                "message": "Possible credentials sent over HTTP",
                "source_ip": entry.get("id.orig_h"),
                "dest_ip": entry.get("id.resp_h"),
                "uri": uri,
                "risk": "HIGH"
            })

    return alerts
