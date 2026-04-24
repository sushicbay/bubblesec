COMMON_PORTS = {80, 443, 53, 25, 123}

def detect_unusual_ports(records):

    alerts = []

    for r in records:

        src = r["id.orig_h"]
        dst = r["id.resp_h"]

        try:
            port = int(r["id.resp_p"])
        except:
            continue

        if src.startswith("192.168") and port not in COMMON_PORTS:

            alerts.append({
                "src_ip": src,
                "dst_ip": dst,
                "port": port,
                "type": "Unusual Port"
            })

    return alerts