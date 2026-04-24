from collections import defaultdict
import config

def detect_port_scans(records):

    port_tracker = defaultdict(set)

    for r in records:

        src = r["id.orig_h"]
        port = r["id.resp_p"]

        port_tracker[src].add(port)

    alerts = []

    for ip, ports in port_tracker.items():

        if len(ports) > config.PORT_SCAN_THRESHOLD:

            alerts.append({
                "src_ip": ip,
                "ports_scanned": len(ports),
                "type": "Port Scan"
            })

    return alerts