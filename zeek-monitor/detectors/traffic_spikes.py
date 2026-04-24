import config

def detect_traffic_spikes(records):

    alerts = []

    for r in records:

        try:

            orig = int(r.get("orig_bytes", 0))
            resp = int(r.get("resp_bytes", 0))

            total = orig + resp

        except:
            continue

        if total > config.TRAFFIC_SPIKE_THRESHOLD:

            alerts.append({
                "src_ip": r["id.orig_h"],
                "dst_ip": r["id.resp_h"],
                "bytes": total,
                "type": "Traffic Spike"
            })

    return alerts