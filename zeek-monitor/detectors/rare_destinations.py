from collections import Counter

def rare_destinations(records, threshold=3):

    counter = Counter()

    for r in records:
        dst = r["id.resp_h"]
        counter[dst] += 1

    alerts = []

    for ip, count in counter.items():

        if count <= threshold:

            alerts.append({
                "dst_ip": ip,
                "connections": count,
                "type": "Rare Destination"
            })

    return alerts