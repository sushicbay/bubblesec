import os
import subprocess
import json

from utils.alert_logger import save_alerts
from utils.db import initialize_db, insert_privacy_alerts

from detectors.port_scan import detect_port_scans
from detectors.unusual_ports import detect_unusual_ports
from detectors.rare_destinations import rare_destinations
from detectors.traffic_spikes import detect_traffic_spikes

from detectors.privacy.plaintext_credentials import detect_plaintext_credentials
from detectors.privacy.tokens_in_url import detect_tokens_in_url
from detectors.privacy.weak_tls import detect_weak_tls
from detectors.privacy.tracker_domains import detect_tracker_domains

PCAP_DIR = "./uploaded_pcaps"
OUTPUT_DIR = "./analysis"


def normalize(alert_list):
    return {
        "count": len(alert_list),
        "events": alert_list
    }


def parse_zeek_log(log_path):
    records = []

    try:
        with open(log_path, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except FileNotFoundError:
        return []

    return records


def run_zeek(pcap_file, output_folder):
    result = subprocess.run(
        ["zeek", "-r", pcap_file, "LogAscii::use_json=T"],
        cwd=output_folder,
        capture_output=True,
        text=True
    )

    return result.returncode == 0


def analyze_pcap(pcap_file):
    name = os.path.basename(pcap_file).replace(".pcap", "")
    output_folder = os.path.join(OUTPUT_DIR, name)

    os.makedirs(output_folder, exist_ok=True)

    if not run_zeek(pcap_file, output_folder):
        return

    conn_log = os.path.join(output_folder, "conn.log")
    http_log = os.path.join(output_folder, "http.log")
    ssl_log = os.path.join(output_folder, "ssl.log")
    dns_log = os.path.join(output_folder, "dns.log")

    if not os.path.exists(conn_log):
        return

    conn_records = parse_zeek_log(conn_log)
    http_records = parse_zeek_log(http_log) if os.path.exists(http_log) else []
    ssl_records = parse_zeek_log(ssl_log) if os.path.exists(ssl_log) else []
    dns_records = parse_zeek_log(dns_log) if os.path.exists(dns_log) else []

    intrusion_alerts = {
        "port_scans": normalize(detect_port_scans(conn_records)),
        "unusual_ports": normalize(detect_unusual_ports(conn_records)),
        "rare_destinations": normalize(rare_destinations(conn_records)),
        "traffic_spikes": normalize(detect_traffic_spikes(conn_records))
    }

    privacy_alerts = {
        "plaintext_credentials": normalize(detect_plaintext_credentials(http_records)),
        "tokens_in_url": normalize(detect_tokens_in_url(http_records)),
        "weak_tls": normalize(detect_weak_tls(ssl_records)),
        "tracker_domains": normalize(detect_tracker_domains(dns_records))
    }

    alerts = {
        "intrusion": intrusion_alerts,
        "privacy": privacy_alerts
    }

    alert_file = os.path.join(output_folder, "alerts.json")
    save_alerts(alerts, alert_file)

    return alerts


def main():
    initialize_db()
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    processed_files = []
    alerts_by_file = {}

    for file in os.listdir(PCAP_DIR):
        if file.endswith((".pcap", ".pcapng")):
            pcap_path = os.path.abspath(os.path.join(PCAP_DIR, file))

            alerts = analyze_pcap(pcap_path)

            processed_files.append(file)
            alerts_by_file[file] = alerts if alerts else {}

    return processed_files, alerts_by_file


if __name__ == "__main__":
    main()