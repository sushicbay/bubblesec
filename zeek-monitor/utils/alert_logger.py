import json
from datetime import datetime

def save_alerts(alerts, file_path):

    output = {
        "timestamp": str(datetime.now()),
        "alerts": alerts
    }

    with open(file_path, "w") as f:
        json.dump(output, f, indent=4)