import sqlite3
import os

DB_PATH = "network_analysis.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


def initialize_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Privacy alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS privacy_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT,
            message TEXT,
            source_ip TEXT,
            dest_ip TEXT,
            uri TEXT,
            risk TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()


def insert_privacy_alerts(privacy_alerts):
    conn = get_connection()
    cursor = conn.cursor()

    for alert_type, alerts_list in privacy_alerts.items():

        for alert in alerts_list:
            cursor.execute("""
                INSERT INTO privacy_alerts (
                    type,
                    message,
                    source_ip,
                    dest_ip,
                    uri,
                    risk
                )
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                alert_type,
                alert.get("message"),
                alert.get("source_ip"),
                alert.get("dest_ip"),
                alert.get("uri"),
                alert.get("risk")
            ))

    conn.commit()
    conn.close()
