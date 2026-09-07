"""
SentinelCloud-Advanced: Vitals Medical Microservice
Monitors patient vital signs. Labeled as critical: true.
Endpoints: GET /health, POST /beat
"""

import os
import json
import time
import logging
from datetime import datetime
from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("vitals-service")

# In-memory store for vitals
vitals_store = []

SERVICE_NAME = "vitals"
SERVICE_VERSION = "1.0.0"
START_TIME = time.time()


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    uptime = time.time() - START_TIME
    return jsonify({
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "status": "healthy",
        "uptime_seconds": round(uptime, 2),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }), 200


@app.route("/beat", methods=["POST"])
def beat():
    """
    Receive a heartbeat / vital sign reading.
    Expected JSON: { "patient_id": str, "heart_rate": int, "bp_systolic": int, "bp_diastolic": int, "spo2": float }
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    record = {
        "patient_id": data.get("patient_id", "unknown"),
        "heart_rate": data.get("heart_rate"),
        "bp_systolic": data.get("bp_systolic"),
        "bp_diastolic": data.get("bp_diastolic"),
        "spo2": data.get("spo2"),
        "received_at": datetime.utcnow().isoformat() + "Z"
    }
    vitals_store.append(record)
    logger.info("Received vital signs for patient %s", record["patient_id"])

    # Simple alerting logic
    alerts = []
    if record["heart_rate"] and (record["heart_rate"] < 40 or record["heart_rate"] > 180):
        alerts.append({"type": "heart_rate_critical", "value": record["heart_rate"]})
    if record["spo2"] and record["spo2"] < 90.0:
        alerts.append({"type": "spo2_low", "value": record["spo2"]})

    return jsonify({
        "status": "recorded",
        "record": record,
        "alerts": alerts,
        "total_records": len(vitals_store)
    }), 201


@app.route("/vitals", methods=["GET"])
def get_vitals():
    """Return the last 50 vitals readings."""
    return jsonify({
        "count": len(vitals_store),
        "records": vitals_store[-50:]
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logger.info("Starting Vitals service on port %d", port)
    app.run(host="0.0.0.0", port=port)
