"""
SentinelCloud-Advanced: EHR (Electronic Health Record) Medical Microservice
Manages patient health records.
Endpoints: GET /health, GET /record, POST /record
"""

import os
import json
import time
import logging
from datetime import datetime
from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ehr-service")

# In-memory EHR store
ehr_store = {}

SERVICE_NAME = "ehr"
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


@app.route("/record", methods=["GET"])
def get_record():
    """
    Retrieve a patient record by patient_id query param.
    GET /record?patient_id=P001
    """
    patient_id = request.args.get("patient_id")
    if not patient_id:
        return jsonify({"error": "patient_id query parameter required"}), 400

    record = ehr_store.get(patient_id)
    if not record:
        return jsonify({"error": f"No record found for patient {patient_id}"}), 404

    return jsonify({"patient_id": patient_id, "record": record}), 200


@app.route("/record", methods=["POST"])
def create_record():
    """
    Create or update a patient record.
    Expected JSON: { "patient_id": str, "name": str, "diagnosis": str, "medications": list, "notes": str }
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    patient_id = data.get("patient_id")
    if not patient_id:
        return jsonify({"error": "patient_id is required"}), 400

    record = {
        "name": data.get("name", ""),
        "diagnosis": data.get("diagnosis", ""),
        "medications": data.get("medications", []),
        "notes": data.get("notes", ""),
        "updated_at": datetime.utcnow().isoformat() + "Z"
    }

    is_update = patient_id in ehr_store
    ehr_store[patient_id] = record
    action = "updated" if is_update else "created"
    logger.info("EHR record %s for patient %s", action, patient_id)

    return jsonify({
        "status": action,
        "patient_id": patient_id,
        "record": record
    }), 201 if not is_update else 200


@app.route("/records", methods=["GET"])
def list_records():
    """List all patient IDs."""
    return jsonify({
        "count": len(ehr_store),
        "patient_ids": list(ehr_store.keys())
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5002))
    logger.info("Starting EHR service on port %d", port)
    app.run(host="0.0.0.0", port=port)
