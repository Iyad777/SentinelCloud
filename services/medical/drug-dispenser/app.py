"""
SentinelCloud-Advanced: Drug Dispenser Medical Microservice
Handles drug dispensing operations. Labeled as critical: true.
Endpoints: GET /health, POST /dispense
"""

import os
import json
import time
import logging
from datetime import datetime
from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("drug-dispenser-service")

# In-memory drug dispensing log
dispense_log = []
drug_inventory = {
    "aspirin": 500,
    "morphine": 100,
    "insulin": 300,
    "amoxicillin": 200,
    "metformin": 400,
}

SERVICE_NAME = "drug-dispenser"
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


@app.route("/dispense", methods=["POST"])
def dispense():
    """
    Dispense a drug.
    Expected JSON: { "patient_id": str, "drug_name": str, "quantity": int, "prescriber_id": str }
    """
    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid JSON payload"}), 400

    drug = data.get("drug_name", "").lower()
    quantity = data.get("quantity", 0)
    patient_id = data.get("patient_id", "unknown")
    prescriber_id = data.get("prescriber_id", "unknown")

    if drug not in drug_inventory:
        return jsonify({"error": f"Drug '{drug}' not found in inventory"}), 404

    if drug_inventory[drug] < quantity:
        return jsonify({"error": f"Insufficient stock for '{drug}'. Available: {drug_inventory[drug]}"}), 409

    drug_inventory[drug] -= quantity

    record = {
        "patient_id": patient_id,
        "drug_name": drug,
        "quantity": quantity,
        "prescriber_id": prescriber_id,
        "remaining_stock": drug_inventory[drug],
        "dispensed_at": datetime.utcnow().isoformat() + "Z"
    }
    dispense_log.append(record)
    logger.info("Dispensed %d units of %s to patient %s", quantity, drug, patient_id)

    return jsonify({
        "status": "dispensed",
        "record": record
    }), 201


@app.route("/inventory", methods=["GET"])
def inventory():
    """Return current drug inventory."""
    return jsonify({"inventory": drug_inventory}), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    logger.info("Starting Drug Dispenser service on port %d", port)
    app.run(host="0.0.0.0", port=port)
