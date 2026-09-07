"""
SentinelCloud-Advanced: Billing Medical Microservice
Handles invoicing and billing operations.
Endpoints: GET /health, GET /invoice
"""

import os
import json
import time
import logging
import random
from datetime import datetime
from flask import Flask, jsonify, request

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("billing-service")

# In-memory invoices
invoices_store = []

SERVICE_NAME = "billing"
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


@app.route("/invoice", methods=["GET"])
def get_invoice():
    """
    Generate or retrieve an invoice for a patient.
    GET /invoice?patient_id=P001
    """
    patient_id = request.args.get("patient_id")
    if not patient_id:
        return jsonify({"error": "patient_id query parameter required"}), 400

    # Find existing invoices for this patient
    patient_invoices = [inv for inv in invoices_store if inv["patient_id"] == patient_id]

    if not patient_invoices:
        # Generate a mock invoice
        invoice = {
            "invoice_id": f"INV-{random.randint(10000, 99999)}",
            "patient_id": patient_id,
            "items": [
                {"description": "Consultation", "amount": 150.00},
                {"description": "Lab Tests", "amount": 75.50},
                {"description": "Medication", "amount": 45.00}
            ],
            "total": 270.50,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat() + "Z"
        }
        invoices_store.append(invoice)
        logger.info("Generated invoice %s for patient %s", invoice["invoice_id"], patient_id)
        return jsonify({"invoice": invoice}), 201

    return jsonify({
        "patient_id": patient_id,
        "invoices": patient_invoices,
        "count": len(patient_invoices)
    }), 200


@app.route("/invoices", methods=["GET"])
def list_invoices():
    """List all invoices."""
    return jsonify({
        "count": len(invoices_store),
        "invoices": invoices_store[-50:]
    }), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5003))
    logger.info("Starting Billing service on port %d", port)
    app.run(host="0.0.0.0", port=port)
