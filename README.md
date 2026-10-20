# SentinelCloud-Advanced
## eBPF-Driven Autonomous Cyber-Resilience for Medical Microservices

## Overview
SentinelCloud-Advanced is a cyber-resilience platform that protects critical medical microservices against advanced threats such as ransomware, lateral movement, and data exfiltration. It combines two independently-recorded detection systems — a MITRE-mapped signature rule engine and an online streaming ML model (HalfSpaceTrees + HMM) — with real-time telemetry, causal root-cause diagnosis, and autonomous remediation using the MAPE-K control loop.

Live telemetry comes from two real sources: Falco's eBPF probe capturing actual kernel syscalls inside the medical service containers (delivered to the backend via webhook), and structured JSON access logs tailed from the running medical services. Synthetic events exist only as clearly-labeled cold-start baseline warm-up and stop after 500 events.

The system operates in three modes:
- **LIVE**: Full Kubernetes cluster with real infrastructure (Tetragon, Kafka, ClickHouse, Cilium).
- **LAB**: Local Docker Compose environment with real services and containerized dependencies.
- **DEV**: Single-machine development mode with in-process ML; remediation attempts real Docker container stop/restart when reachable, otherwise records the action with a clear `[DEV MODE]` label.

## Architecture
See [docs/architecture.md](docs/architecture.md) for detailed design and diagrams.

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- Docker & Docker Compose (for LAB mode)

### DEV Mode (No Docker)
1. Set up backend virtual environment and dependencies:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r backend/requirements.txt
   ```

2. Install frontend dependencies:
   ```bash
   npm install
   ```

3. Launch both backend and frontend using the unified developer runner:
   ```bash
   ./scripts/dev-start.sh
   # or
   ./start_range.sh
   ```

4. Access the dashboard:
   - **Command Center**: [http://localhost:3000](http://localhost:3000)
   - **Backend API**: [http://localhost:5050](http://localhost:5050)
   - **API Docs**: [http://localhost:5050/docs](http://localhost:5050/docs)
   - Default credentials: `admin` / `sentinel-admin-2026`

---

### LAB Mode (Docker Compose)
1. Ensure Docker is running.
2. Start the complete lab environment:
   ```bash
   ./scripts/lab-start.sh
   ```
   This launches:
   - Zookeeper (:2181), Kafka (:9092), ClickHouse (:8123, :9000)
   - Medical microservices: vitals (:5000), drug-dispenser (:5001), ehr (:5002), billing (:5003)
   - Intelligence services: anomaly-detector (:8080), diagnosis (:8081), MAPE-K controller (:8083)
   - SentinelCloud backend (:5050)

3. Check health across all services:
   ```bash
   ./scripts/health-check.sh
   ```

4. Stop all services when finished:
   ```bash
   ./scripts/stop-all.sh
   ```

---

## Running Tests

Execute the automated test suite with pytest:

```bash
# Unit tests
pytest tests/unit -v

# API tests
pytest tests/api -v

# Integration tests (skips automatically if services are offline)
pytest -m integration tests/integration -v

# Run all non-integration tests
pytest -m "not integration" -v
```

---

## Running Attack Simulations

Use the testing harness to safely simulate attack kill-chains:

```bash
python3 testing/harness.py --scenario recon --target-pod ehr --target-namespace medical
```

Available scenarios in `testing/scenarios/`:
- `recon` – Network port scanning
- `shell_exec` – Unauthorized shell spawn
- `lateral_movement` – SMB probing on port 445
- `file_encryption` – Canary file renaming to `.locked`
- `dns_exfil` – High-volume DNS exfiltration tunneling
- `auth_bruteforce` – Repeated authentication failure
- `ransomware` – Complete 4-stage kill-chain

---

## Project Structure

```text
sentinel-cloud/
├── backend/          # FastAPI + Socket.IO backend (auth, ML pipeline, routes)
├── app/              # Next.js 15 Resilience Dashboard (React, Tailwind v4)
├── components/       # Shared UI components (metric cards, telemetry table, etc.)
├── services/
│   ├── medical/      # Medical microservices (vitals, ehr, drug-dispenser, billing)
│   ├── intelligence/ # Streaming anomaly detector & diagnosis service
│   └── orchestrator/ # MAPE-K remediation controller
├── testing/          # Lab testing harness and attack scenarios
├── tests/            # Automated test suite (unit, api, integration)
├── deploy/           # Kubernetes manifests & Helm charts
├── policies/         # Cilium, Falco, OPA Gatekeeper policies
├── scripts/          # Control scripts (dev-start, lab-start, health-check, stop-all)
├── docker-compose.yml# Complete local LAB stack
├── docs/             # Technical and architectural documentation
└── README.md
```

## Two-PC Network Deployment (Demonstration Architecture)

The primary live demonstration uses two computers connected over a local private area network (LAN):

- **PC1 (Target & Defender)**: Runs the SentinelCloud SOC dashboard (:3000), FastAPI backend (:5050), in-process or containerized ML anomaly detector, SQLite persistence, and MAPE-K autonomous resilience controller.
- **PC2 (Authorized External Test Client)**: Runs the lightweight standalone test client (`testing/pc2_client.py`). PC2 does not need Node.js, Next.js, or heavyweight dependencies.

---

### Step 1: Set Up PC1 (Defender / Target)

1. Find PC1's local LAN IP address:
   ```bash
   # On macOS:
   ipconfig getifaddr en0
   # On Linux:
   hostname -I | awk '{print $1}'
   ```
   *(Example: `192.168.1.100`)*

2. Configure environment on PC1 (`.env`):
   ```bash
   cp .env.example .env
   ```
   Ensure `SENTINEL_HOST=0.0.0.0` and `SENTINEL_PORT=5050`.

3. Ensure incoming firewall permits ports `5050` (Backend API & WebSocket) and `3000` (Dashboard):
   - **macOS**: System Settings → Network → Firewall → Allow incoming connections for Python and Node.
   - **Linux (ufw)**: `sudo ufw allow 5050/tcp && sudo ufw allow 3000/tcp`

4. Launch the platform on PC1:
   ```bash
   ./start_range.sh
   # or
   ./scripts/dev-start.sh
   ```
   Both the Backend (`http://0.0.0.0:5050`) and Next.js Dashboard (`http://0.0.0.0:3000`) will bind to all network interfaces.

5. Open the SOC Dashboard in a browser on PC1:
   - URL: `http://localhost:3000`
   - Log in with default credentials: `admin` / `sentinel-admin-2026`

---

### Step 2: Set Up PC2 (Authorized Test Client)

PC2 requires only Python 3 and the `requests` library.

1. Install client dependencies on PC2:
   ```bash
   pip install requests
   ```

2. Configure the client using environment variables or `testing/pc2_config.json`:
   ```bash
   cp testing/pc2_config.example.json testing/pc2_config.json
   ```
   Edit `testing/pc2_config.json` and set `"pc1_api_url"` to PC1's LAN IP:
   ```json
   {
     "pc1_api_url": "http://192.168.1.100:5050",
     "username": "admin",
     "password": "sentinel-admin-2026",
     "timeout_seconds": 10
   }
   ```

3. Test reachability to PC1 over the LAN:
   ```bash
   python3 testing/pc2_client.py --pc1-url http://192.168.1.100:5050 --check
   ```
   Expected output:
   `✔ PC1 is reachable! RTT Latency: 4.2ms | Mode: dev | Service: sentinel-backend`

4. Verify secure authentication with PC1:
   ```bash
   python3 testing/pc2_client.py --pc1-url http://192.168.1.100:5050 --auth
   ```
   Expected output:
   `✔ Authenticated successfully on PC1 as 'admin' (role: admin)`

---

### Step 3: Run Controlled Scenarios from PC2

List all available scenarios:
```bash
python3 testing/pc2_client.py --list-scenarios
```

#### Scenario A: Unauthorized Shell Execution in EHR Container
```bash
python3 testing/pc2_client.py --pc1-url http://192.168.1.100:5050 --scenario shell_exec --target-pod ehr
```
*What happens:*
- PC2 submits an authorized `sys_execve` event with `/bin/bash`
- PC1 ML pipeline flags the anomaly (score crosses the configured threshold)
- Incident is automatically opened on PC1
- MAPE-K quarantines the pod, rolls out a clean container, and verifies health
- PC2 observes the recovery and outputs an evidence verification table

#### Scenario B: Multi-Stage Ransomware Kill Chain
```bash
python3 testing/pc2_client.py --pc1-url http://192.168.1.100:5050 --scenario ransomware --target-pod ehr --save-report results/ransomware_evidence.json
```
*What happens:*
- PC2 simulates the 4-stage kill chain:
  1. Initial shell spawn (`sys_execve`)
  2. Database encryption and rename (`sys_rename` -> `.locked`)
  3. Lateral movement pivot to billing (`sys_connect` -> port 445 SMB)
  4. DNS exfiltration tunnel (`sys_sendto` -> port 53)
- The signature rule engine (`RANSOM_001`, `SHELL_001`, `LATERAL_001`, `EXFIL_001`)
  fires deterministically; the HalfSpaceTrees ML model scores the same events
  independently. Which detector fired is recorded per event
  (`RULE_MATCH` / `ML_ANOMALY` / `BOTH`).
- MAPE-K executes failover & quarantine, restores the service to healthy
- PC2 verifies post-mitigation service restoration and records the evidence report

#### Scenario C: Network Reconnaissance Scan
```bash
python3 testing/pc2_client.py --pc1-url http://192.168.1.100:5050 --scenario recon --target-pod vitals
```

---

## Operating Environment & Telemetry Notes

- **macOS Development**:
  Linux kernel eBPF probes and Cilium/Tetragon kernel hooks require a Linux host. On macOS, the platform runs in `DEV` mode: telemetry ingestion (Falco webhook, HTTP log tailing), real ML streaming anomaly detection (HalfSpaceTrees + HMM), rule-engine detection, root-cause diagnosis, and MAPE-K lifecycle logic all execute in-process. Kernel-level syscall capture is provided by running Falco in a Linux VM (e.g., UTM) with the medical services in Docker — see `deploy/utm-setup.md`.
- **Linux / Kubernetes Deployment**:
  In a Linux or Kubernetes cluster, Falco (or Tetragon via the Kafka forwarder) streams kernel-level events into the same ingestion pipeline.
- **Event Provenance**:
  All events are explicitly labeled in the UI and data model:
  - `http` (API Test / PC2): Injected by the external authorized test client or lab scenario runner
  - `http_log`: Tailed from the real JSON access logs of the running medical services (Flask services emit structured logs; the backend tails and abstracts HTTP to syscall semantics)
  - `falco`: Real kernel-level syscall events captured by Falco's eBPF probe on a Linux host/VM and delivered to the backend via authenticated webhook
  - `synthetic`: Clearly-labeled baseline warm-up events emitted only during the online model's cold-start period; they stop after 500 events and never claim to be live
  - `replay` / `lab_test`: Deterministic benchmark replay and lab-injected events

---

## Telemetry Sources: What Is Real vs. What Is Simulated

This platform is honest about where every event comes from:

### 1. Kernel-level telemetry: Falco + eBPF (LIVE)
On a Linux host or VM, [Falco](https://falco.org/) runs with its modern eBPF
probe and captures real syscall activity (`execve`, `connect`, `rename`,
`sendto`, `openat`, ...) inside the medical microservice containers. Alerts
are POSTed as JSON to this backend's `/api/falco/webhook`, converted into
`TelemetryEvent` objects (`source=falco`, `data_mode=live`), and processed by
the same pipeline as all other telemetry. Custom rules in
`policies/falco/sentinel_rules.yaml` cover the attack scenarios used in
testing. See `deploy/utm-setup.md` for the reference setup.

### 2. Application-level telemetry: structured HTTP access logs (LIVE)
The four medical services (`ehr`, `vitals`, `drug-dispenser`, `billing`) emit
structured JSON access logs. The backend's log tailer
(`backend/pipeline/log_tail.py`) follows these files in real time, converts
each request into a `TelemetryEvent` (`source=http_log`), and abstracts
HTTP method+path into syscall semantics (`GET /record` -> `sys_read`,
`POST /record` -> `sys_write`, `DELETE` -> `sys_unlink`, ...). The companion
traffic generator (`simulation/benign_traffic_generator.py`) drives real HTTP
requests against the service endpoints — including an `--mode attack` that
issues anomalous request patterns — so this telemetry path is exercised with
real, end-to-end HTTP traffic.

### 3. Synthetic baseline warm-up (SYNTHETIC, opt-in, off by default)
Online models can optionally receive an initial distribution before scoring
novel events. A clearly-labeled synthetic generator can emit baseline clinical
templates (`data_mode=synthetic`) for the first 500 events, then stop — enable
with `SENTINEL_SYNTHETIC_WARMUP_ENABLED=true` for cold-start research only.
By default it is **off**: the model trains purely on live Falco + HTTP
traffic, so no synthetic asterisk attaches to the evaluation. These events,
when enabled, are never presented as live traffic.

### 4. Authorized attack injection (lab test / PC2 client)
Attack scenarios are injected explicitly and labeled as such: the two-PC test
client (`testing/pc2_client.py`), the lab scenario runner, and
`--mode attack` on the traffic generator. Nothing is misattributed to
"organic" traffic.

### Detection: two separate, independently-recorded systems
- **Signature rule engine** (`backend/pipeline/rule_engine.py`): deterministic,
  named rules (`RANSOM_001`, `SHELL_001`, `LATERAL_001`, `RECON_001`,
  `EXFIL_001`, `BACKDOOR_001`, `BRUTE_001`), each mapped to a MITRE ATT&CK
  technique. Rule matches never alter the ML score.
- **Online ML** (`backend/pipeline/detector.py`): HalfSpaceTrees (streaming
  anomaly detection) + HMM sequence scoring, returning raw model output with
  no hardcoded overrides or calibration tables.
Every detection record stores which system fired (`RULE_MATCH`, `ML_ANOMALY`,
`BOTH`, or `NONE`) and the matching rule id / MITRE technique.

### MAPE-K remediation
Remediation uses the Docker SDK to stop (quarantine) and restart (redeploy)
the affected container when one is reachable; timings are the real operation
durations, not simulated sleeps. When no matching container is reachable
(e.g., pure development mode), the action is recorded and labeled as such
rather than faked. On Kubernetes, real namespace-scoped operations are used.

### Datasets: future work, not live telemetry
ADFA-LD and MIMIC-III are **not** currently wired into the live pipeline. The
`simulation/dataset_replay/` engine exists as an offline evaluation harness
with placeholder sample records; connecting real benchmark datasets is
explicitly future work. No claim of "replayed authentic benchmark records"
being present in the live traffic path should be made until that integration
is implemented and validated with the real datasets.

## Security & Resilience Guarantees
- **Authentication**: JWT with bcrypt hashing and role-based access.
- **Observability**: Prometheus metrics at `/metrics` and structured JSON logs.
- **Safety**: Safety boundary validation via `SAFETY_ALLOWED_CIDRS` (`safety.py`).
- **Honest Metrics**: Real MTTD/MTTR calculations based on event timestamps (no mocked or random values).

## License
Proprietary — Developed for research and demonstration purposes.
