# SentinelCloud‑Advanced
## eBPF‑Driven Autonomous Cyber‑Resilience for Medical Microservices

> A research prototype that protects a medical microservice cluster (K3s) against multi‑stage ransomware attacks using layered eBPF monitoring, streaming ML anomaly detection, causal diagnosis, and autonomous MAPE‑K remediation.

---

## Table of Contents

- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Detailed Setup](#detailed-setup)
- [Running the Attack Simulation](#running-the-attack-simulation)
- [Metrics & Evaluation](#metrics--evaluation)
- [Components](#components)
- [Configuration](#configuration)

---

## Architecture

The system is organised into **four planes**:

| Plane | Components | Purpose |
|-------|-----------|---------|
| **Observability** | Tetragon, Falco, DNSObelisk, Inspektor Gadget | eBPF-based syscall monitoring, DNS inspection |
| **Intelligence** | Online iForest, HMM, ExIFFI, Diagnosis Service | Anomaly detection, explainability, causal diagnosis |
| **Enforcement** | MAPE-K Controller, Cilium NPs | Autonomous remediation (quarantine, failover, redeploy) |
| **Assurance** | OPA/Gatekeeper, Kata Containers (optional) | Policy verification, confidential computing |

### Data Flow

```
Tetragon/Falco → Kafka → Anomaly Detector (iForest + HMM)
                                ↓
                        SecurityAlert CRD
                                ↓
                   MAPE-K Controller (kopf)
                      ↓            ↓
               Diagnosis      Execute Action
               Service      (Quarantine/Redeploy)
                                ↓
                          ClickHouse (logs)
```

---

## Project Structure

```
FINAL PROJECT V2/
├── deploy/
│   ├── sentinel-chart/          # Helm umbrella chart
│   │   ├── Chart.yaml
│   │   ├── values.yaml
│   │   └── templates/           # K8s resource templates
│   ├── manifests/               # Standalone K8s manifests
│   │   ├── securityalert-crd.yaml
│   │   ├── medical-services.yaml
│   │   └── sentinel-services.yaml
│   ├── setup-infrastructure.sh  # One-command infra setup
│   └── build-images.sh          # Docker build script
├── services/
│   ├── medical/                 # Mock medical microservices
│   │   ├── vitals/              # Patient vital signs (critical)
│   │   ├── drug-dispenser/      # Drug dispensing (critical)
│   │   ├── ehr/                 # Electronic Health Records
│   │   └── billing/             # Invoice management
│   ├── intelligence/            # Detection & analysis
│   │   ├── streaming-anomaly-detector/  # iForest + HMM + ExIFFI
│   │   ├── diagnosis-service/   # Causal root-cause analysis
│   │   └── tetragon-kafka-forwarder/    # eBPF event collector
│   └── orchestrator/
│       └── mape-k-controller/   # Autonomous remediation controller
├── policies/
│   ├── cilium/                  # Cilium NetworkPolicy definitions
│   │   └── baseline-policies.yaml
│   └── opa-gatekeeper/          # Rego policies + Gatekeeper constraints
│       ├── deny-smb-egress.rego
│       ├── deny-external-ingress.rego
│       ├── deny-host-network.rego
│       └── constraints.yaml
├── simulation/
│   ├── attack-scripts/          # Multi-stage ransomware simulator
│   │   ├── ransomware_simulator.py
│   │   ├── Dockerfile
│   │   └── attack-job.yaml
│   ├── metrics/                 # MTTD, MTTR, AUC, FPR collection
│   │   └── collect_metrics.py
│   └── benign_traffic_generator.py
└── README.md
```

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Ubuntu | 22.04 LTS | Host OS |
| K3s | v1.28+ | Kubernetes distribution |
| Helm | v3+ | Package manager |
| Docker | 24+ | Container building |
| Python | 3.11+ | Intelligence plane |
| kubectl | matching K3s | Cluster management |

---

## Quick Start

### 1. Set up infrastructure (one command)

```bash
chmod +x deploy/setup-infrastructure.sh
sudo ./deploy/setup-infrastructure.sh
```

This installs: K3s → Cilium → Tetragon → Falco → Gatekeeper → Kafka → ClickHouse → CRDs → Network Policies.

### 2. Build and push Docker images

```bash
chmod +x deploy/build-images.sh
./deploy/build-images.sh sentinelcloud  # or your registry
```

### 3. Deploy SentinelCloud

```bash
# Using Helm chart
helm install sentinel ./deploy/sentinel-chart

# Or using standalone manifests
kubectl apply -f deploy/manifests/securityalert-crd.yaml
kubectl apply -f deploy/manifests/medical-services.yaml
kubectl apply -f deploy/manifests/sentinel-services.yaml
kubectl apply -f policies/cilium/baseline-policies.yaml
kubectl apply -f policies/opa-gatekeeper/constraints.yaml
```

### 4. Generate benign baseline traffic (train models)

```bash
# Run for at least 1 hour to train the HMM
python simulation/benign_traffic_generator.py --duration 60 --rate 10
```

### 5. Run the attack simulation

```bash
# Option A: As a Kubernetes Job
kubectl apply -f simulation/attack-scripts/attack-job.yaml

# Option B: Exec into a medical pod
kubectl exec -it $(kubectl get pods -n medical -l app=ehr -o name | head -1) -n medical -- \
    python /tmp/ransomware_simulator.py --file-count 100
```

### 6. Collect metrics

```bash
python simulation/metrics/collect_metrics.py --output-dir ./results
```

---

## Detailed Setup

### For Local Development (Minikube)

```bash
# Start minikube with enough resources
minikube start --cpus=4 --memory=8192 --cni=false --driver=docker

# Install Cilium
helm install cilium cilium/cilium --namespace kube-system \
    --set ipam.mode=kubernetes \
    --set policyEnforcementMode=always

# Continue with Step 2+ from Quick Start
```

### For 3-Node K3s Cluster

```bash
# On control-plane node:
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--flannel-backend=none --disable-network-policy" sh -

# Get the token:
sudo cat /var/lib/rancher/k3s/server/node-token

# On worker nodes:
curl -sfL https://get.k3s.io | K3S_URL=https://<MASTER_IP>:6443 K3S_TOKEN=<TOKEN> sh -
```

---

## Running the Attack Simulation

The ransomware simulator executes a **4-stage kill chain**:

| Stage | Action | Detection Trigger |
|-------|--------|-------------------|
| 1 | Shell execution (`/bin/sh`) | `sys_execve` → iForest high score |
| 2 | SMB lateral movement (port 445) | `sys_connect` → Cilium deny + iForest |
| 3 | File encryption (`.json` → `.locked`) | `sys_rename` → iForest + HMM sequence |
| 4 | DNS exfiltration (TXT queries) | DNSObelisk block + DNS topic alert |

### Expected Response

1. **Anomaly Detector** catches the shell exec → anomaly score > 0.75
2. **SecurityAlert CRD** is created automatically
3. **MAPE-K Controller** receives the alert → calls Diagnosis Service
4. **Diagnosis** returns `root_cause: compromise`
5. **Controller** executes `FailoverAndQuarantine` (for critical pods) or `Redeploy` (non-critical)
6. Pod is quarantined via Cilium NP and then redeployed from golden image

---

## Metrics & Evaluation

| Metric | Target | Description |
|--------|--------|-------------|
| MTTD | ≤ 2s | Time from first malicious syscall to alert |
| MTTR | ≤ 45s | Time from alert to pod restoration |
| CPU Overhead | ≤ 5% | eBPF + ML processing overhead |
| AUC-ROC | ≥ 0.95 | Detection accuracy |
| FPR | ≤ 1% | False positive rate over 24h |

---

## Components

### Intelligence Plane

- **Online Isolation Forest** (`river.anomaly.HalfSpaceTrees`): Streaming anomaly detection that adapts to evolving traffic. Processes events one-at-a-time with O(1) update complexity.
- **Hidden Markov Model** (`hmmlearn.GaussianHMM`): Detects attack sequences (kill chains) that individual events might not trigger. Uses a sliding window of 10 events.
- **ExIFFI Explainability**: Computes per-feature contribution to anomaly scores. Explains *why* an event is suspicious (e.g., "68% due to .locked file extension").
- **Diagnosis Service**: Rule-based causal analysis querying ClickHouse for recent pod events. Classifies root cause as `compromise`, `dependency_failure`, `network_partition`, or `unknown`.

### Enforcement Plane

The **MAPE-K Controller** (built with `kopf`) autonomously remediates threats:

| Root Cause | Critical Pod | Action |
|-----------|-------------|--------|
| compromise | Yes | FailoverAndQuarantine |
| compromise | No | Redeploy |
| dependency_failure | Any | RestartDependency |
| network_partition | Any | QuarantineOnly |

Safety interlocks prevent service disruption: before terminating a critical pod, the controller waits up to 3 seconds for a backup replica.

### Assurance Plane

OPA/Gatekeeper enforces three invariants as admission webhooks:
1. No egress to port 445 (SMB) from medical namespace
2. No external ingress (0.0.0.0/0) except via Ingress controller
3. No `hostNetwork: true` in medical namespace

---

## Configuration

All services are configurable via environment variables:

| Variable | Default | Service |
|----------|---------|---------|
| `IFOREST_THRESHOLD` | 0.75 | Anomaly Detector |
| `HMM_THRESHOLD` | -5.0 | Anomaly Detector |
| `HMM_WINDOW_SIZE` | 10 | Anomaly Detector |
| `LOOKBACK_SECONDS` | 60 | Diagnosis Service |
| `SAFETY_TIMEOUT_SECONDS` | 3 | MAPE-K Controller |
| `KAFKA_BOOTSTRAP` | kafka.sentinel:9092 | All producers/consumers |
| `CLICKHOUSE_HOST` | clickhouse.sentinel:9000 | All writers/readers |

Override these in `deploy/sentinel-chart/values.yaml` for Helm deployments.

---

## License

This is a research prototype for academic purposes.
