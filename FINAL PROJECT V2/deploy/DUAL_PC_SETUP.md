# Dual-PC Network Deployment & 4-Screen Demonstration Guide

This document outlines the setup procedure for evaluating **SentinelCloud-Advanced** across physical hardware using two PCs connected over a Local Area Network (LAN) or Tailscale VPN.

---

## 🏗️ Dual-PC Hardware Architecture

```
+------------------------------------+          +----------------------------------+
|           PC 1: TARGET             |          |          PC 2: ATTACKER          |
|  (Smart Hospital K3s Cluster)      |  Local   |  (Kali Linux / Attack Controller) |
|  - IP: 192.168.1.100               |  Ethernet|  - IP: 192.168.1.200              |
|  - Microservices (NodePort 30080)  | <------> |  - Runs attack scripts / nmap    |
|  - eBPF + Kafka + MAPE-K Engine    |  / Wi-Fi |  - Monitors egress traffic       |
+------------------------------------+          +----------------------------------+
```

### IP Allocation Table
- **PC 1 (Target Hospital Cluster)**: `192.168.1.100`
- **PC 2 (Attacker Machine)**: `192.168.1.200`

---

## ⚙️ Step-by-Step Configuration

### 1. Configure Static IP Addresses
Connect both machines via Ethernet switch or Wi-Fi router.

* **PC 1 (Target)**:
  ```bash
  sudo nmcli con mod "Ethernet" ipv4.addresses "192.168.1.100/24" ipv4.gateway "192.168.1.1" ipv4.method manual
  ```
* **PC 2 (Attacker)**:
  ```bash
  sudo nmcli con mod "Ethernet" ipv4.addresses "192.168.1.200/24" ipv4.gateway "192.168.1.1" ipv4.method manual
  ```

### 2. Expose Microservices via NodePort (PC 1)
Apply the NodePort services manifest on PC 1:
```bash
kubectl apply -f deploy/manifests/dual-pc-nodeport-services.yaml
```

### 3. Verify Cross-PC Connectivity (PC 2 -> PC 1)
From PC 2, verify routing to the target microservices:
```bash
curl http://192.168.1.100:30080/health
```
Expected Output:
```json
{"service": "vitals", "status": "healthy"}
```

---

## 📺 4-Screen Demonstration View Layout

To demonstrate attack, mitigation, and autonomous remediation in real time, set up four simultaneous monitors/terminal windows:

```
+-----------------------------------------------------------------------------------+
|  SCREEN 1 (PC 1): Observability       |  SCREEN 2 (PC 1): K8s Cluster State       |
|  - Hubble UI (Live Cilium Flows)      |  - `kubectl get pods -w`                  |
|  - ClickHouse / Grafana Dashboard     |  - `kubectl get securityalerts -w`        |
+---------------------------------------+-------------------------------------------+
|  SCREEN 3 (PC 1): Orchestrator Logs   |  SCREEN 4 (PC 2): Attacker Terminal       |
|  - `kopf` controller terminal logs   |  - Simulated Ransomware / Exploit Script  |
+-----------------------------------------------------------------------------------+
```

### Screen Window Setup Commands:

* **Screen 1 (PC 1)**: Hubble UI / Web Dashboard at `http://localhost:5050`
* **Screen 2 (PC 1)**:
  ```bash
  kubectl get pods -n medical -w
  ```
* **Screen 3 (PC 1)**:
  ```bash
  kubectl logs -n sentinel -l app=mape-k-controller -f
  ```
* **Screen 4 (PC 2 Attacker)**:
  ```bash
  python simulation/attack-scripts/remote_attack_controller.py --target-ip 192.168.1.100 --target-port 30080
  ```

---

## ⚡ Attack & Remediation Sequence

1. **Stage 1 (Reconnaissance)**: Attacker executes `nmap -sV 192.168.1.100 -p 30080`.
2. **Stage 2 (Exploitation)**: Remote Code Execution payload sent to `vitals-service`.
3. **Stage 3 (Ransomware & Exfiltration)**: Trigger `.locked` encryption and DNS TXT tunneling.
4. **Autonomous Remediation**:
   - **Tetragon/Falco** flags syscall anomaly ($> 0.8$).
   - **MAPE-K Controller** applies `CiliumNetworkPolicy` quarantine.
   - **Attacker Terminal (PC 2)**: Command freezes / throws `Connection refused`.
   - **Target Cluster (PC 1)**: Compromised pod is deleted and clean replica enters `Running` status within **$< 45$ seconds**.
