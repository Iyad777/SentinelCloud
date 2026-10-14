# UTM Ubuntu VM Setup for Falco Integration (Phase 5)

Target: Ubuntu Server 24.04 LTS in UTM on Apple Silicon (ARM64).
Mac (PC1) keeps running: backend :5050, dashboard :3000, log tailer, pipeline.

## 1. Install UTM + download Ubuntu

- UTM (free): https://mac.getutm.app/ — install the .dmg
- Ubuntu Server 24.04 ARM64 ISO:
  https://cdimage.ubuntu.com/releases/24.04/release/ubuntu-24.04.2-live-server-arm64.iso
  (Intel Macs: use the amd64 ISO instead)

## 2. Create the VM in UTM

- New VM → Virtualize → Linux → point at the downloaded ISO
- RAM: 2048 MB minimum (4096 if you can spare it)
- Disk: 20 GB (NVMe)
- Network: **Bridged** (shares your Mac's LAN — required so Falco can POST
  to the Mac backend and you can scp/ssh into the VM)
- CPU: default core count is fine
- Boot, run the Ubuntu installer, create user `ubuntu`, install OpenSSH server
  when offered.

## 3. Note both IPs

```bash
# On the Mac:
ipconfig getifaddr en0          # e.g. 192.168.1.50  -> this is <PC1-IP>
# On the VM (console or ssh):
ip -4 addr show scope global    # e.g. 192.168.1.60  -> this is <UTM-VM-IP>
```

## 4. Install Docker on the Ubuntu VM

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker   # or log out and back in
docker --version
```

## 5. Install Falco on the Ubuntu VM

```bash
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
  https://download.falco.org/packages/deb stable main" \
  | sudo tee /etc/apt/sources.list.d/falco.list
sudo apt update && sudo apt install -y falco
```

Ubuntu 24.04's kernel (6.8) supports modern eBPF — no extra kernel-module
build is needed.

## 6. Copy SentinelCloud files to the VM

From the Mac (repo root):

```bash
VM=ubuntu@<UTM-VM-IP>
scp policies/falco/sentinel_rules.yaml $VM:/tmp/
scp policies/falco/falco_config.yaml  $VM:/tmp/
scp -r services/ $VM:~/sentinel-services/
scp docker-compose.yml $VM:~/sentinel-services/
ssh $VM "sudo cp /tmp/sentinel_rules.yaml /etc/falco/rules.d/ && \
  sudo systemctl restart falco"
```

Then edit the webhook URL on the VM to point at your Mac:

```bash
ssh $VM
sudo nano /etc/falco/falco.yaml
# set http_output.url: "http://<PC1-IP>:5050/api/falco/webhook"
sudo systemctl restart falco
sudo journalctl -u falco -f   # watch for "Falco starting" + rule load
```

## 7. Run the medical services in the VM

```bash
ssh $VM
cd ~/sentinel-services
docker compose up -d vitals ehr billing drug-dispenser
docker ps --format '{{.Names}}'
```

Expect container names like `sentinel-services-ehr-1` (the folder name
becomes the compose project prefix). The Falco rules and remediation
candidate list match both `sentinel-cloud-*` and `sentinel-services-*`.

## 8. Enable the receiver on the Mac backend (.env)

```bash
SENTINEL_FALCO_ENABLED=true
# optional shared secret (must match X-Falco-Token in falco.yaml):
# SENTINEL_FALCO_WEBHOOK_TOKEN=<random>
```

Restart the backend. Verify:

```bash
curl http://localhost:5050/api/falco/status
# {"enabled": true, "endpoint": "/api/falco/webhook", ...}
```

## 9. End-to-end test

```bash
# In the VM — trigger a shell-spawn rule (use your actual container name
# from `docker ps`, e.g. sentinel-services-ehr-1):
docker exec sentinel-services-ehr-1 sh -c 'whoami'
# On the Mac dashboard: threats page should show a RULE badge
# (SHELL_001) with source=falco, data_mode=live.
# VM check: sudo journalctl -u falco | tail — should show the alert JSON.
```

## Troubleshooting

- No alerts arriving: check Bridged networking (VM and Mac on same subnet),
  macOS Firewall allowing :5050, and the exact `<PC1-IP>` in falco.yaml.
- 401 from webhook: token mismatch — compare `SENTINEL_FALCO_WEBHOOK_TOKEN`
  with `X-Falco-Token` in falco.yaml.
- 503 from webhook: `SENTINEL_FALCO_ENABLED` is not true / backend not restarted.
- Falco won't start: `sudo falco --validate` shows rule syntax errors.
