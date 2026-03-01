# 🚨 IDS/IPS Home Lab — Intrusion Detection & Prevention

> Hands-on implementation of multi-layer intrusion detection and prevention built on top of the [hardened-infra](https://github.com/Khalil-secure/hardened-infra) SOC lab. Real attacks, real detections, real documentation.

![Fail2ban](https://img.shields.io/badge/Fail2ban-IDS-red)
![Suricata](https://img.shields.io/badge/Suricata-IDS%2FIPS-blue)
![Grafana](https://img.shields.io/badge/Grafana-SOC_Dashboard-F46800?logo=grafana&logoColor=white)
![Loki](https://img.shields.io/badge/Loki-Log_Aggregation-F7D25E)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)

---

## 📌 Project Vision

This project documents the IDS/IPS stack built inside the hardened-infra SOC lab. It covers two complementary detection layers — application-level with Fail2ban and network-level with Suricata — feeding into a centralized Grafana SOC dashboard via Loki.

The goal is to understand how detection works in depth, not just configure tools. Every attack simulated, every alert triggered, every architectural decision is documented.

---

## 🔍 IDS vs IPS — What's the Difference?

| | IDS | IPS |
|---|---|---|
| **Full name** | Intrusion Detection System | Intrusion Prevention System |
| **What it does** | Observes and alerts | Observes, alerts, AND blocks |
| **Position** | Passive — watches traffic | Inline — traffic passes through it |
| **Risk** | False negatives (misses attacks) | False positives (blocks legit traffic) |
| **In this lab** | Fail2ban (log-based), Suricata (network) | Fail2ban in ban mode (active blocking) |

---

## 🏗️ Detection Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                      hardened-net                               │
│                                                                  │
│  ┌─────────────────────────────────────┐                        │
│  │         ansible-target              │                        │
│  │                                     │                        │
│  │  Layer 1 — SSH Hardening            │                        │
│  │  ├── Port 2222 (avoid scanners)     │                        │
│  │  ├── PermitRootLogin no             │                        │
│  │  ├── MaxAuthTries 3                 │                        │
│  │  └── PasswordAuthentication no      │                        │
│  │                                     │                        │
│  │  Layer 2 — Fail2ban (App IDS/IPS)   │                        │
│  │  ├── Reads auth.log in real-time    │                        │
│  │  ├── Detects brute force patterns   │                        │
│  │  ├── Bans IP after 3 attempts       │                        │
│  │  └── Ban duration: 1 hour           │                        │
│  │                                     │                        │
│  │  Layer 3 — File Integrity (HIDS)    │                        │
│  │  ├── inotifywait watches /etc/passwd│                        │
│  │  ├── Watches /etc/shadow            │                        │
│  │  └── Watches /etc/ssh/sshd_config   │                        │
│  └─────────────────────────────────────┘                        │
│                                                                  │
│  ┌─────────────────────────────────────┐                        │
│  │         suricata                    │                        │
│  │  Layer 4 — Network IDS              │                        │
│  │  ├── 48,716 ET/Open rules loaded    │                        │
│  │  ├── Watches eth0 interface         │                        │
│  │  ├── eve.json — full event log      │                        │
│  │  └── fast.log — alert summary       │                        │
│  └─────────────────────────────────────┘                        │
│                                                                  │
│  ┌──────────┐    ┌──────────┐    ┌─────────────────────────┐   │
│  │ promtail │───►│   loki   │───►│  grafana SOC dashboard  │   │
│  │ ships    │    │ aggregates│   │  real-time alerts       │   │
│  │ all logs │    │ all logs  │   │  port 3000              │   │
│  └──────────┘    └──────────┘    └─────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Detection Layers Explained

### Layer 1 — SSH Hardening (Prevention)

The first line of defense. Configuration changes that eliminate entire attack classes before any detection is needed.

```
Port 2222              → Eliminates 99% of automated scanners
PermitRootLogin no     → Root brute force impossible
MaxAuthTries 3         → Cuts off slow brute force
PasswordAuthentication no → Password attacks impossible
LogLevel VERBOSE       → Full forensic logging
```

### Layer 2 — Fail2ban (Application IDS/IPS)

Log-based intrusion detection. Fail2ban reads `auth.log` in real-time and bans IPs that exceed the threshold.

**Configuration:**
```ini
[DEFAULT]
bantime  = 3600      # 1 hour ban
findtime = 600       # 10 minute window
maxretry = 3         # 3 failures = ban
ignoreself = false   # Don't ignore localhost (for testing)

[sshd]
enabled  = true
port     = 2222
logpath  = /var/log/auth.log
```

**Detection flow:**
```
Failed SSH attempt → written to auth.log
       ↓
Fail2ban reads auth.log (inotify-based)
       ↓
3 failures in 600 seconds?
       ↓
iptables rule added → IP banned for 1 hour
       ↓
Ban logged to fail2ban.log
       ↓
Promtail ships to Loki → Grafana alert
```

### Layer 3 — File Integrity Monitoring (HIDS)

Host-based IDS using `inotifywait` to detect unauthorized changes to critical system files.

**Watched files:**
```
/etc/passwd       → user account modifications
/etc/shadow       → password hash changes
/etc/ssh/sshd_config → SSH config tampering
```

**Detection events:**
- `MODIFY` — file content changed
- `ATTRIB` — permissions or ownership changed
- `CREATE` — new file created
- `DELETE` — file deleted
- `MOVE` — file renamed or moved

### Layer 4 — Suricata (Network IDS)

Network-level intrusion detection with 48,716 ET/Open rules covering:
- Port scans and reconnaissance
- Exploit attempts
- Malware communication patterns
- Protocol anomalies
- Known bad IP addresses

**Key files:**
```
/var/log/suricata/eve.json   → Full JSON event log (all traffic)
/var/log/suricata/fast.log   → Alert summary (triggered rules only)
/var/log/suricata/stats.log  → Engine statistics
```

---

## ⚔️ Attack Simulations & Detection Results

### Attack 1 — SSH Brute Force

```bash
# Simulate brute force from inside the network
for ($i=1; $i -le 10; $i++) {
  docker exec ansible-target ssh -o StrictHostKeyChecking=no root@localhost -p 2222
}
```

**Detection chain:**
```
10 failed attempts
    → auth.log captures each failure
    → Fail2ban detects pattern after attempt 3
    → IP banned: [sshd] Ban ::1
    → Grafana spike visible on "Failed logins per minute" panel
```

**Result:** ✅ Detected and blocked within seconds

---

### Attack 2 — Root Login Attempt

```bash
ssh root@target -p 2222
```

**Detection chain:**
```
Connection attempt
    → sshd rejects immediately (PermitRootLogin no)
    → "ROOT LOGIN REFUSED" written to auth.log
    → Promtail ships to Loki
    → Visible in Grafana live log stream
```

**Result:** ✅ Blocked at config level, logged

---

### Attack 3 — File Integrity Violation

```bash
# Simulate unauthorized modification
docker exec ansible-target bash -c "echo 'malicious' >> /etc/passwd"
```

**Detection chain:**
```
File write to /etc/passwd
    → inotifywait detects MODIFY event instantly
    → Written to /var/log/file-monitor.log
    → Promtail ships to Loki
    → Alert visible in Grafana
```

**Result:** ✅ Detected in real-time

---

### Attack 4 — Network Port Scan (Suricata)

```bash
docker exec ansible-control bash -c "nmap -sS -p 1-10000 172.18.0.3"
```

**Result:** ⚠️ Partial — Suricata sees traffic in `eve.json` but Docker bridge networking processes inter-container traffic at the kernel bridge level, below Suricata's monitored interface. Full detection planned for Oracle Cloud deployment where host networking is available.

---

## 📊 Grafana SOC Dashboard

### Panels

| Panel | Query | Type |
|---|---|---|
| Live log stream | `{job="hardened-server"}` | Logs |
| Failed logins/min | `count_over_time({job="hardened-server"} \|= "Failed" [1m])` | Time series |
| Fail2ban bans | `{job="hardened-server"} \|= "Ban"` | Logs |
| File integrity alerts | `{job="hardened-server"} \|= "MODIFY"` | Logs |
| Root login attempts | `{job="hardened-server"} \|= "ROOT LOGIN REFUSED"` | Logs |

### What a brute force looks like on the dashboard

```
Time series panel:
  Normal baseline: ~2 events/min
  During attack:   spike to 10-15 events/min
  After Fail2ban:  drops to 0 (IP banned)

Log panel:
  Feb 22 17:30:01 Failed password for root from ::1
  Feb 22 17:30:02 Failed password for root from ::1
  Feb 22 17:30:03 Failed password for root from ::1
  Feb 22 17:30:03 [sshd] Ban ::1
```

---

## 🏛️ Architecture Decision — Suricata in Docker vs Production

### Current limitation

In Docker bridge networking, Suricata on `eth0` cannot inspect inter-container traffic because it's processed at the kernel bridge level — below the monitored interface.

```
Container A → [kernel bridge] → Container B
                    ↑
          Suricata cannot see this
```

### Production solution

| Environment | Suricata mode | Traffic visibility |
|---|---|---|
| Docker bridge | eth0 passive | External traffic only |
| Docker host network | --net=host | All host traffic |
| Oracle Cloud VM | eth0 on VM | Full inter-container + external |
| Dedicated tap | SPAN/mirror port | 100% network visibility |

### Planned for Oracle Cloud (Phase 4)

On an Oracle Cloud VM, Suricata runs with `--net=host` giving it full visibility over all container traffic. This enables:
- Real-time port scan detection
- MITRE ATT&CK T1046 (Network Service Discovery)
- MITRE ATT&CK T1021 (Remote Services abuse)
- MITRE ATT&CK T1190 (Exploit Public-Facing Application)

---

## 🔧 How to Reproduce

### Prerequisites

```powershell
docker network create hardened-net
docker volume create hardened-logs
```

### Deploy the hardened target

```powershell
docker run -d --name ansible-target `
  --network hardened-net `
  -v hardened-logs:/var/log `
  ubuntu:22.04 sleep infinity
```

### Run Ansible hardening playbook

```bash
cd /ansible
ansible-playbook playbooks/site.yml
```

### Deploy SOC stack

```powershell
# Loki
docker run -d --name loki `
  --network hardened-net -p 3100:3100 `
  grafana/loki:latest

# Grafana
docker run -d --name grafana `
  --network hardened-net -p 3000:3000 `
  grafana/grafana:latest

# Promtail
docker run -d --name promtail `
  --network hardened-net `
  -v hardened-logs:/var/log/hardened:ro `
  -v ./promtail-config.yml:/etc/promtail/config.yml `
  grafana/promtail:latest

# Suricata
docker run -d --name suricata `
  --network hardened-net `
  --cap-add NET_ADMIN --cap-add NET_RAW `
  -v hardened-logs:/var/log/suricata `
  jasonish/suricata:latest -i eth0

# Load ET/Open rules
docker exec suricata suricata-update enable-source et/open
docker exec suricata suricata-update
```

### Start rsyslog on target

```powershell
docker exec ansible-target bash -c "rsyslogd && chmod 666 /var/log/auth.log"
```

### Access dashboards

- Grafana SOC: `http://localhost:3000` (admin/admin)
- Loki ready: `http://localhost:3100/ready`

---

## 🧠 Key Lessons

1. **Defense in depth** — no single tool catches everything, layers are essential
2. **Logs must flow** — rsyslog not running = blind IDS, entire pipeline fails silently
3. **Test your detection** — an IDS you haven't tested is not an IDS
4. **False positives matter** — `ignoreself = false` needed to test from localhost
5. **Network architecture limits visibility** — Docker bridge hides inter-container traffic from Suricata
6. **Document what doesn't work** — architectural constraints show deeper understanding than hiding limitations

---

## 🔗 Related Projects

- [hardened-infra](https://github.com/Khalil-secure/hardened-infra) — Full lab this IDS/IPS stack is built on
- [zerotrust-k8s](https://github.com/Khalil-secure/zerotrust-k8s) — Next project: Zero Trust Kubernetes
