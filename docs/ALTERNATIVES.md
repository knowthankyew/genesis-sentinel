<!-- landscape-meta
last-reviewed: 2026-11-25
review-cadence-days: 180
reviewed-versions: [fail2ban@v1.1, crowdsec@v1.6, falco@v0.39, ossec@v3.8, wazuh@v4.9, opensearch-security-analytics@v2.18]
-->

# When to Use Genesis Sentinel (and When NOT To)

Engineering requires picking the right tool for the job. Genesis Sentinel is built for a narrow, specific problem: **local-first, zero-egress log anomaly detection and local LoRA alert triage operating as a lightweight pure-Go sidecar beside Project Genesis.**

If your threat model requires kernel-level syscall tracing, active firewall blocking, or multi-node compliance retention, another tool in the open-source security ecosystem is likely a better fit. Below is a candid comparison.

---

## Comparison Matrix

| Solution | Telemetry Scope | Memory Footprint | Network Posture | Remediation Mode | Best Used For | Where It Falls Down |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Genesis Sentinel** | Genesis `.seg` / `/query` & log files | Strict ceiling (`<=` <!-- claim:default_max_mem_mb -->256 MB<!-- /claim --> Go sidecar; optional local ML runtime) | Loopback-only (Zero external egress) | **Alert-Only** (`service=sentinel`) | Local-first Genesis hosts, dev/homelab anomaly triage, air-gapped environments | No automated IP banning, no kernel eBPF syscall visibility, single-host scope |
| **Fail2ban** | Local log files & `systemd` journal | Minimal (`~20–50 MB`) | Zero external egress | Active (`iptables`, `nftables`, `pf`) | Immediate SSH / web brute-force IP blocking on single servers | Static regex filters only; no statistical novelty scoring or structured triage |
| **CrowdSec** | Local logs, syslog, cloud audit streams | Low to Medium (`~100–250 MB`) | Optional cloud CTI & blocklist sync | Active via external Bouncers (firewall, Nginx, Cloudflare) | Internet-facing servers benefiting from crowd-sourced IP reputation & active blocking | Full value relies on external CTI hub connectivity rather than strict air-gapped operation |
| **Falco** | Linux kernel syscalls (eBPF / kmod) & plugins | Low to Medium (`~100–300 MB`) | Local or remote webhook sinks | Alert-first (optional Falco Talon response) | Detecting container escapes, unexpected `execve` lineage, sensitive file opens | Linux kernel-centric; does not collapse high-volume application log streams or train host adapters |
| **OSSEC** | Host logs, file integrity (FIM), rootcheck | Low (`~50–150 MB` agent) | Agent-to-manager encrypted channel | Alerting + optional active response scripts | Classic host-based IDS with file integrity monitoring across Linux/BSD/Windows fleets | C XML rule maintenance overhead; lacks information-theoretic anomaly scoring |
| **Wazuh / OpenSearch Security** | Fleet logs, FIM, vulnerability & cloud posture | Heavy (`4 GB–16 GB+` with OpenSearch JVM) | Multi-node cluster & CTI feeds | Full SIEM / XDR + active response | Multi-host compliance (PCI-DSS, HIPAA, SOC 2), long-term retention, fleet dashboards | Heavy JVM/cluster operational footprint for a single workstation, CI runner, or edge host |

---

## Detailed Tool Breakdown

### 1. Fail2ban
* **Where it fits:** Internet-exposed SSH daemons, mail relays, and reverse proxies where deterministic regex matches should immediately trigger temporary `nftables`, `iptables`, or `pf` firewall bans.
* **Where Genesis Sentinel fits instead:** Sentinel enforces a strict **alert-only safety boundary** so crafted or spoofed log lines cannot trick the detector into banning legitimate upstream infrastructure. Sentinel also pairs deterministic RE2 rules with Drain template collapsing, Laplace-LK surprisal scoring for unseen anomalies, and local LoRA triage explanations.

### 2. CrowdSec
* **Where it fits:** Production edge hosts where sharing attack signals and subscribing to community-curated IP blocklists stops known botnets before they brute-force endpoints.
* **Where Genesis Sentinel fits instead:** Strict zero-egress environments where log metadata, source IPs, and operational baselines must remain on loopback (`127.0.0.1`), and where anomalies are tailored to custom internal application logs via local FTaaS LoRA fine-tuning.

### 3. Falco
* **Where it fits:** Kubernetes nodes and Linux hosts where attackers bypass application logging altogether—requiring kernel eBPF hooks on `execve`, `connect`, `ptrace`, and privilege-escalation syscalls.
* **Where Genesis Sentinel fits instead:** Cross-platform user-space application and service telemetry ingested by Project Genesis on macOS or Linux without loading kernel modules or privileged eBPF probes. (On hardened Linux hosts, running Falco for kernel syscalls alongside Genesis + Sentinel for application log streams is complementary.)

### 4. OSSEC
* **Where it fits:** Traditional host-based intrusion detection combining log decoding, file integrity checksum monitoring (FIM), and centralized manager-agent rollups.
* **Where Genesis Sentinel fits instead:** Zero-dependency pure-Go sidecar deployments tailing Genesis CRC32 `.seg` segments losslessly with sub-100-microsecond per-window Laplace-LK novelty scoring and interactive operator feedback (`sentinel feedback` / `sentinel train`).

### 5. Wazuh & OpenSearch Security Analytics
* **Where they fit:** Organization-wide security operations centers requiring multi-month indexed retention, Sigma rule libraries, endpoint vulnerability inventories, and compliance reporting dashboards.
* **Where Genesis Sentinel fits instead:** Single-machine developer environments, self-hosted appliances, and privacy-sensitive local setups that want structured anomaly triage inside Genesis's existing Web UI without operating a multi-gigabyte JVM cluster.

---

## Living Document & Freshness Policy

This document is governed by an automated **180-day freshness cadence** tracked in the `landscape-meta` header and enforced by `scripts/audit-claims.py`.

Our commitment is intellectual honesty:
* If any tool listed here has evolved to change a limitation or trade-off noted above, please open an issue or pull request with the updated release version.
* We re-evaluate all listed projects semi-annually against their current stable releases and record updates to cited trade-offs.
* **Radar & Emerging Tools:** We track lightweight local log and security tools (such as Vector VRL pipelines, Sigma-to-Go evaluators, and compact ONNX/GGUF local security classifiers) for inclusion in future review cycles.
