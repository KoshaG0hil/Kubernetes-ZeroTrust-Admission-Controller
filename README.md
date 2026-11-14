# ☸️ Kubernetes Zero-Trust Workload Admission Controller & Quarantine Mesh

[![Kubernetes](https://img.shields.io/badge/Kubernetes-v1.28%2B-326CE5.svg?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Tests](https://img.shields.io/badge/Tests-3%2F3%20Passed-brightgreen.svg?logo=pytest&logoColor=white)](tests)
[![Zero Trust](https://img.shields.io/badge/Security-Zero_Trust_Admission-darkgreen.svg)](https://www.cisa.gov/)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Webhook-FastAPI-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise **Kubernetes Dynamic Admission Webhook (`ValidatingWebhookConfiguration`)** enforcing strict Zero-Trust pod security standards, preventing container escapes, blocking untrusted registries, and automatically quarantining non-compliant workloads at the API server boundary.

---

## 🎯 Executive Highlights & Problem Solved

- **Zero-Trust Pod Admission**: Intercepts `CREATE` and `UPDATE` operations on Pods, Deployments, and DaemonSets before they touch the cluster etcd or schedule on worker nodes.
- **Root & Privilege Escape Prevention**: Blocks `privileged: true`, host namespaces (`hostNetwork`, `hostPID`, `hostIPC`), writable root filesystems, and uncontained Linux capabilities.
- **Container Registry & Tag Hardening**: Restricts image pulls to verified enterprise registries (ECR/GCR/Quay) and bans mutable tags (`:latest`, `:dev`) to enforce immutable digest deployment.
- **Automated Quarantine Logging**: Non-compliant workloads generate structured forensic incident logs (`reports/quarantine_incidents.json`) detailing violating UIDs, namespace actors, and remediation steps.
- **Zero-Cloud-Cost Local Simulation**: Includes a full CLI auditor and FastAPI webhook simulator enabling testing without requiring an active cloud bill.

---

## 🏛️ Architecture & Enforcement Flow

```text
                  kubectl apply -f workload.yaml / CI/CD Deployment
                                        │
                                        ▼
                         ┌─────────────────────────────┐
                         │    Kubernetes API Server    │
                         └──────────────┬──────────────┘
                                        │ AdmissionReview POST /validate
                                        ▼
                         ┌─────────────────────────────┐
                         │   Zero-Trust Webhook Pod    │
                         │ (FastAPI Validation Engine) │
                         └──────────────┬──────────────┘
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 ▼ (If Clean & Compliant)                      ▼ (If Policy Violated)
     ┌────────────────────────┐                   ┌────────────────────────┐
     │ 200 OK: Allowed        │                   │ 403 Forbidden: Denied  │
     │ Scheduled to Node      │                   │ Blocked at API Gateway │
     └────────────────────────┘                   └───────────┬────────────┘
                                                              │
                                                              ▼
                                                  ┌────────────────────────┐
                                                  │ Automated Quarantine   │
                                                  │ Forensic Incident Log  │
                                                  └────────────────────────┘
```

---

## 📋 Zero-Trust Admission Rules Evaluated

| Rule ID | Severity | Policy Title | Technical Constraint & Zero-Trust Impact |
| :--- | :---: | :--- | :--- |
| **`ZT-K8S-01`** | `HIGH` | Mandatory Metadata Labels | Enforces team ownership, environment, and cost-center tracking. |
| **`ZT-K8S-02`** | `CRITICAL` | Host Network Namespace | Disallows `hostNetwork: true` to prevent container packet sniffing. |
| **`ZT-K8S-03`** | `CRITICAL` | Host PID Namespace | Disallows `hostPID: true` to block visibility into host OS processes. |
| **`ZT-K8S-04`** | `CRITICAL` | Host IPC Namespace | Disallows `hostIPC: true` to block shared memory access across pods. |
| **`ZT-K8S-05`** | `HIGH` | Approved Registry Enforcement | Rejects images from unapproved registries (e.g. unverified public Docker Hub). |
| **`ZT-K8S-06`** | `MEDIUM` | Mutable Image Tags | Rejects `:latest` tags; mandates immutable semantic versioning or digests. |
| **`ZT-K8S-07`** | `CRITICAL` | Privileged Containers | Disallows `privileged: true` to eliminate host device access escapes. |
| **`ZT-K8S-08`** | `HIGH` | Non-Root UID Enforcement | Mandates `runAsNonRoot: true` and non-zero UID. |
| **`ZT-K8S-09`** | `MEDIUM` | Read-Only Root Filesystem | Mandates `readOnlyRootFilesystem: true` to prevent malware drops. |
| **`ZT-K8S-10`** | `HIGH` | Linux Capabilities Drop | Enforces `drop: ['ALL']` to remove default kernel privileges. |
| **`ZT-K8S-11`** | `MEDIUM` | Anti-DoS CPU Limits | Requires CPU limits to prevent host CPU starvation. |
| **`ZT-K8S-12`** | `HIGH` | Anti-DoS Memory Limits | Requires memory limits to avoid node-wide Out-Of-Memory (OOM) panics. |

---

## ⚡ Quickstart & Local Execution (Zero Cloud Spend)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the Offline Workload Audit
Audit sample workloads against the zero-trust security baseline:

```bash
python main.py --audit tests/mock_requests/sample_untrusted_workload.yaml
```

**Expected Terminal Output:**
```text
================================================================================
 ☸️ KUBERNETES ZERO-TRUST WORKLOAD ADMISSION AUDITOR
================================================================================
[*] Auditing Deployment 'insecure-crypto-miner' (Namespace: default)...
    ❌ ADMISSION DENIED: 13 Policy Violations Found.
    • [ZT-K8S-02] CRITICAL: Pod Host Network Namespace Violation
    • [ZT-K8S-03] CRITICAL: Pod Host PID Namespace Violation
    • [ZT-K8S-07] CRITICAL: Privileged Container Execution Blocked
    • [ZT-K8S-08] HIGH: Root User Execution Risk

[*] Auditing Pod 'compliant-zero-trust-microservice' (Namespace: production)...
    ✅ ADMISSION ALLOWED: Meets Zero-Trust Baseline.

--------------------------------------------------------------------------------
Summary: Evaluated 2 workloads | Allowed: 1 | Blocked: 1
================================================================================
```

### 3. Start the Live Admission Webhook Server
```bash
python main.py --server --port 8443
```
Endpoint `/validate` is now ready to receive Kubernetes `AdmissionReview` requests.

### 4. Run Automated Unit Tests
```bash
pytest -v
```

---

## 📜 License
Distributed under the **MIT License**.
