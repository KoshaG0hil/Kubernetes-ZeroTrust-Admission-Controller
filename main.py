"""CLI Runner for Kubernetes Zero-Trust Admission Controller."""

import argparse
import json
import logging
import os
import sys
import yaml

# Ensure UTF-8 output on Windows consoles
if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.rules.engine import ZeroTrustRuleEngine
from src.quarantine.controller import WorkloadQuarantineController

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ZTAdmissionCLI")


def audit_manifest(manifest_file: str, policy_file: str):
    """Audit a local Kubernetes YAML or JSON manifest."""
    print("\n" + "=" * 80)
    print(" ☸️ KUBERNETES ZERO-TRUST WORKLOAD ADMISSION AUDITOR")
    print("=" * 80 + "\n")

    if not os.path.exists(manifest_file):
        print(f"[-] Error: Manifest file not found: {manifest_file}")
        return

    with open(policy_file, "r", encoding="utf-8") as f:
        policy_cfg = yaml.safe_load(f)

    with open(manifest_file, "r", encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))

    engine = ZeroTrustRuleEngine(policy_cfg)
    quarantine = WorkloadQuarantineController()

    total_workloads = 0
    denied_workloads = 0

    for doc in docs:
        if not doc or not isinstance(doc, dict):
            continue

        kind = doc.get("kind", "Unknown")
        metadata = doc.get("metadata", {})
        name = metadata.get("name", "unnamed")
        namespace = metadata.get("namespace", "default")

        if kind in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "Job"):
            total_workloads += 1
            if kind == "Pod":
                pod_spec = doc.get("spec", {})
            else:
                pod_spec = doc.get("spec", {}).get("template", {}).get("spec", {})

            is_allowed, violations = engine.evaluate_pod(pod_spec, metadata)

            print(f"[*] Auditing {kind} '{name}' (Namespace: {namespace})...")
            if is_allowed:
                print(f"    ✅ ADMISSION ALLOWED: Meets Zero-Trust Baseline.\n")
            else:
                denied_workloads += 1
                print(f"    ❌ ADMISSION DENIED: {len(violations)} Policy Violations Found.")

                quarantine.record_quarantine_incident(
                    admission_uid=f"cli-audit-{name}",
                    namespace=namespace,
                    workload_name=name,
                    violations=violations,
                    user="cli-security-auditor"
                )

                table_rows = []
                for v in violations:
                    table_rows.append([
                        v.get("rule_id"),
                        v.get("severity"),
                        v.get("title")[:36],
                        v.get("remediation")[:45]
                    ])

                if HAS_TABULATE:
                    print(tabulate(table_rows, headers=["Rule ID", "Severity", "Violation Title", "Remediation Action"], tablefmt="rounded_grid"))
                else:
                    for row in table_rows:
                        print(f"    • [{row[0]}] {row[1]}: {row[2]}")
                print()

    print("-" * 80)
    print(f"Summary: Evaluated {total_workloads} workloads | Allowed: {total_workloads - denied_workloads} | Blocked: {denied_workloads}")
    print("=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Zero-Trust Admission Controller")
    parser.add_argument("--audit", type=str, help="Path to Kubernetes YAML manifest file to audit")
    parser.add_argument("--policy", type=str, default="policies/zero_trust_baseline.yaml", help="Path to policy YAML")
    parser.add_argument("--server", action="store_true", help="Launch live FastAPI admission webhook server")
    parser.add_argument("--port", type=int, default=8443, help="Webhook server port")

    args = parser.parse_args()

    if args.server:
        import uvicorn
        from src.admission.webhook import app
        print(f"[*] Starting Zero-Trust Admission Webhook on port {args.port}...")
        uvicorn.run(app, host="0.0.0.0", port=args.port)
    elif args.audit:
        audit_manifest(args.audit, args.policy)
    else:
        # Default run on mock sample
        sample_path = "tests/mock_requests/sample_untrusted_workload.yaml"
        audit_manifest(sample_path, args.policy)


if __name__ == "__main__":
    main()
