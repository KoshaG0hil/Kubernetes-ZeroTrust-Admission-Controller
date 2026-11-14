"""Automated Workload Quarantine & Security Incident Response."""

from datetime import datetime, timezone
import json
import logging
import os
from typing import Any, Dict, List

logger = logging.getLogger(__name__)


class WorkloadQuarantineController:
    """Isolates and records non-compliant or compromised Kubernetes workloads."""

    def __init__(self, quarantine_log_path: str = "reports/quarantine_incidents.json"):
        self.log_path = quarantine_log_path
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)

    def record_quarantine_incident(
        self,
        admission_uid: str,
        namespace: str,
        workload_name: str,
        violations: List[Dict[str, Any]],
        user: str = "system"
    ) -> Dict[str, Any]:
        """Constructs and appends a forensic quarantine incident report."""
        timestamp = datetime.now(timezone.utc).isoformat()
        critical_count = sum(1 for v in violations if v.get("severity") == "CRITICAL")
        high_count = sum(1 for v in violations if v.get("severity") == "HIGH")

        # Isolation action plan
        remedial_action = (
            "AUTOMATED_REJECTION: Workload admission blocked at API server boundary. "
            "Isolated to quarantine log to prevent cluster compromise."
        )

        incident = {
            "incident_id": f"QUAR-{admission_uid[:8]}",
            "timestamp": timestamp,
            "target_workload": workload_name,
            "namespace": namespace,
            "requester": user,
            "action_taken": remedial_action,
            "summary": {
                "total_violations": len(violations),
                "critical": critical_count,
                "high": high_count
            },
            "violations": violations
        }

        # Persist to forensic log
        try:
            records = []
            if os.path.exists(self.log_path):
                with open(self.log_path, "r", encoding="utf-8") as f:
                    records = json.load(f)
            records.append(incident)
            with open(self.log_path, "w", encoding="utf-8") as f:
                json.dump(records, f, indent=2)
            logger.info(f"Recorded quarantine incident {incident['incident_id']} for {workload_name}")
        except Exception as e:
            logger.error(f"Failed to write quarantine incident log: {e}")

        return incident
