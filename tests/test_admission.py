"""Unit tests for Zero-Trust Admission Controller."""

import os
import sys
import pytest
import yaml

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.rules.engine import ZeroTrustRuleEngine
from src.quarantine.controller import WorkloadQuarantineController


@pytest.fixture
def rule_engine():
    policy_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "policies", "zero_trust_baseline.yaml"))
    with open(policy_path, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    return ZeroTrustRuleEngine(cfg)


def test_compliant_pod_allowed(rule_engine):
    pod_spec = {
        "securityContext": {"runAsNonRoot": True, "runAsUser": 10001},
        "containers": [
            {
                "name": "app",
                "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/service:v1.0.0",
                "securityContext": {
                    "privileged": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]}
                },
                "resources": {
                    "limits": {"cpu": "500m", "memory": "512Mi"},
                    "requests": {"cpu": "100m", "memory": "128Mi"}
                }
            }
        ]
    }
    metadata = {
        "labels": {
            "app.kubernetes.io/name": "test-app",
            "app.kubernetes.io/part-of": "core",
            "security.enterprise.io/owner": "secops",
            "security.enterprise.io/environment": "prod"
        }
    }
    is_allowed, violations = rule_engine.evaluate_pod(pod_spec, metadata)
    assert is_allowed is True
    assert len(violations) == 0


def test_privileged_and_host_network_blocked(rule_engine):
    pod_spec = {
        "hostNetwork": True,
        "hostPID": True,
        "containers": [
            {
                "name": "attacker-pod",
                "image": "docker.io/untrusted/image:latest",
                "securityContext": {"privileged": True}
            }
        ]
    }
    metadata = {"labels": {}}
    is_allowed, violations = rule_engine.evaluate_pod(pod_spec, metadata)
    assert is_allowed is False
    rule_ids = {v["rule_id"] for v in violations}
    assert "ZT-K8S-02" in rule_ids  # hostNetwork
    assert "ZT-K8S-03" in rule_ids  # hostPID
    assert "ZT-K8S-07" in rule_ids  # privileged
    assert "ZT-K8S-05" in rule_ids  # unapproved registry


def test_quarantine_incident_recorder():
    controller = WorkloadQuarantineController("reports/test_quarantine.json")
    violations = [{"rule_id": "ZT-K8S-07", "severity": "CRITICAL", "title": "Privileged Container"}]
    incident = controller.record_quarantine_incident(
        admission_uid="test-uid-12345",
        namespace="default",
        workload_name="rogue-pod",
        violations=violations
    )
    assert incident["incident_id"] == "QUAR-test-uid"
    assert incident["summary"]["critical"] == 1
    if os.path.exists("reports/test_quarantine.json"):
        os.remove("reports/test_quarantine.json")
