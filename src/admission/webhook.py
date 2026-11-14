"""Kubernetes Dynamic Admission Webhook (ValidatingWebhookConfiguration)."""

import json
import logging
import os
from typing import Any, Dict
import yaml
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from src.rules.engine import ZeroTrustRuleEngine
from src.quarantine.controller import WorkloadQuarantineController

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ZTAdmissionWebhook")

app = FastAPI(
    title="Kubernetes Zero-Trust Admission Controller",
    version="1.0.0",
    description="Validating webhook intercepting Kubernetes workloads against Zero-Trust CIS baselines"
)

# Load baseline policy
POLICY_PATH = os.environ.get("POLICY_PATH", "policies/zero_trust_baseline.yaml")


def load_policy(path: str) -> Dict[str, Any]:
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


policy_cfg = load_policy(POLICY_PATH)
rule_engine = ZeroTrustRuleEngine(policy_cfg)
quarantine_controller = WorkloadQuarantineController()


@app.get("/healthz")
def healthz():
    return {"status": "healthy", "service": "Zero-Trust Admission Webhook", "policy": POLICY_PATH}


@app.post("/validate")
async def validate_admission(request: Request):
    """Handles Kubernetes AdmissionReview POST requests."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Invalid JSON payload"})

    req = body.get("request", {})
    uid = req.get("uid", "00000000-0000-0000-0000-000000000000")
    namespace = req.get("namespace", "default")
    user_info = req.get("userInfo", {}).get("username", "unknown-user")
    obj = req.get("object", {})

    kind = req.get("kind", {}).get("kind", "Pod")
    metadata = obj.get("metadata", {})
    name = metadata.get("name") or metadata.get("generateName") or "unnamed-workload"

    # Extract pod spec (handles Pod, Deployment, DaemonSet, StatefulSet)
    if kind == "Pod":
        pod_spec = obj.get("spec", {})
    else:
        pod_spec = obj.get("spec", {}).get("template", {}).get("spec", {})

    logger.info(f"Evaluating AdmissionReview UID '{uid}' for {kind} '{name}' in namespace '{namespace}'")

    is_allowed, violations = rule_engine.evaluate_pod(pod_spec, metadata)

    if not is_allowed:
        logger.warning(f"Admission DENIED for {kind} '{name}': {len(violations)} violations detected")

        # Record forensic quarantine log
        quarantine_controller.record_quarantine_incident(
            admission_uid=uid,
            namespace=namespace,
            workload_name=name,
            violations=violations,
            user=user_info
        )

        rejection_reasons = "\n".join([f"• [{v['rule_id']}] {v['title']}: {v['description']}" for v in violations[:4]])
        if len(violations) > 4:
            rejection_reasons += f"\n... and {len(violations) - 4} more violations."

        admission_response = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": False,
                "status": {
                    "code": 403,
                    "message": f"Zero-Trust Admission Policy Violation:\n{rejection_reasons}"
                }
            }
        }
    else:
        logger.info(f"Admission ALLOWED for {kind} '{name}'")
        admission_response = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": uid,
                "allowed": True,
                "status": {
                    "code": 200,
                    "message": "Workload satisfies all zero-trust admission security guardrails."
                }
            }
        }

    return JSONResponse(content=admission_response)
