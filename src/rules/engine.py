"""Zero-Trust Kubernetes Admission Rules & Validation Engine."""

import re
from typing import Any, Dict, List, Tuple


class ZeroTrustRuleEngine:
    """Evaluates Kubernetes Pod specifications against zero-trust security baselines."""

    def __init__(self, baseline_config: Dict[str, Any]):
        self.config = baseline_config
        self.allowed_registries = self.config.get("allowed_registries", [])
        self.disallow_tags = set(self.config.get("disallow_image_tags", ["latest"]))
        self.sec_rules = self.config.get("security_context_guardrails", {})
        self.res_rules = self.config.get("resource_limits_guardrails", {})
        self.mandatory_labels = self.config.get("mandatory_labels", [])

    def evaluate_pod(self, pod_spec: Dict[str, Any], metadata: Dict[str, Any]) -> Tuple[bool, List[Dict[str, Any]]]:
        """Validates pod spec. Returns (is_allowed, list_of_violations)."""
        violations = []

        # 1. Mandatory Labels Check
        labels = metadata.get("labels", {})
        for label in self.mandatory_labels:
            if label not in labels:
                violations.append({
                    "rule_id": "ZT-K8S-01",
                    "severity": "HIGH",
                    "title": f"Missing Mandatory Label: '{label}'",
                    "description": f"Workload metadata lacks required organizational governance label '{label}'.",
                    "remediation": f"Add label '{label}' under metadata.labels with valid ownership identifier."
                })

        # 2. Host Namespace Isolation
        if self.sec_rules.get("disallow_host_network") and pod_spec.get("hostNetwork", False):
            violations.append({
                "rule_id": "ZT-K8S-02",
                "severity": "CRITICAL",
                "title": "Pod Host Network Namespace Violation",
                "description": "hostNetwork: true allows pod to snoop host network interfaces and bypass network policies.",
                "remediation": "Remove hostNetwork: true from pod spec."
            })

        if self.sec_rules.get("disallow_host_pid") and pod_spec.get("hostPID", False):
            violations.append({
                "rule_id": "ZT-K8S-03",
                "severity": "CRITICAL",
                "title": "Pod Host PID Namespace Violation",
                "description": "hostPID: true allows container processes to view and signal host-level processes.",
                "remediation": "Remove hostPID: true to preserve process isolation."
            })

        if self.sec_rules.get("disallow_host_ipc") and pod_spec.get("hostIPC", False):
            violations.append({
                "rule_id": "ZT-K8S-04",
                "severity": "CRITICAL",
                "title": "Pod Host IPC Namespace Violation",
                "description": "hostIPC: true enables inter-process communication with host memory and other containers.",
                "remediation": "Remove hostIPC: true from pod spec."
            })

        # Pod-level security context
        pod_sec_ctx = pod_spec.get("securityContext", {})

        # Containers evaluation
        containers = pod_spec.get("containers", [])
        init_containers = pod_spec.get("initContainers", [])
        all_containers = containers + init_containers

        for c in all_containers:
            c_name = c.get("name", "unknown")
            image = c.get("image", "")

            # 3. Image Registry Governance
            if self.allowed_registries:
                is_from_allowed_reg = any(image.startswith(reg) for reg in self.allowed_registries)
                if not is_from_allowed_reg:
                    violations.append({
                        "rule_id": "ZT-K8S-05",
                        "severity": "HIGH",
                        "title": f"Unapproved Container Image Registry: '{c_name}'",
                        "description": f"Image '{image}' is pulled from unapproved registry. Allowed: {self.allowed_registries}",
                        "remediation": "Promote and mirror images into an approved enterprise container registry."
                    })

            # 4. Disallow Mutable / Undefined Image Tags (e.g. :latest)
            tag = image.split(":")[-1] if ":" in image else "latest"
            if tag in self.disallow_tags or "@sha256:" not in image and ":" not in image:
                violations.append({
                    "rule_id": "ZT-K8S-06",
                    "severity": "MEDIUM",
                    "title": f"Mutable Image Tag Detected: '{c_name}'",
                    "description": f"Container uses mutable tag '{tag}'. Zero-trust mandates immutable semantic versions or sha256 digests.",
                    "remediation": f"Pin image to immutable SHA-256 digest (e.g. '{image.split(':')[0]}@sha256:...')."
                })

            c_sec_ctx = c.get("securityContext", {})

            # 5. Privileged Container Prohibition
            if self.sec_rules.get("disallow_privileged") and c_sec_ctx.get("privileged", False):
                violations.append({
                    "rule_id": "ZT-K8S-07",
                    "severity": "CRITICAL",
                    "title": f"Privileged Container Execution Blocked: '{c_name}'",
                    "description": "privileged: true grants full root access to host devices and disables kernel namespaces.",
                    "remediation": "Set securityContext.privileged: false and use scoped capabilities."
                })

            # 6. Non-Root Execution Enforcement
            run_as_non_root = c_sec_ctx.get("runAsNonRoot") or pod_sec_ctx.get("runAsNonRoot")
            run_as_user = c_sec_ctx.get("runAsUser") or pod_sec_ctx.get("runAsUser")
            if self.sec_rules.get("require_run_as_non_root"):
                if run_as_non_root is False or run_as_user == 0 or (run_as_non_root is None and run_as_user is None):
                    violations.append({
                        "rule_id": "ZT-K8S-08",
                        "severity": "HIGH",
                        "title": f"Root User Execution Risk: '{c_name}'",
                        "description": f"Container '{c_name}' runs as UID 0 (root) or does not set runAsNonRoot: true.",
                        "remediation": "Configure securityContext.runAsNonRoot: true and specify a non-zero runAsUser (e.g. 10001)."
                    })

            # 7. Read-Only Root Filesystem
            if self.sec_rules.get("require_read_only_root_filesystem") and not c_sec_ctx.get("readOnlyRootFilesystem", False):
                violations.append({
                    "rule_id": "ZT-K8S-09",
                    "severity": "MEDIUM",
                    "title": f"Writable Root Filesystem: '{c_name}'",
                    "description": "readOnlyRootFilesystem: false allows attackers to install malware or overwrite binaries during a compromise.",
                    "remediation": "Set securityContext.readOnlyRootFilesystem: true and mount emptyDir volumes for scratch data."
                })

            # 8. Linux Capabilities Dropped
            caps = c_sec_ctx.get("capabilities", {})
            dropped = set(caps.get("drop", []))
            if self.sec_rules.get("drop_all_capabilities"):
                if "ALL" not in dropped and "all" not in dropped:
                    violations.append({
                        "rule_id": "ZT-K8S-10",
                        "severity": "HIGH",
                        "title": f"Excess Linux Capabilities on Container '{c_name}'",
                        "description": "Container does not drop capabilities.ALL. Attackers can leverage default capabilities for host escapes.",
                        "remediation": "Add securityContext.capabilities.drop: ['ALL'] and whitelist only strictly necessary privileges."
                    })

            # 9. Resource Limits & Requests (Anti-DoS)
            resources = c.get("resources", {})
            limits = resources.get("limits", {})
            requests = resources.get("requests", {})

            if self.res_rules.get("require_cpu_limits") and "cpu" not in limits:
                violations.append({
                    "rule_id": "ZT-K8S-11",
                    "severity": "MEDIUM",
                    "title": f"Missing CPU Limit: '{c_name}'",
                    "description": "Missing CPU limit enables noisy neighbors and CPU starvation attacks against the node.",
                    "remediation": "Define resources.limits.cpu (e.g. '500m' or '1000m')."
                })

            if self.res_rules.get("require_memory_limits") and "memory" not in limits:
                violations.append({
                    "rule_id": "ZT-K8S-12",
                    "severity": "HIGH",
                    "title": f"Missing Memory Limit: '{c_name}'",
                    "description": "Missing memory limit can cause node-wide OOM (Out-of-Memory) panics and pod evictions.",
                    "remediation": "Define resources.limits.memory (e.g. '512Mi' or '1Gi')."
                })

        is_allowed = len(violations) == 0
        return is_allowed, violations
