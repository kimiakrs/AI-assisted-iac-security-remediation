from typing import Dict, Any, List


CHECKOV_K8S_RULES = {
    "CKV_K8S_16": {
        "severity": "high",
        "classification": "auto_fixable",
        "risk": "A privileged container can access host-level resources and may increase the impact of container escape.",
        "fix": "Set securityContext.privileged to false.",
    },
    "CKV_K8S_20": {
        "severity": "high",
        "classification": "auto_fixable",
        "risk": "Privilege escalation may allow a process inside the container to gain more privileges than intended.",
        "fix": "Set securityContext.allowPrivilegeEscalation to false.",
    },
    "CKV_K8S_10": {
        "severity": "medium",
        "classification": "auto_fixable",
        "risk": "Without CPU requests, Kubernetes cannot reserve CPU capacity properly for the workload.",
        "fix": "Add resources.requests.cpu to the container.",
    },
    "CKV_K8S_12": {
        "severity": "medium",
        "classification": "auto_fixable",
        "risk": "Without memory requests, Kubernetes cannot schedule the pod reliably and the workload may cause resource pressure.",
        "fix": "Add resources.requests.memory to the container.",
    },
    "CKV_K8S_11": {
        "severity": "medium",
        "classification": "auto_fixable",
        "risk": "Without CPU limits, a container may consume excessive CPU and affect other workloads.",
        "fix": "Add resources.limits.cpu to the container.",
    },
    "CKV_K8S_13": {
        "severity": "medium",
        "classification": "auto_fixable",
        "risk": "Without memory limits, a container may consume excessive memory and affect node stability.",
        "fix": "Add resources.limits.memory to the container.",
    },
    "CKV_K8S_38": {
        "severity": "medium",
        "classification": "auto_fixable",
        "risk": "Automatically mounted service account tokens may expose Kubernetes API credentials to workloads that do not need Kubernetes API access.",
        "fix": "Set automountServiceAccountToken to false unless the pod needs Kubernetes API access.",
    },
    "CKV_K8S_37": {
        "severity": "medium",
        "classification": "auto_fixable",
        "risk": "Containers with unnecessary Linux capabilities have a larger attack surface.",
        "fix": "Drop all unnecessary capabilities, preferably with capabilities.drop: ['ALL'].",
    },
    "CKV_K8S_22": {
        "severity": "medium",
        "classification": "auto_fixable",
        "risk": "A writable root filesystem can allow attackers to modify files inside the container.",
        "fix": "Set securityContext.readOnlyRootFilesystem to true where the application supports it.",
    },

    "CKV2_K8S_6": {
        "severity": "medium",
        "classification": "needs_context",
        "risk": "Pods without NetworkPolicy may allow unrestricted network traffic.",
        "fix": "Create a NetworkPolicy after confirming required ingress, egress, ports, namespaces, and pod labels.",
    },
    "CKV_K8S_21": {
        "severity": "medium",
        "classification": "needs_context",
        "risk": "Running workloads in the default namespace weakens environment separation.",
        "fix": "Move the workload to an application-specific namespace after confirming the correct namespace strategy.",
    },
    "CKV_K8S_43": {
        "severity": "medium",
        "classification": "needs_context",
        "risk": "Image tags can change over time; digest pinning improves reproducibility.",
        "fix": "Use an image digest after resolving the correct digest from the trusted container registry.",
    },
    "CKV_K8S_8": {
        "severity": "low",
        "classification": "needs_context",
        "risk": "Without a liveness probe, Kubernetes may not automatically restart an unhealthy container.",
        "fix": "Add a livenessProbe based on the application's health endpoint or command.",
    },
    "CKV_K8S_9": {
        "severity": "low",
        "classification": "needs_context",
        "risk": "Without a readiness probe, Kubernetes may send traffic to a pod before it is ready.",
        "fix": "Add a readinessProbe based on the application's readiness endpoint or command.",
    },
    "CKV_K8S_14": {
        "severity": "medium",
        "classification": "needs_context",
        "risk": "Using latest or an empty image tag makes deployments non-reproducible.",
        "fix": "Use a fixed approved image tag selected by the application owner.",
    },
    "CKV_K8S_15": {
        "severity": "medium",
        "classification": "needs_context",
        "risk": "Image pull policy can affect image freshness and deployment behavior.",
        "fix": "Set imagePullPolicy according to the deployment strategy.",
    },
    "CKV_K8S_23": {
        "severity": "medium",
        "classification": "needs_context",
        "risk": "Running as root increases the impact of container compromise.",
        "fix": "Set runAsNonRoot and runAsUser after confirming the application supports a non-root UID.",
    },
    "CKV_K8S_29": {
        "severity": "medium",
        "classification": "needs_context",
        "risk": "Missing pod/container security context weakens workload isolation.",
        "fix": "Define pod and container securityContext settings such as runAsNonRoot and seccompProfile.",
    },
    "CKV_K8S_30": {
        "severity": "medium",
        "classification": "needs_context",
        "risk": "Missing container security context weakens workload isolation.",
        "fix": "Define container securityContext settings after confirming application runtime requirements.",
    },
    "CKV_K8S_31": {
        "severity": "medium",
        "classification": "needs_context",
        "risk": "Missing seccomp profile reduces syscall-level isolation.",
        "fix": "Set seccompProfile to RuntimeDefault where supported.",
    },
    "CKV_K8S_40": {
        "severity": "medium",
        "classification": "needs_context",
        "risk": "Low UIDs may conflict with host users or increase risk in some runtime configurations.",
        "fix": "Set runAsUser to a high non-root UID after confirming application compatibility.",
    },
}


def _get_failed_checks(checkov_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    results = checkov_result.get("results", {})

    if isinstance(results, dict):
        return results.get("failed_checks", []) or []

    if isinstance(results, list):
        failed = []
        for item in results:
            if isinstance(item, dict):
                failed.extend(item.get("failed_checks", []) or [])
        return failed

    return []


def build_deterministic_report(
    checkov_result: Dict[str, Any],
    max_findings: int = 50,
) -> Dict[str, Any]:
    failed_checks = _get_failed_checks(checkov_result)

    issues = []

    for check in failed_checks[:max_findings]:
        check_id = check.get("check_id", "")
        check_name = check.get("check_name", "")
        evaluated_keys = check.get("check_result", {}).get("evaluated_keys", [])
        resource = check.get("resource", "")
        line_range = check.get("file_line_range", [])
        file_path = check.get("file_path", "")
        guideline = check.get("guideline", "")

        mapped_rule = CHECKOV_K8S_RULES.get(check_id, {})

        classification = mapped_rule.get("classification", "unknown")

        issues.append({
            "check_id": check_id,
            "check_name": check_name,
            "severity": mapped_rule.get("severity", "medium"),
            "classification": classification,
            "problem": check_name,
            "risk": mapped_rule.get(
                "risk",
                "This issue was detected by Checkov and should be reviewed using external policy guidance."
            ),
            "fix": mapped_rule.get(
                "fix",
                "Retrieve external policy guidance and review the Kubernetes manifest manually."
            ),
            "resource": resource,
            "file_path": file_path,
            "evaluated_keys": evaluated_keys,
            "file_line_range": line_range,
            "guideline": guideline,
            "confidence": "high" if check_id in CHECKOV_K8S_RULES else "low",
        })

    return {
        "summary": f"{len(failed_checks)} failed Checkov checks were detected.",
        "total_failed_checks": len(failed_checks),
        "returned_findings": len(issues),
        "issues": issues,
        "final_recommendation": "Apply safe auto-fixable remediations, generate guidance for context-dependent findings, and rescan with Checkov.",
    }
