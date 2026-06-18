CHECKOV_K8S_RULES = {
    "CKV_K8S_16": {
        "severity": "high",
        "risk": "A privileged container can access host-level resources and may increase the impact of container escape.",
        "fix": "Set securityContext.privileged to false."
    },
    "CKV_K8S_20": {
        "severity": "high",
        "risk": "Privilege escalation may allow a process inside the container to gain more privileges than intended.",
        "fix": "Set securityContext.allowPrivilegeEscalation to false."
    },
    "CKV_K8S_12": {
        "severity": "medium",
        "risk": "Without memory requests, Kubernetes cannot schedule the pod reliably and the workload may cause resource pressure.",
        "fix": "Add resources.requests.memory to the container."
    },
    "CKV_K8S_10": {
        "severity": "medium",
        "risk": "Without CPU requests, Kubernetes cannot reserve CPU capacity properly for the workload.",
        "fix": "Add resources.requests.cpu to the container."
    },
    "CKV_K8S_38": {
        "severity": "medium",
        "risk": "Automatically mounted service account tokens may expose Kubernetes API credentials to workloads that do not need Kubernetes API access.",
        "fix": "Set automountServiceAccountToken: false unless the pod needs Kubernetes API access."
    },
    "CKV_K8S_14": {
        "severity": "medium",
        "risk": "Using the latest image tag makes deployments non-reproducible and may introduce unreviewed image changes.",
        "fix": "Use a fixed image tag instead of latest, for example nginx:1.25."
    },
    "CKV_K8S_37": {
        "severity": "medium",
        "risk": "Containers with unnecessary Linux capabilities have a larger attack surface.",
        "fix": "Drop all unnecessary capabilities, preferably with capabilities.drop: ['ALL']."
    },
    "CKV_K8S_8": {
        "severity": "low",
        "risk": "Without a liveness probe, Kubernetes may not automatically restart an unhealthy container.",
        "fix": "Add a livenessProbe to the container."
    },
    "CKV_K8S_9": {
        "severity": "low",
        "risk": "Without a readiness probe, Kubernetes may send traffic to a pod before it is ready.",
        "fix": "Add a readinessProbe to the container."
    },
    "CKV_K8S_29": {
        "severity": "medium",
        "risk": "Missing pod/container security context weakens workload isolation.",
        "fix": "Define pod and container securityContext settings such as runAsNonRoot and seccompProfile."
    },
    "CKV_K8S_11": {
        "severity": "medium",
        "risk": "Without CPU limits, a container may consume excessive CPU and affect other workloads.",
        "fix": "Add resources.limits.cpu to the container."
    },
    "CKV_K8S_13": {
        "severity": "medium",
        "risk": "Without memory limits, a container may consume excessive memory and affect node stability.",
        "fix": "Add resources.limits.memory to the container."
    },
}


def build_deterministic_report(checkov_result: dict, max_findings: int = 20) -> dict:
    failed_checks = checkov_result.get("results", {}).get("failed_checks", [])

    issues = []

    for check in failed_checks[:max_findings]:
        check_id = check.get("check_id")
        check_name = check.get("check_name")
        evaluated_keys = check.get("check_result", {}).get("evaluated_keys", [])
        resource = check.get("resource")
        line_range = check.get("file_line_range")

        mapped_rule = CHECKOV_K8S_RULES.get(check_id, {})

        issues.append({
            "check_id": check_id,
            "check_name": check_name,
            "severity": mapped_rule.get("severity", "medium"),
            "problem": check_name,
            "risk": mapped_rule.get(
                "risk",
                "This issue was detected by Checkov and should be reviewed according to the Checkov policy guidance."
            ),
            "fix": mapped_rule.get(
                "fix",
                "Review the evaluated key and update the Kubernetes manifest according to the Checkov finding."
            ),
            "resource": resource,
            "evaluated_keys": evaluated_keys,
            "file_line_range": line_range,
            "confidence": "high" if check_id in CHECKOV_K8S_RULES else "medium"
        })

    return {
        "summary": f"{len(failed_checks)} failed Checkov checks were detected.",
        "issues": issues,
        "final_recommendation": "Apply the listed remediations and rescan the manifest with Checkov."
    }
