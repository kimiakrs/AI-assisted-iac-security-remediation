import json
from app.services.llm_service import ask_llama


def select_patchable_issues(report: dict) -> list:
    priority_ids = [
        "CKV_K8S_16",  # privileged
        "CKV_K8S_20",  # allowPrivilegeEscalation
        "CKV_K8S_14",  # latest image tag
        "CKV_K8S_10",  # CPU requests
        "CKV_K8S_12",  # memory requests
        "CKV_K8S_11",  # CPU limits
        "CKV_K8S_13",  # memory limits
        "CKV_K8S_38",  # service account token
        "CKV_K8S_37",  # capabilities
        "CKV_K8S_22",  # read-only filesystem
    ]

    issues = report.get("issues", [])

    selected = []

    for check_id in priority_ids:
        for issue in issues:
            if issue.get("check_id") == check_id:
                selected.append(issue)

    return selected[:5]


def generate_patch_plan(trusted_report: dict) -> dict:
    issues = select_patchable_issues(trusted_report)

    prompt = f"""
You are a Kubernetes YAML patch planner.

Return ONLY valid JSON.
Do not explain.
Do not return YAML.
Do not use markdown.
Do not wrap output in ```json.
Use actual check_id values from the trusted findings.
Do not use placeholder values like "existing check id".
Only create patches for the trusted findings listed below.

Trusted findings:
{json.dumps(issues, indent=2)}

Allowed paths:
- spec.automountServiceAccountToken
- spec.containers.0.image
- spec.containers.0.securityContext.privileged
- spec.containers.0.securityContext.allowPrivilegeEscalation
- spec.containers.0.securityContext.readOnlyRootFilesystem
- spec.containers.0.securityContext.capabilities.drop
- spec.containers.0.resources.requests.cpu
- spec.containers.0.resources.requests.memory
- spec.containers.0.resources.limits.cpu
- spec.containers.0.resources.limits.memory

Example output:
{{
  "patches": [
    {{
      "check_id": "CKV_K8S_16",
      "path": "spec.containers.0.securityContext.privileged",
      "action": "set",
      "value": false
    }}
  ]
}}

Now return the patch plan JSON.
"""

    result = ask_llama(prompt)

    print("\n===== PATCH PLAN RAW RESULT =====")
    print(result)
    print("=================================\n")

    if isinstance(result, dict) and "patches" in result:
        return result

    return {
        "error": "Invalid patch plan returned by LLM",
        "raw_result": result
    }
