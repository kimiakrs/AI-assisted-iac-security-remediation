import json
import re

from app.services.llm_service import ask_llama
from app.services.external_policy_service import get_context_for_check_id


def select_patchable_issues(report: dict) -> list:
    priority_ids = [
        "CKV_K8S_16",
        "CKV_K8S_20",
        "CKV_K8S_10",
        "CKV_K8S_12",
        "CKV_K8S_11",
        "CKV_K8S_13",
        "CKV_K8S_38",
        "CKV_K8S_37",
        "CKV_K8S_22",
    ]

    issues = report.get("issues", [])
    selected = []

    for check_id in priority_ids:
        for issue in issues:
            if issue.get("check_id") == check_id:
                selected.append(issue)

    return selected[:5]


def normalize_value(value):
    if isinstance(value, str):
        lowered = value.strip().lower()

        if lowered == "true":
            return True

        if lowered == "false":
            return False

    return value


def normalize_path(path: str) -> str:
    if not path or not isinstance(path, str):
        return path

    path = path.strip()
    path = path.replace("/", ".")
    path = re.sub(r"\[(\d+)\]", r".\1", path)
    path = re.sub(r"\.+", ".", path)

    if path.startswith("."):
        path = path[1:]

    if path.endswith("."):
        path = path[:-1]

    return path


def extract_json_from_llm_result(result):
    if isinstance(result, dict):
        return result

    if not isinstance(result, str):
        return {
            "error": "LLM result is neither dict nor string",
            "raw_result": result,
        }

    raw = result.strip()

    try:
        return json.loads(raw)
    except Exception:
        pass

    start = raw.find("{")
    end = raw.rfind("}")

    if start != -1 and end != -1 and end > start:
        json_text = raw[start:end + 1]

        try:
            return json.loads(json_text)
        except Exception as e:
            return {
                "error": "Failed to parse JSON object from LLM response",
                "raw_result": raw,
                "json_text": json_text,
                "exception": str(e),
            }

    return {
        "error": "No valid JSON object found in LLM response",
        "raw_result": raw,
    }


def build_relevant_policy_context(issues: list, rag_context: list) -> str:
    blocks = []

    for issue in issues:
        check_id = issue.get("check_id", "")
        matching_context = get_context_for_check_id(rag_context, check_id)

        issue_block = f"""
Finding:
Check ID: {issue.get("check_id")}
Check name: {issue.get("check_name")}
Problem: {issue.get("problem")}
Risk: {issue.get("risk")}
Fix: {issue.get("fix")}
Evaluated keys: {issue.get("evaluated_keys")}

Relevant context:
"""

        if matching_context:
            for context in matching_context[:2]:
                issue_block += "\n---\n"
                issue_block += context.get("text", "")[:1000]
        else:
            issue_block += "\nNo specific RAG/external context found. Use the trusted finding only."

        blocks.append(issue_block.strip())

    return "\n\n====================\n\n".join(blocks)


def normalize_patch_plan(parsed_result: dict, allowed_check_ids: set) -> dict:
    if not isinstance(parsed_result, dict):
        return {
            "error": "Parsed LLM result is not a dictionary",
            "parsed_result": parsed_result,
        }

    if "error" in parsed_result:
        return parsed_result

    if "patches" in parsed_result and isinstance(parsed_result["patches"], list):
        raw_patches = parsed_result["patches"]
    else:
        return {
            "error": "Invalid patch plan structure",
            "parsed_result": parsed_result,
        }

    valid_patches = []
    rejected_patches = []

    allowed_paths = {
        "spec.automountServiceAccountToken",
        "spec.containers.0.image",
        "spec.containers.0.securityContext.privileged",
        "spec.containers.0.securityContext.allowPrivilegeEscalation",
        "spec.containers.0.securityContext.readOnlyRootFilesystem",
        "spec.containers.0.securityContext.capabilities.drop",
        "spec.containers.0.resources.requests.cpu",
        "spec.containers.0.resources.requests.memory",
        "spec.containers.0.resources.limits.cpu",
        "spec.containers.0.resources.limits.memory",
    }

    for patch in raw_patches:
        if not isinstance(patch, dict):
            rejected_patches.append({
                "patch": patch,
                "reason": "Patch is not a dictionary",
            })
            continue

        check_id = patch.get("check_id")

        if check_id not in allowed_check_ids:
            rejected_patches.append({
                "patch": patch,
                "reason": "Rejected because check_id was not found in selected trusted findings",
            })
            continue

        path = normalize_path(patch.get("path", ""))
        action = patch.get("action")

        if action != "set":
            rejected_patches.append({
                "patch": patch,
                "reason": "Only action=set is supported",
            })
            continue

        if not path:
            rejected_patches.append({
                "patch": patch,
                "reason": "Missing path",
            })
            continue

        if path not in allowed_paths:
            rejected_patches.append({
                "patch": patch,
                "reason": f"Path is not allowed: {path}",
            })
            continue

        if "value" not in patch:
            rejected_patches.append({
                "patch": patch,
                "reason": "Missing value",
            })
            continue

        valid_patches.append({
            "check_id": check_id,
            "path": path,
            "action": "set",
            "value": normalize_value(patch.get("value")),
        })

    return {
        "patches": valid_patches,
        "rejected_patches": rejected_patches,
    }


def generate_patch_plan(trusted_report: dict, rag_context: list = None) -> dict:
    if rag_context is None:
        rag_context = []

    issues = select_patchable_issues(trusted_report)

    if not issues:
        return {
            "patches": [],
            "rejected_patches": [],
            "message": "No safely patchable issues found",
        }

    allowed_check_ids = {
        issue.get("check_id")
        for issue in issues
        if issue.get("check_id")
    }

    policy_context = build_relevant_policy_context(
        issues=issues,
        rag_context=rag_context,
    )

    prompt = f"""
You are a Kubernetes YAML patch planner.

Return ONLY valid JSON.
Do not use markdown.
Do not explain.

You may ONLY create patches for these allowed check_ids:
{json.dumps(list(allowed_check_ids), indent=2)}

Every patch MUST contain:
- check_id
- path
- action
- value

Rules:
- action must always be "set".
- Do not invent check_ids.
- Do not patch check_ids outside the allowed list.
- Do not patch findings classified as needs_context.
- If unsure, return an empty patches list.
- Use dot notation paths only.
- Do not use slash paths.
- Do not use [0] syntax.
- Use containers.0 syntax.

Relevant trusted findings and matched policy context:
{policy_context}

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

Preferred safe default values:
- allowPrivilegeEscalation: false
- privileged: false
- readOnlyRootFilesystem: true
- capabilities.drop: ["ALL"]
- automountServiceAccountToken: false
- resources.requests.cpu: "250m"
- resources.requests.memory: "256Mi"
- resources.limits.cpu: "500m"
- resources.limits.memory: "512Mi"

Return exactly this JSON schema:

{{
  "patches": [
    {{
      "check_id": "one of the allowed check_ids",
      "path": "one allowed dot notation path",
      "action": "set",
      "value": "correct value"
    }}
  ]
}}
"""

    result = ask_llama(prompt)

    print("\n===== PATCH PLAN RAW RESULT =====")
    print(result)
    print("=================================\n")

    parsed_result = extract_json_from_llm_result(result)

    return normalize_patch_plan(
        parsed_result=parsed_result,
        allowed_check_ids=allowed_check_ids,
    )
