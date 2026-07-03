import json
import re

from app.services.llm_service import ask_llama
from app.services.external_policy_service import get_context_for_check_id
from app.services.remediation_catalog_service import (
    load_remediation_catalog,
    get_catalog_entry,
)


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


def select_patchable_issues(report: dict) -> list:
    selected = []
    catalog = load_remediation_catalog()

    for issue in report.get("issues", []):
        check_id = issue.get("check_id")
        catalog_entry = catalog.get(check_id)

        if not catalog_entry:
            continue

        if catalog_entry.get("remediation_type") == "automatic":
            selected.append(issue)

    return selected


def build_manual_recommendations(report: dict) -> list:
    recommendations = []
    catalog = load_remediation_catalog()

    for issue in report.get("issues", []):
        check_id = issue.get("check_id")
        catalog_entry = catalog.get(check_id)

        if catalog_entry and catalog_entry.get("remediation_type") == "automatic":
            continue

        reason = "No supported automatic remediation exists for this finding."

        if catalog_entry:
            reason = catalog_entry.get("reason", reason)

        recommendations.append({
            "check_id": check_id,
            "check_name": issue.get("check_name"),
            "classification": issue.get("classification"),
            "problem": issue.get("problem"),
            "risk": issue.get("risk"),
            "recommendation": issue.get("fix"),
            "resource": issue.get("resource"),
            "evaluated_keys": issue.get("evaluated_keys"),
            "remediation_type": "manual",
            "reason": reason,
        })

    return recommendations


def build_policy_context_for_issue(issue: dict, rag_context: list) -> str:
    check_id = issue.get("check_id", "")
    matching_context = get_context_for_check_id(rag_context, check_id)

    if not matching_context:
        return "No specific RAG/external context found. Use the trusted finding and remediation catalog."

    context_text = ""

    for context in matching_context[:2]:
        context_text += "\n---\n"
        context_text += context.get("text", "")[:1200]

    return context_text.strip()


def build_single_issue_prompt(issue: dict, catalog_entry: dict, policy_context: str) -> str:
    check_id = issue.get("check_id")

    safe_rule = {
        "path": catalog_entry.get("path"),
        "action": catalog_entry.get("action", "set"),
        "value": catalog_entry.get("value"),
    }

    return f"""
You are a Kubernetes YAML patch planner.

Return ONLY valid JSON.
Do not use markdown.
Do not explain.

Generate exactly ONE patch for this supported automatic remediation.

Trusted finding:
Check ID: {issue.get("check_id")}
Check name: {issue.get("check_name")}
Classification from report: {issue.get("classification")}
Problem: {issue.get("problem")}
Risk: {issue.get("risk")}
Fix from report: {issue.get("fix")}
Evaluated keys: {issue.get("evaluated_keys")}
Resource: {issue.get("resource")}

Relevant policy context:
{policy_context}

Supported remediation catalog entry:
{json.dumps(catalog_entry, indent=2)}

You MUST use this exact safe patch:
{json.dumps(safe_rule, indent=2)}

Rules:
- Return exactly one patch.
- action must always be "set".
- check_id must be "{check_id}".
- path must be "{safe_rule["path"]}".
- value must be exactly the catalog value.
- Do not invent another path.
- Do not invent another value.
- Do not use slash paths.
- Do not use [0] syntax.
- Use containers.0 syntax.
- Do not generate patches for manual remediation findings.

Return exactly this JSON schema:

{{
  "patches": [
    {{
      "check_id": "{check_id}",
      "path": "{safe_rule["path"]}",
      "action": "set",
      "value": {json.dumps(safe_rule["value"])}
    }}
  ]
}}
"""


def validate_single_patch(parsed_result: dict, issue: dict) -> dict:
    check_id = issue.get("check_id")
    catalog_entry = get_catalog_entry(check_id)

    if not catalog_entry:
        return {
            "patches": [],
            "rejected_patches": [{
                "check_id": check_id,
                "reason": "No remediation catalog entry exists for this check_id.",
            }],
        }

    if catalog_entry.get("remediation_type") != "automatic":
        return {
            "patches": [],
            "rejected_patches": [{
                "check_id": check_id,
                "reason": "Catalog entry is not automatic remediation.",
            }],
        }

    if not isinstance(parsed_result, dict):
        return {
            "patches": [],
            "rejected_patches": [{
                "check_id": check_id,
                "reason": "Parsed result is not a dictionary",
                "parsed_result": parsed_result,
            }],
        }

    if "error" in parsed_result:
        return {
            "patches": [],
            "rejected_patches": [{
                "check_id": check_id,
                "reason": "LLM response could not be parsed",
                "error": parsed_result,
            }],
        }

    raw_patches = parsed_result.get("patches")

    if not isinstance(raw_patches, list) or len(raw_patches) != 1:
        return {
            "patches": [],
            "rejected_patches": [{
                "check_id": check_id,
                "reason": "Expected exactly one patch",
                "parsed_result": parsed_result,
            }],
        }

    patch = raw_patches[0]

    if not isinstance(patch, dict):
        return {
            "patches": [],
            "rejected_patches": [{
                "check_id": check_id,
                "reason": "Patch is not a dictionary",
                "patch": patch,
            }],
        }

    patch_check_id = patch.get("check_id")
    action = patch.get("action")
    path = normalize_path(patch.get("path", ""))
    value = normalize_value(patch.get("value"))

    expected_path = catalog_entry.get("path")
    expected_action = catalog_entry.get("action", "set")
    expected_value = catalog_entry.get("value")

    if patch_check_id != check_id:
        return {
            "patches": [],
            "rejected_patches": [{
                "patch": patch,
                "reason": f"Invalid check_id. Expected: {check_id}",
            }],
        }

    if action != expected_action:
        return {
            "patches": [],
            "rejected_patches": [{
                "patch": patch,
                "reason": f"Invalid action. Expected: {expected_action}",
            }],
        }

    if path != expected_path:
        return {
            "patches": [],
            "rejected_patches": [{
                "patch": patch,
                "reason": f"Invalid path. Expected: {expected_path}",
            }],
        }

    if value != expected_value:
        return {
            "patches": [],
            "rejected_patches": [{
                "patch": patch,
                "reason": f"Invalid value. Expected: {expected_value}",
            }],
        }

    return {
        "patches": [{
            "check_id": check_id,
            "path": expected_path,
            "action": expected_action,
            "value": expected_value,
            "source": "remediation_catalog",
        }],
        "rejected_patches": [],
    }


def generate_patch_for_issue(issue: dict, rag_context: list) -> dict:
    check_id = issue.get("check_id")
    catalog_entry = get_catalog_entry(check_id)

    if not catalog_entry:
        return {
            "patches": [],
            "rejected_patches": [{
                "check_id": check_id,
                "reason": "No remediation catalog entry exists.",
            }],
        }

    if catalog_entry.get("remediation_type") != "automatic":
        return {
            "patches": [],
            "rejected_patches": [{
                "check_id": check_id,
                "reason": "Finding is not marked automatic in remediation catalog.",
            }],
        }

    policy_context = build_policy_context_for_issue(
        issue=issue,
        rag_context=rag_context,
    )

    prompt = build_single_issue_prompt(
        issue=issue,
        catalog_entry=catalog_entry,
        policy_context=policy_context,
    )

    result = ask_llama(prompt)

    print(f"\n===== PATCH PLAN RAW RESULT FOR {check_id} =====")
    print(result)
    print("==============================================\n")

    parsed_result = extract_json_from_llm_result(result)

    return validate_single_patch(
        parsed_result=parsed_result,
        issue=issue,
    )


def generate_patch_plan(trusted_report: dict, rag_context: list = None) -> dict:
    if rag_context is None:
        rag_context = []

    auto_patchable_issues = select_patchable_issues(trusted_report)
    manual_recommendations = build_manual_recommendations(trusted_report)

    all_patches = []
    all_rejected_patches = []

    for issue in auto_patchable_issues:
        result = generate_patch_for_issue(
            issue=issue,
            rag_context=rag_context,
        )

        all_patches.extend(result.get("patches", []))
        all_rejected_patches.extend(result.get("rejected_patches", []))

    return {
        "patches": all_patches,
        "rejected_patches": all_rejected_patches,
        "manual_recommendations": manual_recommendations,
        "auto_patchable_count": len(auto_patchable_issues),
        "manual_recommendation_count": len(manual_recommendations),
        "catalog_based": True,
    }
