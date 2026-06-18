import json

from app.services.rag_retriever_service import retrieve_context
from app.services.llm_service import ask_llama


KNOWN_AUTO_FIX_IDS = {
    "CKV_K8S_16",
    "CKV_K8S_20",
    "CKV_K8S_14",
    "CKV_K8S_10",
    "CKV_K8S_12",
    "CKV_K8S_11",
    "CKV_K8S_13",
    "CKV_K8S_38",
    "CKV_K8S_37",
    "CKV_K8S_22",
}

#It expects dictionary which it enthaltet verschiedene Liste
def find_unknown_issues(report: dict) -> list:
    issues = report.get("issues", [])

    return [
        issue for issue in issues
        if issue.get("check_id") not in KNOWN_AUTO_FIX_IDS
    ]


def analyze_unknown_issue(issue: dict) -> dict:
    query = (
        f"{issue.get('check_id')} "
        f"{issue.get('check_name')} "
        f"{issue.get('problem')}"
    )

    retrieved_chunks = retrieve_context(query, top_k=3)

    context_text = "\n\n".join(
        chunk["text"] for chunk in retrieved_chunks
    )

    prompt = f"""
You are a Kubernetes DevSecOps assistant.

Use ONLY the retrieved context and the Checkov finding.
Do not invent facts.
Do not generate YAML.
Do not create patches.

Checkov finding:
{json.dumps(issue, indent=2)}

Retrieved context:
{context_text}

Return ONLY valid JSON:

{{
  "check_id": "{issue.get('check_id')}",
  "classification": "safe_auto_fix | needs_context | report_only",
  "summary": "short explanation",
  "suggested_action": "what the user should do",
  "reason": "why this classification was chosen"
}}
"""

    llm_result = ask_llama(prompt)

    return {
        "check_id": issue.get("check_id"),
        "query": query,
        "retrieved_context": retrieved_chunks,
        "llm_result": llm_result
    }


def analyze_unknown_findings_with_rag(
    trusted_report_before: dict,
    trusted_report_after: dict
) -> dict:
    unknown_issues = find_unknown_issues(trusted_report_after)

    analyses = []

    for issue in unknown_issues[:5]:
        analyses.append(analyze_unknown_issue(issue))

    return {
        "unknown_count": len(unknown_issues),
        "analyzed_count": len(analyses),
        "analyses": analyses
    }
