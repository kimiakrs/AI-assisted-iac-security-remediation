import json
from app.services.llm_service import ask_llama


def explain_remediation_result(comparison: dict) -> dict:
    prompt = f"""
You are a Kubernetes DevSecOps assistant.

Explain the remediation result using ONLY this verified comparison.
Do not invent findings.
Do not mention checks that are not listed.

Verified comparison:
{json.dumps(comparison, indent=2)}

Return ONLY valid JSON:

{{
  "summary": "short explanation of what improved",
  "fixed_explanation": "what was fixed",
  "remaining_risks": "what still needs work",
  "next_step": "recommended next action"
}}
"""

    return ask_llama(prompt)
