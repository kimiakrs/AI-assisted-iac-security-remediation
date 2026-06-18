import os
import json
from datetime import datetime


REPORT_DIR = "reports"


def save_remediation_report(
    filename: str,
    trusted_report_before: dict,
    patch_plan: dict,
    fixed_yaml: str,
    trusted_report_after: dict,
    comparison: dict,
    llm_explanation: dict,
    rag_unknown_analysis: dict
) -> dict:
    os.makedirs(REPORT_DIR, exist_ok=True)

    base_name = os.path.splitext(filename)[0]
    report_path = os.path.join(REPORT_DIR, f"{base_name}-remediation-report.json")

    report = {
        "filename": filename,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "trusted_report_before": trusted_report_before,
        "patch_plan": patch_plan,
        "fixed_yaml": fixed_yaml,
        "trusted_report_after": trusted_report_after,
        "comparison": comparison,
        "llm_explanation": llm_explanationi,
        "rag_unknown_analysis": rag_unknown_analysis
    }

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    return {
        "report_path": report_path,
        "report": report
    }
