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
    llm_explanation,
    rag_unknown_analysis=None,
) -> dict:
    os.makedirs(REPORT_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    safe_filename = filename.replace("/", "_").replace("\\", "_")
    report_path = os.path.join(
        REPORT_DIR,
        f"remediation-report-{safe_filename}-{timestamp}.json"
    )

    report = {
        "filename": filename,
        "created_at": timestamp,
        "trusted_report_before": trusted_report_before,
        "patch_plan": patch_plan,
        "fixed_yaml": fixed_yaml,
        "trusted_report_after": trusted_report_after,
        "comparison": comparison,
        "llm_explanation": llm_explanation,
        "rag_unknown_analysis": rag_unknown_analysis or {},
    }

    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    return {
        "status": "success",
        "report_path": report_path,
    }
