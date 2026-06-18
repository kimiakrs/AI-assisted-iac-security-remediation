import os
import shutil
import logging

from fastapi import APIRouter, UploadFile, File, HTTPException

from app.services.scanner_service import run_checkov
from app.services.report_service import build_deterministic_report
from app.services.patch_plan_service import generate_patch_plan
from app.services.patch_apply_service import apply_patch_plan
from app.services.comparison_service import compare_reports
from app.services.explanation_service import explain_remediation_result
from app.services.report_writer_service import save_remediation_report
from app.services.rag_policy_service import analyze_unknown_findings_with_rag


router = APIRouter(prefix="/scan", tags=["Scan"])

UPLOAD_DIR = "uploads"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def detect_file_type(filename: str) -> str:
    lower_name = filename.lower()

    if lower_name.endswith((".yaml", ".yml")):
        return "yaml"

    if lower_name.endswith(".tf"):
        return "terraform"

    if lower_name.endswith(".json"):
        return "json"

    if lower_name.endswith(".md"):
        return "markdown"

    if lower_name.endswith("dockerfile"):
        return "dockerfile"

    return "unknown"


@router.post("/upload")
async def upload_and_scan(file: UploadFile = File(...)):
    logger.info("Upload started")

    os.makedirs(UPLOAD_DIR, exist_ok=True)

    filename = file.filename
    detected_type = detect_file_type(filename)

    if detected_type == "unknown":
        raise HTTPException(
            status_code=400,
            detail="Unsupported file type."
        )

    file_path = os.path.join(UPLOAD_DIR, filename)

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        logger.info(f"File saved: {file_path}")
        logger.info(f"Detected type: {detected_type}")

        logger.info("Checkov scan started")
        scan_result = run_checkov(file_path)
        logger.info("Checkov scan finished")

        logger.info("Trusted report building started")
        trusted_report = build_deterministic_report(scan_result)
        logger.info("Trusted report building finished")

        return {
            "status": "success",
            "filename": filename,
            "saved_to": file_path,
            "content_type": file.content_type,
            "detected_type": detected_type,
            "scanner": "checkov",
            "scan_result": scan_result,
            "ai_report": trusted_report
        }

    except Exception as e:
        logger.exception("Upload/scan pipeline failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/patch-plan-test")
async def patch_plan_test(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    logger.info("Patch-plan test started")

    scan_result = run_checkov(file_path)
    trusted_report = build_deterministic_report(scan_result)

    patch_plan = generate_patch_plan(trusted_report)

    if "error" in patch_plan:
        return {
            "status": "patch_plan_failed",
            "filename": filename,
            "trusted_report": trusted_report,
            "patch_plan": patch_plan
        }

    applied_patch = apply_patch_plan(file_path, patch_plan)

    if applied_patch.get("status") != "success":
        return {
            "status": "patch_apply_failed",
            "filename": filename,
            "trusted_report": trusted_report,
            "patch_plan": patch_plan,
            "applied_patch": applied_patch
        }

    rescan_result = run_checkov(applied_patch["fixed_path"])
    fixed_report = build_deterministic_report(rescan_result)

    comparison = compare_reports(trusted_report, fixed_report)
    llm_explanation = explain_remediation_result(comparison)
    rag_unknown_analysis = analyze_unknown_findings_with_rag(
    trusted_report_before=trusted_report,
    trusted_report_after=fixed_report
    )
    saved_report = save_remediation_report(
        filename=filename,
        trusted_report_before=trusted_report,
        patch_plan=patch_plan,
        fixed_yaml=applied_patch["fixed_yaml"],
        trusted_report_after=fixed_report,
        comparison=comparison,
        llm_explanation=llm_explanation,
        rag_unknown_analysis=rag_unknown_analysis
        
    )

    return {
        "status": "patch_plan_test_complete",
        "filename": filename,
        "original_file": file_path,
        "fixed_file": applied_patch["fixed_path"],
        "trusted_report_before": trusted_report,
        "patch_plan": patch_plan,
        "fixed_yaml": applied_patch["fixed_yaml"],
        "trusted_report_after": fixed_report,
        "comparison": comparison,
        "llm_explanation": llm_explanation,
        "rag_unknown_analysis": rag_unknown_analysis,
        "report_path": saved_report["report_path"]
    }
