import os
import shutil
import logging

from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from app.services.scanner_service import run_checkov
from app.services.report_service import build_deterministic_report
from app.services.patch_plan_service import generate_patch_plan
from app.services.patch_apply_service import apply_patch_plan
from app.services.comparison_service import compare_reports
from app.services.explanation_service import explain_remediation_result
from app.services.report_writer_service import save_remediation_report
from app.services.rag_retriever_service import retrieve_context
from app.services.external_policy_service import enrich_rag_context_with_external_sources
from app.services.remediation_agent_service import run_agentic_remediation


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

    if lower_name.endswith("dockerfile"):
        return "dockerfile"

    return "unknown"


def build_rag_query_from_report(trusted_report: dict) -> str:
    query_parts = []

    for issue in trusted_report.get("issues", []):
        query_parts.append(
            f"{issue.get('check_id', '')} "
            f"{issue.get('check_name', '')} "
            f"{issue.get('problem', '')} "
            f"{issue.get('risk', '')} "
            f"{issue.get('fix', '')}"
        )

    return " ".join(query_parts).strip()


def get_enriched_rag_context(trusted_report: dict) -> tuple[str, list]:
    rag_query = build_rag_query_from_report(trusted_report)

    local_context = retrieve_context(rag_query)

    enriched_context = enrich_rag_context_with_external_sources(
        issues=trusted_report.get("issues", []),
        local_rag_context=local_context,
        max_issues=5,
    )

    return rag_query, enriched_context


def scan_and_prepare_context(file_path: str) -> tuple[dict, str, list]:
    scan_result = run_checkov(file_path)
    trusted_report = build_deterministic_report(scan_result)

    rag_query, rag_context = get_enriched_rag_context(trusted_report)

    return trusted_report, rag_query, rag_context


@router.post("/upload")
async def upload_and_scan(file: UploadFile = File(...)):
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    filename = file.filename
    detected_type = detect_file_type(filename)

    if detected_type == "unknown":
        raise HTTPException(status_code=400, detail="Unsupported file type")

    file_path = os.path.join(UPLOAD_DIR, filename)

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        trusted_report, rag_query, rag_context = scan_and_prepare_context(file_path)

        return {
            "status": "upload_scan_complete",
            "filename": filename,
            "saved_to": file_path,
            "detected_type": detected_type,
            "rag_query": rag_query,
            "trusted_report": trusted_report,
        }

    except Exception as e:
        logger.exception("Upload scan failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/remediate")
async def remediate(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    logger.info("REMEDIATE - started")

    trusted_report, rag_query, rag_context = scan_and_prepare_context(file_path)

    patch_plan = generate_patch_plan(
        trusted_report=trusted_report,
        rag_context=rag_context,
    )

    if "error" in patch_plan:
        return {
            "status": "patch_plan_failed",
            "filename": filename,
            "trusted_report": trusted_report,
            "rag_query": rag_query,
            "patch_plan": patch_plan,
        }

    if not patch_plan.get("patches"):
        return {
            "status": "no_safe_auto_patches",
            "filename": filename,
            "trusted_report": trusted_report,
            "rag_query": rag_query,
            "patch_plan": patch_plan,
            "message": "No safe automatic patches were generated. Some findings require human context.",
        }

    applied_patch = apply_patch_plan(file_path, patch_plan)

    if applied_patch.get("status") != "success":
        return {
            "status": "patch_apply_failed",
            "filename": filename,
            "trusted_report": trusted_report,
            "rag_query": rag_query,
            "patch_plan": patch_plan,
            "applied_patch": applied_patch,
        }

    rescan_result = run_checkov(applied_patch["fixed_path"])
    fixed_report = build_deterministic_report(rescan_result)

    comparison = compare_reports(trusted_report, fixed_report)
    llm_explanation = explain_remediation_result(comparison)

    saved_report = save_remediation_report(
        filename=filename,
        trusted_report_before=trusted_report,
        patch_plan=patch_plan,
        fixed_yaml=applied_patch["fixed_yaml"],
        trusted_report_after=fixed_report,
        comparison=comparison,
        llm_explanation=llm_explanation,
        rag_unknown_analysis=None,
    )

    logger.info("REMEDIATE - finished")

    return {
        "status": "remediation_complete",
        "filename": filename,
        "original_file": file_path,
        "fixed_file": applied_patch["fixed_path"],
        "summary": {
            "before_failed_checks": trusted_report.get("total_failed_checks"),
            "after_failed_checks": fixed_report.get("total_failed_checks"),
            "patches_generated": len(patch_plan.get("patches", [])),
            "patches_rejected": len(patch_plan.get("rejected_patches", [])),
            "manual_recommendations": len(patch_plan.get("manual_recommendations", [])),
            "auto_patchable_count": patch_plan.get("auto_patchable_count", 0),
        },
        "trusted_report_before": trusted_report,
        "patch_plan": patch_plan,
        "fixed_yaml": applied_patch["fixed_yaml"],
        "trusted_report_after": fixed_report,
        "comparison": comparison,
        "llm_explanation": llm_explanation,
        "report_path": saved_report["report_path"],
    }


@router.post("/debug/checkov")
async def debug_checkov(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    scan_result = run_checkov(file_path)
    trusted_report = build_deterministic_report(scan_result)

    return {
        "status": "checkov_ok",
        "filename": filename,
        "trusted_report": trusted_report,
    }


@router.post("/debug/patch-plan")
async def debug_patch_plan(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    trusted_report, rag_query, rag_context = scan_and_prepare_context(file_path)

    patch_plan = generate_patch_plan(
        trusted_report=trusted_report,
        rag_context=rag_context,
    )

    return {
        "status": "patch_plan_ok",
        "filename": filename,
        "trusted_report": trusted_report,
        "rag_query": rag_query,
        "rag_context": rag_context,
        "patch_plan": patch_plan,
    }


@router.post("/debug/apply-patch")
async def debug_apply_patch(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    trusted_report, rag_query, rag_context = scan_and_prepare_context(file_path)

    patch_plan = generate_patch_plan(
        trusted_report=trusted_report,
        rag_context=rag_context,
    )

    applied_patch = apply_patch_plan(file_path, patch_plan)

    return {
        "status": "apply_patch_ok",
        "filename": filename,
        "trusted_report": trusted_report,
        "rag_query": rag_query,
        "rag_context": rag_context,
        "patch_plan": patch_plan,
        "applied_patch": applied_patch,
    }
@router.post("/agent/remediate")
async def agent_remediate(filename: str, max_iterations: int = 3):
    file_path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    logger.info("AGENT REMEDIATE - started")

    result = run_agentic_remediation(
        file_path=file_path,
        max_iterations=max_iterations,
    )

    logger.info("AGENT REMEDIATE - finished")

    return result

@router.get("/report/download")
async def download_report(path: str):
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="Report not found")

    return FileResponse(
        path,
        media_type="application/json",
        filename=os.path.basename(path),
    )
