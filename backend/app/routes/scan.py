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
from app.services.rag_policy_service import analyze_unknown_issue
from app.services.rag_retriever_service import retrieve_context
from app.services.external_policy_service import (
    enrich_rag_context_with_external_sources,
    search_external_policy_context,
)


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


def build_rag_query_from_report(trusted_report: dict) -> str:
    issues = trusted_report.get("issues", [])
    query_parts = []

    for issue in issues:
        check_id = issue.get("check_id", "")
        check_name = issue.get("check_name", "")
        problem = issue.get("problem", "")
        query_parts.append(f"{check_id} {check_name} {problem}")

    return " ".join(query_parts).strip()


def get_enriched_rag_context(trusted_report: dict) -> tuple[str, list]:
    rag_query = build_rag_query_from_report(trusted_report)

    logger.info("Retrieving local RAG context")
    rag_context = retrieve_context(rag_query)

    logger.info("Enriching RAG context with structured external sources")
    rag_context = enrich_rag_context_with_external_sources(
        issues=trusted_report.get("issues", []),
        local_rag_context=rag_context,
        max_issues=5,
    )

    return rag_query, rag_context


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
            "ai_report": trusted_report,
        }

    except Exception as e:
        logger.exception("Upload/scan pipeline failed")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/patch-plan-test")
async def patch_plan_test(filename: str):
    file_path = os.path.join(UPLOAD_DIR, filename)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")

    logger.info("STEP 1 - Patch-plan test started")

    logger.info("STEP 2 - First Checkov scan started")
    scan_result = run_checkov(file_path)
    logger.info("STEP 3 - First Checkov scan finished")

    logger.info("STEP 4 - Building trusted report")
    trusted_report = build_deterministic_report(scan_result)
    logger.info("STEP 5 - Trusted report built")

    logger.info("STEP 6 - Retrieving local + external RAG context")
    rag_query, rag_context = get_enriched_rag_context(trusted_report)
    logger.info("STEP 7 - RAG context ready")

    logger.info("STEP 8 - Generating patch plan")
    patch_plan = generate_patch_plan(
        trusted_report=trusted_report,
        rag_context=rag_context,
    )
    logger.info("STEP 9 - Patch plan generated")

    if "error" in patch_plan:
        return {
            "status": "patch_plan_failed",
            "filename": filename,
            "trusted_report": trusted_report,
            "rag_query": rag_query,
            "rag_context_used_for_patch": rag_context,
            "patch_plan": patch_plan,
        }

    logger.info("STEP 10 - Applying patch")
    applied_patch = apply_patch_plan(file_path, patch_plan)
    logger.info("STEP 11 - Patch applied")

    if applied_patch.get("status") != "success":
        return {
            "status": "patch_apply_failed",
            "filename": filename,
            "trusted_report": trusted_report,
            "rag_query": rag_query,
            "rag_context_used_for_patch": rag_context,
            "patch_plan": patch_plan,
            "applied_patch": applied_patch,
        }

    logger.info("STEP 12 - Checkov rescan started")
    rescan_result = run_checkov(applied_patch["fixed_path"])
    logger.info("STEP 13 - Checkov rescan finished")

    logger.info("STEP 14 - Building fixed report")
    fixed_report = build_deterministic_report(rescan_result)
    logger.info("STEP 15 - Fixed report built")

    logger.info("STEP 16 - Comparing reports")
    comparison = compare_reports(trusted_report, fixed_report)
    logger.info("STEP 17 - Comparison finished")

    logger.info("STEP 18 - LLM explanation started")
    llm_explanation = explain_remediation_result(comparison)
    logger.info("STEP 19 - LLM explanation finished")

    logger.info("STEP 20 - Saving remediation report")
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
    logger.info("STEP 21 - Remediation report saved")

    return {
        "status": "patch_plan_test_complete",
        "filename": filename,
        "original_file": file_path,
        "fixed_file": applied_patch["fixed_path"],
        "trusted_report_before": trusted_report,
        "rag_query": rag_query,
        "rag_context_used_for_patch": rag_context,
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

    logger.info("DEBUG CHECKOV - started")

    scan_result = run_checkov(file_path)
    trusted_report = build_deterministic_report(scan_result)

    logger.info("DEBUG CHECKOV - finished")

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

    logger.info("DEBUG PATCH PLAN - started")

    scan_result = run_checkov(file_path)
    trusted_report = build_deterministic_report(scan_result)

    rag_query, rag_context = get_enriched_rag_context(trusted_report)

    patch_plan = generate_patch_plan(
        trusted_report=trusted_report,
        rag_context=rag_context,
    )

    logger.info("DEBUG PATCH PLAN - finished")

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

    logger.info("DEBUG APPLY PATCH - started")

    scan_result = run_checkov(file_path)
    trusted_report = build_deterministic_report(scan_result)

    rag_query, rag_context = get_enriched_rag_context(trusted_report)

    patch_plan = generate_patch_plan(
        trusted_report=trusted_report,
        rag_context=rag_context,
    )

    applied_patch = apply_patch_plan(file_path, patch_plan)

    logger.info("DEBUG APPLY PATCH - finished")

    return {
        "status": "apply_patch_ok",
        "filename": filename,
        "trusted_report": trusted_report,
        "rag_query": rag_query,
        "rag_context": rag_context,
        "patch_plan": patch_plan,
        "applied_patch": applied_patch,
    }


@router.get("/debug/rag-retrieve")
async def debug_rag_retrieve(query: str):
    logger.info("DEBUG RAG RETRIEVE - started")

    context = retrieve_context(query)

    logger.info("DEBUG RAG RETRIEVE - finished")

    return {
        "status": "rag_retrieve_ok",
        "query": query,
        "context": context,
    }


@router.get("/debug/external-policy")
async def debug_external_policy(check_id: str, check_name: str = ""):
    logger.info("DEBUG EXTERNAL POLICY - started")

    issue = {
        "check_id": check_id,
        "check_name": check_name,
        "problem": "",
        "risk": "",
        "fix": "",
    }

    result = search_external_policy_context(issue)

    logger.info("DEBUG EXTERNAL POLICY - finished")

    return {
        "status": "external_policy_ok",
        "result": result,
    }


@router.post("/debug/rag-one")
async def debug_rag_one():
    logger.info("DEBUG RAG ONE - started")

    issue = {
        "check_id": "CKV_K8S_43",
        "check_name": "Image should use digest",
        "problem": "Container image should use immutable digest",
    }

    result = analyze_unknown_issue(issue)

    logger.info("DEBUG RAG ONE - finished")

    return {
        "status": "rag_one_ok",
        "result": result,
    }
