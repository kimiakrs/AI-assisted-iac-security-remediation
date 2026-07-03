import os
import shutil
from datetime import datetime

from app.services.scanner_service import run_checkov
from app.services.report_service import build_deterministic_report
from app.services.patch_plan_service import generate_patch_plan
from app.services.patch_apply_service import apply_patch_plan
from app.services.comparison_service import compare_reports
from app.services.explanation_service import explain_remediation_result
from app.services.report_writer_service import save_remediation_report
from app.services.rag_retriever_service import retrieve_context
from app.services.external_policy_service import enrich_rag_context_with_external_sources


AGENT_WORK_DIR = "agent_runs"


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


def run_agentic_remediation(file_path: str, max_iterations: int = 3) -> dict:
    os.makedirs(AGENT_WORK_DIR, exist_ok=True)

    original_filename = os.path.basename(file_path)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    current_path = os.path.join(
        AGENT_WORK_DIR,
        f"agent-{timestamp}-{original_filename}",
    )

    shutil.copyfile(file_path, current_path)

    iterations = []
    final_patch_plan = None
    final_report_before = None
    final_report_after = None
    final_fixed_yaml = None
    final_comparison = None
    stop_reason = "max_iterations_reached"

    for iteration_number in range(1, max_iterations + 1):
        scan_result_before = run_checkov(current_path)
        trusted_report_before = build_deterministic_report(scan_result_before)

        before_count = trusted_report_before.get("total_failed_checks", 0)

        rag_query, rag_context = get_enriched_rag_context(trusted_report_before)

        patch_plan = generate_patch_plan(
            trusted_report=trusted_report_before,
            rag_context=rag_context,
        )

        patches = patch_plan.get("patches", [])

        iteration_record = {
            "iteration": iteration_number,
            "input_file": current_path,
            "before_failed_checks": before_count,
            "patches_generated": len(patches),
            "patches_rejected": len(patch_plan.get("rejected_patches", [])),
            "manual_recommendations": len(patch_plan.get("manual_recommendations", [])),
            "rag_query": rag_query,
            "patch_plan": patch_plan,
        }

        if not patches:
            stop_reason = "no_more_safe_patches"
            iteration_record["status"] = "stopped_no_patches"
            iterations.append(iteration_record)

            final_patch_plan = patch_plan
            final_report_before = trusted_report_before
            final_report_after = trusted_report_before
            final_comparison = compare_reports(
                trusted_report_before,
                trusted_report_before,
            )
            final_fixed_yaml = open(current_path).read()

            break

        applied_patch = apply_patch_plan(current_path, patch_plan)

        iteration_record["applied_patch"] = applied_patch

        if applied_patch.get("status") != "success":
            stop_reason = "patch_apply_failed"
            iteration_record["status"] = "patch_apply_failed"
            iterations.append(iteration_record)

            final_patch_plan = patch_plan
            final_report_before = trusted_report_before
            final_report_after = trusted_report_before
            final_comparison = compare_reports(
                trusted_report_before,
                trusted_report_before,
            )
            final_fixed_yaml = open(current_path).read()

            break

        fixed_path = applied_patch["fixed_path"]
        fixed_yaml = applied_patch["fixed_yaml"]

        scan_result_after = run_checkov(fixed_path)
        trusted_report_after = build_deterministic_report(scan_result_after)

        after_count = trusted_report_after.get("total_failed_checks", 0)
        comparison = compare_reports(trusted_report_before, trusted_report_after)

        iteration_record["status"] = "iteration_complete"
        iteration_record["fixed_file"] = fixed_path
        iteration_record["after_failed_checks"] = after_count
        iteration_record["comparison"] = comparison

        iterations.append(iteration_record)

        final_patch_plan = patch_plan
        final_report_before = trusted_report_before
        final_report_after = trusted_report_after
        final_comparison = comparison
        final_fixed_yaml = fixed_yaml

        if after_count >= before_count:
            stop_reason = "no_improvement_after_rescan"
            break

        if after_count == 0:
            stop_reason = "all_findings_fixed"
            current_path = fixed_path
            break

        current_path = fixed_path

    llm_explanation = explain_remediation_result(final_comparison)

    saved_report = save_remediation_report(
        filename=original_filename,
        trusted_report_before=final_report_before,
        patch_plan=final_patch_plan,
        fixed_yaml=final_fixed_yaml,
        trusted_report_after=final_report_after,
        comparison=final_comparison,
        llm_explanation=llm_explanation,
        rag_unknown_analysis={
            "agent_iterations": iterations,
            "stop_reason": stop_reason,
        },
    )

    return {
        "status": "agent_remediation_complete",
        "filename": original_filename,
        "iterations": iterations,
        "stop_reason": stop_reason,
        "final_file": current_path,
        "final_summary": {
            "before_failed_checks": iterations[0].get("before_failed_checks") if iterations else None,
            "after_failed_checks": final_report_after.get("total_failed_checks") if final_report_after else None,
            "total_iterations": len(iterations),
        },
        "final_comparison": final_comparison,
        "llm_explanation": llm_explanation,
        "report_path": saved_report["report_path"],
    }
