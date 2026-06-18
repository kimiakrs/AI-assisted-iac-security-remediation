def get_issue_ids(report: dict) -> set:
    return {
        issue.get("check_id")
        for issue in report.get("issues", [])
        if issue.get("check_id")
    }


def compare_reports(before_report: dict, after_report: dict) -> dict:
    before_ids = get_issue_ids(before_report)
    after_ids = get_issue_ids(after_report)

    fixed_ids = sorted(before_ids - after_ids)
    remaining_ids = sorted(before_ids & after_ids)
    new_ids = sorted(after_ids - before_ids)

    return {
        "before_count": len(before_ids),
        "after_count": len(after_ids),
        "fixed_count": len(fixed_ids),
        "remaining_count": len(remaining_ids),
        "new_count": len(new_ids),
        "fixed_check_ids": fixed_ids,
        "remaining_check_ids": remaining_ids,
          "new_check_ids": new_ids
    }
