import os
import json
import requests
from bs4 import BeautifulSoup


CACHE_DIR = "knowledge_base/external_cache"

TRUSTED_SOURCES = [
    "https://www.checkov.io/7.Scan%20Examples/Kubernetes.html",
    "https://github.com/bridgecrewio/checkov",
]


def fetch_url_text(url: str, timeout: int = 20) -> str:
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")

    for tag in soup(["script", "style", "nav", "footer", "header"]):
        tag.decompose()

    lines = [
        line.strip()
        for line in soup.get_text(separator="\n").splitlines()
        if line.strip()
    ]

    return "\n".join(lines)


def local_context_contains_check_id(local_rag_context: list, check_id: str) -> bool:
    for item in local_rag_context:
        text = item.get("text", "")
        if check_id and check_id in text:
            return True
    return False


def extract_relevant_lines(
    text: str,
    check_id: str,
    check_name: str = "",
    window: int = 8,
) -> str:
    lines = text.splitlines()
    matched_indexes = []

    search_terms = [check_id]
    if check_name:
        search_terms.append(check_name)

    for index, line in enumerate(lines):
        for term in search_terms:
            if term and term.lower() in line.lower():
                matched_indexes.append(index)

    if not matched_indexes:
        return ""

    extracted = []
    seen = set()

    for idx in matched_indexes[:2]:
        start = max(0, idx - window)
        end = min(len(lines), idx + window)

        for line in lines[start:end]:
            if line not in seen:
                extracted.append(line)
                seen.add(line)

    return "\n".join(extracted[:60])


def build_structured_context(issue: dict, extracted_text: str, source_url: str) -> dict:
    check_id = issue.get("check_id", "")
    check_name = issue.get("check_name", "")

    return {
        "source": "external_policy_context",
        "url": source_url,
        "check_id": check_id,
        "check_name": check_name,
        "text": f"""
External policy context for {check_id}

Check name:
{check_name}

Problem from trusted Checkov report:
{issue.get("problem", "")}

Risk from trusted Checkov report:
{issue.get("risk", "")}

Fix from trusted Checkov report:
{issue.get("fix", "")}

Relevant external extract:
{extracted_text[:1000] if extracted_text else "No exact external section found. Use trusted Checkov report as primary source."}
""".strip(),
    }


def search_external_policy_context(issue: dict) -> dict:
    os.makedirs(CACHE_DIR, exist_ok=True)

    check_id = issue.get("check_id", "")
    check_name = issue.get("check_name", "")

    cache_path = os.path.join(CACHE_DIR, f"{check_id}.json")

    if os.path.exists(cache_path):
        with open(cache_path, "r") as f:
            return json.load(f)

    contexts = []

    for url in TRUSTED_SOURCES:
        try:
            page_text = fetch_url_text(url)
            relevant_text = extract_relevant_lines(
                text=page_text,
                check_id=check_id,
                check_name=check_name,
            )

            contexts.append(
                build_structured_context(
                    issue=issue,
                    extracted_text=relevant_text,
                    source_url=url,
                )
            )

        except Exception as e:
            contexts.append({
                "source": "external_policy_context",
                "url": url,
                "check_id": check_id,
                "check_name": check_name,
                "text": f"External fetch failed for {check_id}: {str(e)}",
            })

    result = {
        "check_id": check_id,
        "check_name": check_name,
        "external_context": contexts,
    }

    with open(cache_path, "w") as f:
        json.dump(result, f, indent=2)

    return result


def remove_duplicate_context(context_items: list) -> list:
    unique = []
    seen = set()

    for item in context_items:
        key = (
            item.get("check_id", ""),
            item.get("source", ""),
            item.get("url", ""),
            item.get("text", "")[:200],
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(item)

    return unique


def enrich_rag_context_with_external_sources(
    issues: list,
    local_rag_context: list,
    max_issues: int = 5,
) -> list:
    enriched_context = list(local_rag_context)
    added = 0

    for issue in issues:
        if added >= max_issues:
            break

        check_id = issue.get("check_id", "")

        if not check_id:
            continue

        if local_context_contains_check_id(local_rag_context, check_id):
            continue

        external_result = search_external_policy_context(issue)

        for context in external_result.get("external_context", []):
            enriched_context.append(context)

        added += 1

    return remove_duplicate_context(enriched_context)


def get_context_for_check_id(context_items: list, check_id: str) -> list:
    matched = []

    for item in context_items:
        text = item.get("text", "")
        item_check_id = item.get("check_id", "")

        if item_check_id == check_id or check_id in text:
            matched.append(item)

    return matched
