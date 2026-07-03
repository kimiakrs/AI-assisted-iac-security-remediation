import json
import os


CATALOG_PATH = "knowledge_base/remediation_catalog.json"


def load_remediation_catalog() -> dict:
    if not os.path.exists(CATALOG_PATH):
        return {}

    with open(CATALOG_PATH, "r") as file:
        return json.load(file)


def get_catalog_entry(check_id: str) -> dict | None:
    catalog = load_remediation_catalog()
    return catalog.get(check_id)


def is_automatic_remediation(check_id: str) -> bool:
    entry = get_catalog_entry(check_id)

    if not entry:
        return False

    return entry.get("remediation_type") == "automatic"


def is_manual_remediation(check_id: str) -> bool:
    entry = get_catalog_entry(check_id)

    if not entry:
        return True

    return entry.get("remediation_type") != "automatic"
