import os
import copy
import yaml


FIXED_DIR = "fixed"


def set_nested_value(data, path: str, value):
    parts = path.split(".")
    current = data

    for part in parts[:-1]:
        if part.isdigit():
            current = current[int(part)]
        else:
            if part not in current or current[part] is None:
                current[part] = {}
            current = current[part]

    last = parts[-1]

    if last.isdigit():
        current[int(last)] = value
    else:
        current[last] = value


def apply_patch_plan(file_path: str, patch_plan: dict) -> dict:
    if "error" in patch_plan:
        return {
            "status": "failed",
            "reason": "Patch plan contains error",
            "patch_plan": patch_plan,
        }

    patches = patch_plan.get("patches", [])

    if not patches:
        return {
            "status": "failed",
            "reason": "No patches found in patch plan",
            "patch_plan": patch_plan,
        }

    try:
        with open(file_path, "r") as f:
            original_yaml = yaml.safe_load(f)

        fixed_yaml_data = copy.deepcopy(original_yaml)

        applied_patches = []

        for patch in patches:
            action = patch.get("action")
            path = patch.get("path")
            value = patch.get("value")

            if action != "set":
                applied_patches.append({
                    "patch": patch,
                    "status": "skipped",
                    "reason": "Unsupported action"
                })
                continue

            if not path:
                applied_patches.append({
                    "patch": patch,
                    "status": "skipped",
                    "reason": "Missing path"
                })
                continue

            set_nested_value(fixed_yaml_data, path, value)

            applied_patches.append({
                "patch": patch,
                "status": "applied"
            })

        os.makedirs(FIXED_DIR, exist_ok=True)

        filename = os.path.basename(file_path)
        fixed_path = os.path.join(FIXED_DIR, f"fixed-{filename}")

        with open(fixed_path, "w") as f:
            yaml.safe_dump(fixed_yaml_data, f, sort_keys=False)

        fixed_yaml_text = yaml.safe_dump(fixed_yaml_data, sort_keys=False)

        return {
            "status": "success",
            "fixed_path": fixed_path,
            "fixed_yaml": fixed_yaml_text,
            "applied_patches": applied_patches,
        }

    except Exception as e:
        return {
            "status": "failed",
            "reason": str(e),
            "patch_plan": patch_plan,
        }
