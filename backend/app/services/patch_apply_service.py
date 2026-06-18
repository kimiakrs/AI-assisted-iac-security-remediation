import yaml


def convert_value(value):
    if value == "true":
        return True

    if value == "false":
        return False

    return value


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
        current[int(last)] = convert_value(value)
    else:
        current[last] = convert_value(value)


def apply_patch_plan(original_path: str, patch_plan: dict) -> dict:
    with open(original_path, "r") as f:
        data = yaml.safe_load(f)

    patches = patch_plan.get("patches", [])

    if not patches:
        return {
            "status": "no_patches",
            "patch_plan": patch_plan
        }

    for patch in patches:
        path = patch.get("path")
        value = patch.get("value")

        if not path:
            continue

        set_nested_value(data, path, value)

    fixed_path = (
        original_path
        .replace(".yaml", "-patched.yaml")
        .replace(".yml", "-patched.yml")
    )

    fixed_yaml = yaml.safe_dump(data, sort_keys=False)

    with open(fixed_path, "w") as f:
        f.write(fixed_yaml)

    return {
        "status": "success",
        "fixed_path": fixed_path,
        "fixed_yaml": fixed_yaml,
        "patch_plan": patch_plan
    }
