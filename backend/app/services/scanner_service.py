import json
import subprocess
from typing import Dict, Any


def run_checkov(file_path: str) -> Dict[str, Any]:
    command = [
        "checkov",
        "-f",
        file_path,
        "--framework",
        "kubernetes",
        "--output",
        "json",
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=120,
    )

    if not result.stdout:
        return {
            "status": "error",
            "message": "No output from Checkov",
            "returncode": result.returncode,
            "stderr": result.stderr,
        }

    try:
        parsed = json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "status": "error",
            "message": "Checkov returned invalid JSON",
            "returncode": result.returncode,
            "raw_output": result.stdout,
            "stderr": result.stderr,
        }

    parsed["_checkov_meta"] = {
        "returncode": result.returncode,
        "stderr": result.stderr,
    }

    return parsed
