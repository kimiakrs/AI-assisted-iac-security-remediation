import subprocess
import json


def run_checkov(file_path: str) -> dict:
    command = [
        "checkov",
        "-f", file_path,
        "--output", "json"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    if result.stdout:
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError:
            return {
                "status": "error",
                "message": "Checkov returned invalid JSON",
                "raw_output": result.stdout,
                "stderr": result.stderr
            }

    return {
        "status": "error",
        "message": "No output from Checkov",
        "stderr": result.stderr
    }
