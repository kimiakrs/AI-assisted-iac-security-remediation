import json
import requests
from typing import Any, Dict


def clean_model_json(response_text: str) -> str:
    cleaned = response_text.strip()

    if cleaned.startswith("```json"):
        cleaned = cleaned.replace("```json", "", 1).strip()

    if cleaned.startswith("```"):
        cleaned = cleaned.replace("```", "", 1).strip()

    if cleaned.endswith("```"):
        cleaned = cleaned[:-3].strip()

    return cleaned


def ask_llama(prompt: str, model: str = "qwen2.5-coder:1.5b") -> Dict[str, Any]:

    try:

        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.0,
                    "num_predict": 500,
                    "num_ctx": 2048
                }
            },
            timeout=240
        )

        response.raise_for_status()

        response_text = response.json().get("response", "").strip()

        cleaned_text = clean_model_json(response_text)

        try:
            return json.loads(cleaned_text)

        except json.JSONDecodeError:
            return {
                "error": "Model returned invalid JSON",
                "raw_response": response_text,
                "cleaned_response": cleaned_text
            }

    except requests.exceptions.Timeout:
        return {
            "error": "Ollama request timed out"
        }

    except requests.exceptions.RequestException as e:
        return {
            "error": "Ollama request failed",
            "details": str(e)
        }
