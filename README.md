# AI-assisted Kubernetes Security Remediation Copilot

This project is an AI-assisted Infrastructure-as-Code security remediation pipeline for Kubernetes manifests.

It combines deterministic security scanning with Checkov, local RAG retrieval, external policy enrichment, an Ollama-based LLM patch planner, strict patch validation, YAML patch application, and Checkov rescan verification.

## Project Goal

The goal is not to blindly ask an LLM to fix Kubernetes YAML.

Instead, the system uses a controlled remediation workflow:

1. Checkov detects Kubernetes security findings.
2. The backend creates a deterministic trusted report.
3. Local RAG retrieves relevant policy knowledge.
4. External policy context is added when local knowledge is missing.
5. The LLM generates a constrained JSON patch plan.
6. The backend validates the patch plan.
7. Safe patches are applied to the YAML file.
8. Checkov rescans the fixed file.
9. The system compares before/after results.

## Pipeline

```text
Kubernetes YAML
    ↓
Checkov Scan
    ↓
Trusted Deterministic Report
    ↓
Local RAG Retrieval
    ↓
External Policy Enrichment
    ↓
LLM Patch Plan
    ↓
Patch Validation
    ↓
Patch Apply
    ↓
Checkov Rescan
    ↓
Before/After Comparison
    ↓
Final Remediation Report
```

## Main Components

### FastAPI Backend

The backend exposes debug and remediation endpoints under:

```text
/scan
```

Important endpoints:

```text
POST /scan/debug/checkov
POST /scan/debug/patch-plan
POST /scan/debug/apply-patch
POST /scan/patch-plan-test
GET  /scan/debug/rag-retrieve
GET  /scan/debug/external-policy
```

### Checkov Scanner

Checkov is used as the deterministic source of truth. The LLM does not decide which vulnerabilities exist.

### Trusted Report Builder

Raw Checkov output is converted into a structured report containing:

* check_id
* check_name
* severity
* classification
* problem
* risk
* fix
* resource
* evaluated keys
* confidence

### Local RAG

The local RAG layer uses:

* SentenceTransformer: `all-MiniLM-L6-v2`
* FAISS vector index
* local Kubernetes policy knowledge base

### External Policy Enrichment

If the local RAG context does not contain the required Checkov policy ID, the system retrieves external policy context from trusted sources and converts it into structured context before sending it to the LLM.

### LLM Patch Planner

The LLM generates only JSON patch plans. It does not directly modify YAML.

Example patch plan:

```json
{
  "patches": [
    {
      "check_id": "CKV_K8S_20",
      "path": "spec.containers.0.securityContext.allowPrivilegeEscalation",
      "action": "set",
      "value": false
    }
  ]
}
```

### Patch Validator

Before applying a patch, the backend validates that:

* the check_id exists in the trusted Checkov findings
* the action is supported
* the path is allowed
* the value exists
* boolean-like strings are normalized

This prevents hallucinated or unsafe LLM patches from being applied.

### Patch Apply

Validated patches are applied to the Kubernetes YAML and written to the `fixed/` directory.

### Rescan

The fixed file is rescanned with Checkov to verify whether findings were actually resolved.

## Example Test

Create a vulnerable Kubernetes manifest:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-auto
spec:
  containers:
    - name: nginx
      image: nginx:1.25
      securityContext:
        allowPrivilegeEscalation: true
```

Run:

```bash
curl -X POST \
"http://127.0.0.1:8000/scan/debug/apply-patch?filename=test-auto.yaml"
```

Expected fixed result:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: test-auto
spec:
  containers:
  - name: nginx
    image: nginx:1.25
    securityContext:
      allowPrivilegeEscalation: false
```

## Safety Design

The LLM is not trusted blindly.

The system follows this principle:

```text
Checkov = source of truth
RAG = policy context
LLM = patch planner
Validator = safety gate
Checkov rescan = verification
```

## Current Supported Auto-fix Examples

Examples of safely patchable findings:

* CKV_K8S_20: disable privilege escalation
* CKV_K8S_16: disable privileged container
* CKV_K8S_10: add CPU requests
* CKV_K8S_12: add memory requests
* CKV_K8S_11: add CPU limits
* CKV_K8S_13: add memory limits
* CKV_K8S_38: disable unnecessary service account token mounting
* CKV_K8S_37: drop Linux capabilities
* CKV_K8S_22: enable read-only root filesystem

Findings that need application context, such as NetworkPolicy, readiness/liveness probes, image digests, namespaces, and runtime users, should not be blindly auto-patched.

## Tech Stack

* Python
* FastAPI
* Checkov
* Ollama
* FAISS
* SentenceTransformers
* BeautifulSoup
* Kubernetes YAML
* Local RAG
* External policy enrichment

## Project Status

The current implementation successfully demonstrates:

* Checkov scanning
* deterministic report generation
* local RAG retrieval
* external policy enrichment
* LLM patch planning
* patch validation
* YAML patch application
* fixed YAML generation

The next improvement is to enhance external policy retrieval with more targeted policy-specific search and better source ranking.
