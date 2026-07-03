# Agentic AI-Assisted Kubernetes Security Remediation Copilot

An AI-assisted DevSecOps pipeline for automatically analyzing, planning, validating, and remediating Kubernetes Infrastructure-as-Code (IaC) security misconfigurations.

The project combines deterministic security scanning with Retrieval-Augmented Generation (RAG), an LLM-based patch planner, a structured remediation catalog, backend validation, and an agentic remediation workflow that continuously verifies its own actions before applying security fixes.

---

# Project Overview

Unlike traditional AI code assistants, this project does **not** allow the LLM to directly modify Kubernetes manifests.

Instead, the system follows a secure remediation pipeline inspired by modern security copilots such as GitHub Copilot Autofix and Amazon Q Developer.

The LLM acts as a constrained planning component, while deterministic tools remain the source of truth for security findings and verification.

---

# High-Level Architecture

```text
                User Upload
                     │
                     ▼
          Scanner Tool (Checkov)
                     │
                     ▼
        Trusted Security Report
                     │
                     ▼
        RAG Retrieval Tool
   (Local Knowledge + External Policy)
                     │
                     ▼
         Remediation Catalog
                     │
                     ▼
       LLM Patch Planner Tool
                     │
                     ▼
        Backend Patch Validator
                     │
                     ▼
         YAML Patch Apply Tool
                     │
                     ▼
      Verification Tool (Checkov)
                     │
                     ▼
          Coordinator Agent
                     │
          Continue Remediation?
             │               │
            Yes              No
             │               │
             └──────► Final Report
```

---

# Agentic Remediation Workflow

The system follows an Observe → Plan → Act → Verify → Decide loop.

## 1. Observe

- Scan Kubernetes YAML using Checkov
- Generate a deterministic trusted security report

## 2. Plan

- Retrieve relevant security documentation using Local RAG
- Enrich missing information with external policy retrieval
- Consult the remediation catalog
- Generate constrained remediation patches using the LLM

## 3. Act

- Validate every generated patch
- Apply only validated patches

## 4. Verify

- Rescan the modified manifest
- Compare security findings before and after remediation

## 5. Decide

The Coordinator Agent determines whether:

- more automatic remediations are available
- no improvement was achieved
- only manual findings remain
- all findings have been resolved

If additional supported remediations exist, another iteration begins.

Otherwise, the workflow terminates and generates the final report.

---

# Security Pipeline

```text
Kubernetes Manifest
        │
        ▼
Checkov Scan
        │
        ▼
Trusted Security Report
        │
        ▼
RAG Context Retrieval
(Local + External)
        │
        ▼
Remediation Catalog Lookup
        │
        ▼
LLM Patch Planning
        │
        ▼
Patch Validation
        │
        ▼
Patch Application
        │
        ▼
Checkov Rescan
        │
        ▼
Comparison
        │
        ▼
Agent Decision
        │
        ▼
Final Report
```

---

# Core Components

## Scanner Tool

Uses **Checkov** as the deterministic source of truth.

The LLM never determines whether a vulnerability exists.

---

## Trusted Report Builder

Converts raw Checkov output into a normalized security report containing:

- Check ID
- Check Name
- Severity
- Problem
- Risk
- Suggested Fix
- Resource
- Evaluated Keys

---

## Local RAG

The project uses

- SentenceTransformer (all-MiniLM-L6-v2)
- FAISS
- Local Kubernetes security knowledge base

to retrieve policy information relevant to each finding.

---

## External Policy Enrichment

If local knowledge is insufficient, additional policy context is retrieved from trusted external documentation.

---

## Remediation Catalog

A structured knowledge base describing supported remediations.

Each Checkov rule is classified as either

- Automatic Remediation
- Manual Remediation

Automatic entries contain

- supported YAML path
- allowed action
- validated value
- remediation rationale

Manual entries explain why human intervention is required.

---

## LLM Patch Planner

The LLM never edits YAML directly.

Instead, it produces constrained JSON patch plans.

Example:

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

---

## Patch Validator

Before any modification is applied, the backend verifies:

- Check ID exists
- Remediation is supported
- YAML path is allowed
- Action is valid
- Value matches the remediation catalog

Only validated patches are accepted.

---

## Patch Apply Tool

Validated patches are applied to the Kubernetes manifest.

Modified manifests are written into

```
fixed/
```

---

## Verification Tool

The updated manifest is rescanned using Checkov.

The system verifies that findings were actually resolved before considering remediation successful.

---

## Coordinator Agent

The Coordinator Agent orchestrates all system components.

Available tools include:

- Scanner Tool
- Trusted Report Builder
- Local RAG Tool
- External Policy Tool
- Remediation Catalog
- Patch Planner Tool
- Patch Validator
- Patch Apply Tool
- Verification Tool
- Report Writer

The Coordinator Agent determines whether another remediation iteration should be executed.

---

# Example

Input

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

↓

Generated Patch

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

↓

Output

```yaml
securityContext:
  allowPrivilegeEscalation: false
```

↓

Verification

```text
Before Scan
------------
Failed Findings : 1

After Scan
-----------
Failed Findings : 0
```

---

# Safety Model

The project follows the following trust hierarchy:

```text
Checkov
        │
        ▼
Trusted Report
        │
        ▼
RAG Context
        │
        ▼
Remediation Catalog
        │
        ▼
LLM Patch Planning
        │
        ▼
Patch Validation
        │
        ▼
Patch Application
        │
        ▼
Checkov Verification
```

The LLM is never treated as the source of truth.

---

# Technology Stack

- Python
- FastAPI
- Checkov
- Ollama
- FAISS
- SentenceTransformers
- BeautifulSoup
- Kubernetes
- YAML
- Retrieval-Augmented Generation (RAG)

---

# Current Features

- Deterministic Kubernetes security scanning
- Trusted security report generation
- Local FAISS-based RAG
- External policy enrichment
- Structured remediation catalog
- LLM-based constrained patch planning
- Backend patch validation
- Safe YAML patch application
- Automatic Checkov verification
- Agentic Observe–Plan–Act–Verify remediation workflow
- Detailed remediation reports

---

# Roadmap

Future improvements include:

- Expand remediation catalog to support additional Checkov policies
- Terraform remediation support
- Dockerfile remediation support
- Human approval workflow before applying patches
- GitHub Pull Request generation
- Kubernetes deployment
- CI/CD integration with Jenkins
- Multi-repository support
- Support for additional security scanners
