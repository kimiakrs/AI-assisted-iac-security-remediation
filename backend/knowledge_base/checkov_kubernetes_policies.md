# CKV_K8S_43 - Image should use digest

Problem:
Container images should use immutable digests.

Recommended remediation:
Use an image reference with a digest, for example nginx@sha256:<digest>.

Classification:
needs_context

Reason:
The exact image digest must be resolved from the container registry.


# CKV2_K8S_6 - Missing NetworkPolicy

Problem:
Pods should have a related NetworkPolicy to restrict network traffic.

Recommended remediation:
Create a Kubernetes NetworkPolicy that only allows required ingress and egress traffic.

Classification:
needs_context

Reason:
The correct NetworkPolicy depends on application communication requirements.


# CKV_K8S_21 - Default namespace should not be used

Problem:
Workloads should not run in the default namespace.

Recommended remediation:
Set metadata.namespace to an application-specific namespace.

Classification:
needs_context

Reason:
The correct namespace name depends on the organization or deployment environment.
