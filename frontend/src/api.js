export const API_BASE = "http://192.168.64.3:8000";

export async function uploadFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE}/scan/upload`, {
    method: "POST",
    body: formData
  });

  if (!res.ok) throw new Error("Upload failed");
  return res.json();
}

export async function runRemediation(filename) {
  const res = await fetch(`${API_BASE}/scan/remediate?filename=${filename}`, {
    method: "POST"
  });

  if (!res.ok) throw new Error("Remediation failed");
  return res.json();
}

export async function runAgentRemediation(filename, maxIterations = 3) {
  const res = await fetch(
    `${API_BASE}/scan/agent/remediate?filename=${filename}&max_iterations=${maxIterations}`,
    { method: "POST" }
  );

  if (!res.ok) throw new Error("Agent remediation failed");
  return res.json();
}
export function getReportDownloadUrl(reportPath) {
  return `${API_BASE}/scan/report/download?path=${encodeURIComponent(reportPath)}`;
}
