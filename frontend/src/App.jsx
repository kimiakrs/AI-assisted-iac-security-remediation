import React, { useState } from "react";
import {
  ShieldCheck,
  Upload,
  Play,
  Bot,
  FileCode,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Activity
} from "lucide-react";
import { uploadFile, runRemediation, runAgentRemediation, getReportDownloadUrl } from "./api";

export default function App() {
  const [file, setFile] = useState(null);
  const [filename, setFilename] = useState("");
  const [uploadResult, setUploadResult] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeMode, setActiveMode] = useState("standard");
  const [error, setError] = useState("");

  async function handleUpload() {
    if (!file) return;
    setLoading(true);
    setError("");

    try {
      const data = await uploadFile(file);
      setUploadResult(data);
      setFilename(data.filename);
      setResult(null);
    } catch (err) {
      setError(err.message);
    }

    setLoading(false);
  }

  async function handleRemediate() {
    if (!filename) return;
    setLoading(true);
    setError("");
    setActiveMode("standard");

    try {
      const data = await runRemediation(filename);
      setResult(data);
    } catch (err) {
      setError(err.message);
    }

    setLoading(false);
  }

  async function handleAgentRemediate() {
    if (!filename) return;
    setLoading(true);
    setError("");
    setActiveMode("agent");

    try {
      const data = await runAgentRemediation(filename, 3);
      setResult(data);
    } catch (err) {
      setError(err.message);
    }

    setLoading(false);
  }

  const summary = result?.summary || result?.final_summary || {};
  const trustedReport = result?.trusted_report_before || uploadResult?.trusted_report;
  const patchPlan = result?.patch_plan || result?.iterations?.[0]?.patch_plan;
  const fixedYaml = result?.fixed_yaml;
  const iterations = result?.iterations || [];

  return (
    <div className="app">
      <header className="hero">
        <div>
          <div className="eyebrow">DevSecOps · Kubernetes · AI Remediation</div>
          <h1>AI Kubernetes Security Copilot</h1>
          <p>
            Scan Kubernetes manifests, generate safe AI-assisted patches,
            validate every change, rescan, and produce a remediation report.
          </p>
        </div>
        <div className="hero-badge">
          <ShieldCheck size={34} />
          <span>Agentic IaC Security</span>
        </div>
      </header>

      <section className="panel upload-panel">
        <div>
          <h2>Upload Manifest</h2>
          <p>Upload a Kubernetes YAML file and start the security workflow.</p>
        </div>

        <div className="upload-actions">
          <input
            type="file"
            accept=".yaml,.yml"
            onChange={(e) => setFile(e.target.files[0])}
          />
          <button onClick={handleUpload} disabled={!file || loading}>
            <Upload size={16} />
            Upload & Scan
          </button>
          <button onClick={handleRemediate} disabled={!filename || loading}>
            <Play size={16} />
            Run Remediation
          </button>
          <button onClick={handleAgentRemediate} disabled={!filename || loading}>
            <Bot size={16} />
            Run Agent
          </button>
        </div>

        {filename && <div className="file-pill">Current file: {filename}</div>}
        {error && <div className="error">{error}</div>}
      </section>

      <Pipeline activeMode={activeMode} />

      {loading && (
        <div className="loading">
          <Activity className="spin" />
          Running security workflow...
        </div>
      )}

      <section className="summary-grid">
        <MetricCard
          title="Before"
          value={summary.before_failed_checks ?? trustedReport?.total_failed_checks ?? "-"}
          label="failed checks"
          icon={<AlertTriangle />}
        />
        <MetricCard
          title="After"
          value={summary.after_failed_checks ?? "-"}
          label="failed checks"
          icon={<CheckCircle />}
        />
        <MetricCard
          title="Patches"
          value={summary.patches_generated ?? patchPlan?.patches?.length ?? "-"}
          label="generated"
          icon={<FileCode />}
        />
        <MetricCard
          title="Manual"
          value={
            summary.manual_recommendations ??
            patchPlan?.manual_recommendations?.length ??
            "-"
          }
          label="recommendations"
          icon={<Bot />}
        />
      </section>

      <main className="content-grid">
        <FindingsPanel report={trustedReport} />
        <PatchPanel patchPlan={patchPlan} />
      </main>

      {iterations.length > 0 && <AgentPanel iterations={iterations} result={result} />}

      {fixedYaml && <YamlPanel title="Fixed YAML" yaml={fixedYaml} />}

      {result?.report_path && (
        <section className="panel">
          <h2>Final Report</h2>
          <p className="report-path">{result.report_path}</p>

          <a
            className="download-button"
            href={getReportDownloadUrl(result.report_path)}
            download
          >
            Download JSON Report
          </a>
        </section>
      )}
    </div>
  );
}
function Pipeline({ activeMode }) {
  const steps = [
    "Upload",
    "Checkov Scan",
    "Trusted Report",
    "RAG",
    "Catalog",
    "Patch Plan",
    "Validate",
    "Apply",
    "Rescan",
    activeMode === "agent" ? "Agent Decide" : "Report"
  ];

  return (
    <section className="pipeline">
      {steps.map((step, index) => (
        <div className="step" key={step}>
          <div className="step-number">{index + 1}</div>
          <span>{step}</span>
        </div>
      ))}
    </section>
  );
}

function MetricCard({ title, value, label, icon }) {
  return (
    <div className="metric-card">
      <div className="metric-icon">{icon}</div>
      <div>
        <p>{title}</p>
        <h3>{value}</h3>
        <span>{label}</span>
      </div>
    </div>
  );
}

function FindingsPanel({ report }) {
  const issues = report?.issues || [];

  return (
    <section className="panel">
      <h2>Security Findings</h2>
      <p>{issues.length} findings detected by Checkov.</p>

      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Check ID</th>
              <th>Severity</th>
              <th>Classification</th>
              <th>Problem</th>
            </tr>
          </thead>
          <tbody>
            {issues.map((issue, idx) => (
              <tr key={`${issue.check_id}-${idx}`}>
                <td>{issue.check_id}</td>
                <td>
                  <Badge value={issue.severity} />
                </td>
                <td>
                  <Badge value={issue.classification} />
                </td>
                <td>{issue.problem}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function PatchPanel({ patchPlan }) {
  const patches = patchPlan?.patches || [];
  const rejected = patchPlan?.rejected_patches || [];
  const manual = patchPlan?.manual_recommendations || [];

  return (
    <section className="panel">
      <h2>Patch Plan</h2>
      <div className="mini-grid">
        <div>
          <strong>{patches.length}</strong>
          <span>Valid patches</span>
        </div>
        <div>
          <strong>{rejected.length}</strong>
          <span>Rejected</span>
        </div>
        <div>
          <strong>{manual.length}</strong>
          <span>Manual</span>
        </div>
      </div>

      <h3>Generated Patches</h3>
      <div className="code-list">
        {patches.length === 0 && <p className="muted">No patches generated yet.</p>}
        {patches.map((patch, idx) => (
          <pre key={idx}>{JSON.stringify(patch, null, 2)}</pre>
        ))}
      </div>

      <h3>Manual Recommendations</h3>
      <div className="manual-list">
        {manual.slice(0, 6).map((item, idx) => (
          <div className="manual-item" key={idx}>
            <strong>{item.check_id}</strong>
            <p>{item.reason}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

function AgentPanel({ iterations, result }) {
  return (
    <section className="panel agent-panel">
      <h2>Agent Iterations</h2>
      <p>Stop reason: <strong>{result.stop_reason}</strong></p>

      <div className="iteration-list">
        {iterations.map((it) => (
          <div className="iteration-card" key={it.iteration}>
            <h3>Iteration {it.iteration}</h3>
            <div className="iteration-stats">
              <span>Before: {it.before_failed_checks}</span>
              <span>After: {it.after_failed_checks ?? "-"}</span>
              <span>Patches: {it.patches_generated}</span>
              <span>Status: {it.status}</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function YamlPanel({ title, yaml }) {
  return (
    <section className="panel">
      <h2>{title}</h2>
      <pre className="yaml-box">{yaml}</pre>
    </section>
  );
}

function Badge({ value }) {
  const normalized = String(value || "unknown").toLowerCase();

  let icon = null;
  if (normalized.includes("high")) icon = <XCircle size={13} />;
  if (normalized.includes("auto")) icon = <CheckCircle size={13} />;

  return (
    <span className={`badge ${normalized.replaceAll("_", "-")}`}>
      {icon}
      {value || "unknown"}
    </span>
  );
}
