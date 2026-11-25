import { useEffect, useMemo, useState } from "react";
import {
  createJob,
  getHealth,
  getQueue,
  messagesFrom,
  pauseJob,
  resumeJob,
  retryAllFailed,
  retryTarget,
  skipTarget,
} from "./api.js";

const SUBMISSION_LABELS = {
  domain: "Domain",
  ip: "IP address",
  url: "URL",
};

const THREAT_LABELS = {
  phishing: "Phishing",
  malware: "Malware",
  scam: "Scam",
  spam: "Spam",
  c2: "Command and control",
  other: "Other",
};

const PLACEHOLDERS = {
  domain: "phish.example\nlogin.evil.test",
  ip: "203.0.113.10\n2001:db8::10",
  url: "https://phish.example/login",
};

function label(map, value) {
  return map[value] || value;
}

function formatBytes(size) {
  if (size % (1024 * 1024) === 0) {
    return `${size / (1024 * 1024)} MiB`;
  }
  return `${size} bytes`;
}

function nonEmptyCount(text) {
  return text.split(/\r?\n/).filter((line) => line.trim()).length;
}

export default function App() {
  const [meta, setMeta] = useState(null);
  const [loadError, setLoadError] = useState("");
  const [submissionType, setSubmissionType] = useState("");
  const [threatType, setThreatType] = useState("");
  const [targets, setTargets] = useState("");
  const [reason, setReason] = useState("");
  const [file, setFile] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const [errors, setErrors] = useState([]);
  const [queue, setQueue] = useState(null);
  const [queueError, setQueueError] = useState("");

  async function loadHealth() {
    setLoadError("");
    try {
      const health = await getHealth();
      setMeta(health);
      setSubmissionType((current) => current || health.enums.submissionType[0]);
      setThreatType((current) => current || health.enums.threatType[0]);
    } catch (error) {
      setLoadError(messagesFrom(error)[0]);
    }
  }

  useEffect(() => {
    loadHealth();
  }, []);

  useEffect(() => {
    let ignore = false;
    async function tick() {
      try {
        const next = await getQueue();
        if (!ignore) {
          setQueue(next);
          setQueueError("");
        }
      } catch (error) {
        if (!ignore) {
          setQueueError(messagesFrom(error)[0]);
        }
      }
    }
    tick();
    const timer = setInterval(tick, 1500);
    return () => {
      ignore = true;
      clearInterval(timer);
    };
  }, []);

  const lineCount = useMemo(() => nonEmptyCount(targets), [targets]);
  const overCap = meta ? lineCount > meta.limits.maxBatchSize : false;
  const fileTooBig = meta && file ? file.size > meta.limits.maxEvidenceBytes : false;

  async function onSubmit(event) {
    event.preventDefault();
    setErrors([]);
    setSubmitting(true);
    const form = new FormData();
    form.set("submission_type", submissionType);
    form.set("targets", targets);
    form.set("threat_type", threatType);
    form.set("reason", reason);
    if (file) {
      form.set("evidence", file);
    }
    try {
      await createJob(form);
      setQueue(await getQueue());
    } catch (error) {
      setErrors(messagesFrom(error));
    } finally {
      setSubmitting(false);
    }
  }

  async function onRetry() {
    setRetrying(true);
    try {
      setQueue(await retryAllFailed());
      setQueueError("");
    } catch (error) {
      setQueueError(messagesFrom(error)[0]);
    } finally {
      setRetrying(false);
    }
  }

  async function onRefresh() {
    try {
      setQueue(await getQueue());
      setQueueError("");
    } catch (error) {
      setQueueError(messagesFrom(error)[0]);
    }
  }

  return (
    <div className="page">
      <header className="masthead">
        <p className="eyebrow">Report queue</p>
        <h1>Bulk report desk</h1>
        <p className="lede">
          Check a batch of domains, IP addresses, or URLs, then queue one report per unique target.
          {meta?.captcha_strategy === "auto"
            ? " One target is submitted at a time. The worker fills the form and solves the captcha automatically."
            : " One browser window opens at a time. The worker fills the form and waits while you solve the captcha."}
        </p>
      </header>

      {loadError ? (
        <div className="banner" role="alert">
          <p>{loadError}</p>
          <button type="button" onClick={loadHealth}>
            Try again
          </button>
        </div>
      ) : null}

      <div className="layout">
        <form className="card" onSubmit={onSubmit}>
          <h2>New batch</h2>
          {meta ? (
            <p className="hint">
              Up to {meta.limits.maxBatchSize} non-empty lines. Evidence is JPEG, PNG, or PDF, up to{" "}
              {formatBytes(meta.limits.maxEvidenceBytes)}. Blank lines are ignored and duplicates are
              folded after normalization.
            </p>
          ) : (
            <p className="hint">Loading the API contract…</p>
          )}

          {errors.length > 0 ? (
            <div className="banner" role="alert">
              <p>Nothing new was queued.</p>
              <ul>
                {errors.map((item, index) => (
                  <li key={`${item}-${index}`}>{item}</li>
                ))}
              </ul>
            </div>
          ) : null}

          <label>
            <span>Submission type</span>
            <select
              name="submission_type"
              value={submissionType}
              disabled={!meta || submitting}
              onChange={(event) => setSubmissionType(event.target.value)}
            >
              {(meta ? meta.enums.submissionType : []).map((value) => (
                <option key={value} value={value}>
                  {label(SUBMISSION_LABELS, value)}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>Targets</span>
            <textarea
              name="targets"
              value={targets}
              rows={11}
              spellCheck={false}
              required
              disabled={!meta || submitting}
              placeholder={PLACEHOLDERS[submissionType] || ""}
              onChange={(event) => setTargets(event.target.value)}
            />
          </label>
          <p className={overCap ? "hint warn" : "hint"}>
            {lineCount} non-empty {lineCount === 1 ? "line" : "lines"}
            {meta ? ` · limit ${meta.limits.maxBatchSize}` : ""}
          </p>

          <label>
            <span>Threat type</span>
            <select
              name="threat_type"
              value={threatType}
              disabled={!meta || submitting}
              onChange={(event) => setThreatType(event.target.value)}
            >
              {(meta ? meta.enums.threatType : []).map((value) => (
                <option key={value} value={value}>
                  {label(THREAT_LABELS, value)}
                </option>
              ))}
            </select>
          </label>

          <label>
            <span>Reason</span>
            <textarea
              name="reason"
              value={reason}
              rows={4}
              required
              disabled={!meta || submitting}
              placeholder="What the evidence shows, applied to every target in this batch."
              onChange={(event) => setReason(event.target.value)}
            />
          </label>

          <label>
            <span>Evidence</span>
            <input
              name="evidence"
              type="file"
              accept=".jpg,.jpeg,.png,.pdf,image/jpeg,image/png,application/pdf"
              required
              disabled={!meta || submitting}
              onChange={(event) => setFile(event.target.files && event.target.files[0] ? event.target.files[0] : null)}
            />
          </label>
          <p className={fileTooBig ? "hint warn" : "hint"}>
            {file
              ? `${file.name} · ${file.size} bytes${fileTooBig ? " · over the server limit" : ""}`
              : "JPEG, PNG, or PDF"}
          </p>

          <button type="submit" className="primary" disabled={!meta || submitting}>
            {submitting ? "Checking…" : "Queue reports"}
          </button>
        </form>

        <section className="card job" aria-live="polite">
          <div className="job-head">
            <h2>Queue</h2>
            <button type="button" className="ghost" onClick={onRefresh}>
              Refresh
            </button>
          </div>
          {queueError ? (
            <div className="banner" role="alert">
              <p>{queueError}</p>
            </div>
          ) : null}
          {queue ? (
            <QueuePanel
              queue={queue}
              retrying={retrying}
              strategy={meta?.captcha_strategy}
              onRetry={onRetry}
              onQueue={setQueue}
              onError={setQueueError}
            />
          ) : (
            <p className="empty">Loading every queued target…</p>
          )}
        </section>
      </div>
    </div>
  );
}

function QueuePanel({ queue, retrying, strategy, onRetry, onQueue, onError }) {
  const captcha = queue.targets.find((target) => target.status === "awaiting_captcha");
  const [busyId, setBusyId] = useState(null);
  const seenJobs = new Set();

  async function run(action, id) {
    onError("");
    setBusyId(id);
    try {
      await action();
      onQueue(await getQueue());
    } catch (error) {
      onError(messagesFrom(error)[0]);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <>
      <p className="hint">
        New batches stay at the top. The worker finishes the current row, then takes the pending row at the top.
        {captcha && captcha.timeout_seconds != null ? ` Captcha timeout ${formatTimeout(captcha.timeout_seconds)}.` : ""}
      </p>
      {captcha ? (
        <p className="banner captcha" role="status">
          {strategy === "auto"
            ? `Solving the captcha for ${captcha.value}`
            : `Solve the captcha in the browser window for ${captcha.value}`}
          {captcha.timeout_seconds != null ? ` · ${formatTimeout(captcha.timeout_seconds)} left` : ""}
        </p>
      ) : null}
      <dl className="counts">
        <div>
          <dt>Pending</dt>
          <dd>{queue.summary.pending}</dd>
        </div>
        <div>
          <dt>Captcha</dt>
          <dd>{queue.summary.awaiting_captcha}</dd>
        </div>
        <div>
          <dt>Retrying</dt>
          <dd>{queue.summary.retrying}</dd>
        </div>
        <div>
          <dt>Submitted</dt>
          <dd>{queue.summary.submitted}</dd>
        </div>
        <div>
          <dt>Failed</dt>
          <dd>{queue.summary.failed}</dd>
        </div>
        <div>
          <dt>Skipped</dt>
          <dd>{queue.summary.skipped}</dd>
        </div>
      </dl>
      <div className="job-actions">
        <button
          type="button"
          className="secondary"
          onClick={onRetry}
          disabled={retrying || queue.summary.failed === 0}
        >
          {retrying ? "Re-queuing…" : "Retry all failed"}
        </button>
        <button type="button" className="ghost" onClick={() => exportCsv(queue)}>
          Export CSV
        </button>
      </div>
      {queue.targets.length === 0 ? (
        <p className="empty">No targets yet. A queued batch appears at the top of this list.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>Target</th>
                <th>Status</th>
                <th>Tries</th>
                <th>Timeout</th>
                <th>Code</th>
                <th>Error</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {queue.targets.map((target) => {
                const firstInBatch = !seenJobs.has(target.job_id);
                seenJobs.add(target.job_id);
                return (
                  <tr key={target.id}>
                    <td>{target.position}</td>
                    <td>
                      <div className="mono">{target.value}</div>
                      {target.input !== target.value ? <div className="alias">{target.input}</div> : null}
                    </td>
                    <td>
                      <span className={`status status-${target.status}`}>{target.status}</span>
                      {target.paused ? <div className="alias">paused</div> : null}
                    </td>
                    <td>
                      {target.attempts}/{queue.max_attempts}
                    </td>
                    <td>{formatTimeout(target.timeout_seconds)}</td>
                    <td className="mono">{target.confirmation_code || "—"}</td>
                    <td>{target.error || "—"}</td>
                    <td>
                      <div className="row-actions">
                        {firstInBatch ? (
                          <button
                            type="button"
                            className="ghost"
                            disabled={busyId === target.job_id}
                            onClick={() =>
                              run(
                                () => (target.paused ? resumeJob(target.job_id) : pauseJob(target.job_id)),
                                target.job_id,
                              )
                            }
                          >
                            {target.paused ? "Resume" : "Pause"}
                          </button>
                        ) : null}
                        {canSkip(target.status) ? (
                          <button
                            type="button"
                            className="ghost"
                            disabled={busyId === target.id}
                            onClick={() => run(() => skipTarget(target.id), target.id)}
                          >
                            Skip
                          </button>
                        ) : null}
                        {canRetry(target.status) ? (
                          <button
                            type="button"
                            className="ghost"
                            disabled={busyId === target.id}
                            onClick={() => run(() => retryTarget(target.id), target.id)}
                          >
                            Retry
                          </button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function formatTimeout(seconds) {
  if (seconds == null) {
    return "—";
  }
  const whole = Math.max(0, seconds);
  const minutes = Math.floor(whole / 60);
  const rest = whole % 60;
  return `${minutes}:${String(rest).padStart(2, "0")}`;
}

function canSkip(status) {
  return status === "pending" || status === "running" || status === "awaiting_captcha" || status === "retrying";
}

function canRetry(status) {
  return status === "failed" || status === "skipped";
}

function exportCsv(queue) {
  const header = ["position", "target", "status", "attempts", "timeout_seconds", "confirmation_code", "error"];
  const lines = [header.join(",")];
  queue.targets.forEach((target) => {
    lines.push(
      [
        target.position,
        target.value,
        target.status,
        `${target.attempts}/${queue.max_attempts}`,
        target.timeout_seconds == null ? "" : target.timeout_seconds,
        target.confirmation_code || "",
        target.error || "",
      ]
        .map(csvCell)
        .join(","),
    );
  });
  const blob = new Blob([lines.join("\n")], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "queue.csv";
  link.click();
  URL.revokeObjectURL(url);
}

function csvCell(value) {
  const text = String(value);
  if (/[",\n]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}
