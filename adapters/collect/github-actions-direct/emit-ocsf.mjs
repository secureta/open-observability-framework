import zlib from "node:zlib";
import { pathToFileURL } from "node:url";

const MAX_RFC3339_MS = 253402300799999;

export function mapConclusionToSeverity(conclusion, status) {
  const c = typeof conclusion === "string" ? conclusion.trim().toLowerCase() : "";
  if (c === "failure" || c === "startup_failure" || c === "error") {
    return { severity_id: 4, severity: "High" };
  }
  if (c === "timed_out" || c === "action_required" || c === "stale") {
    return { severity_id: 3, severity: "Medium" };
  }
  if (c === "cancelled" || c === "skipped" || c === "neutral") {
    return { severity_id: 2, severity: "Low" };
  }
  if (c === "success") {
    return { severity_id: 1, severity: "Informational" };
  }
  const s = typeof status === "string" ? status.trim().toLowerCase() : "";
  if (s === "queued" || s === "in_progress" || s === "requested" || s === "waiting" || s === "completed") {
    return { severity_id: 1, severity: "Informational" };
  }
  return { severity_id: 0, severity: "Unknown" };
}

export function mapRunnerOs(runnerOs) {
  if (typeof runnerOs !== "string") return null;
  const lc = runnerOs.trim().toLowerCase();
  if (lc === "linux" || lc.includes("ubuntu")) return { name: "Linux", type_id: 200 };
  if (lc === "windows") return { name: "Windows", type_id: 100 };
  if (lc === "macos" || lc === "darwin") return { name: "macOS", type_id: 300 };
  return null;
}

function cleanNonEmptyString(val) {
  if (typeof val !== "string") return null;
  const trimmed = val.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function parseNonNegativeInt(val) {
  if (typeof val === "number") {
    return Number.isInteger(val) && val >= 0 && val <= Number.MAX_SAFE_INTEGER ? val : null;
  }
  if (typeof val === "string" && /^[0-9]{1,15}$/.test(val.trim())) {
    const n = Number(val.trim());
    return Number.isSafeInteger(n) ? n : null;
  }
  return null;
}

function resolveTimestampMs(candidate, fallbackMs) {
  if (typeof candidate === "number" && Number.isFinite(candidate)) {
    const floored = Math.floor(candidate);
    if (floored >= 1 && floored <= MAX_RFC3339_MS) return floored;
  }
  if (typeof candidate === "string" && candidate.trim() !== "") {
    const parsed = Date.parse(candidate.trim());
    if (!Number.isNaN(parsed)) {
      const floored = Math.floor(parsed);
      if (floored >= 1 && floored <= MAX_RFC3339_MS) return floored;
    }
  }
  return fallbackMs;
}

function formatRfc3339Ms(ms) {
  return new Date(ms).toISOString();
}

function cleanCorrelationId(val) {
  const s = cleanNonEmptyString(val);
  if (!s || /^0+$/.test(s)) return null;
  return /^[0-9A-Fa-f]+$/.test(s) ? s.toLowerCase() : s;
}

export function buildOcsfEvent(input = {}) {
  const nowMs = resolveTimestampMs(input.nowMs, Date.now());
  const timeMs = resolveTimestampMs(input.timestamp, nowMs);
  const timeDt = formatRfc3339Ms(timeMs);

  const repository = cleanNonEmptyString(input.repository);
  const workflow = cleanNonEmptyString(input.workflow);
  const job = cleanNonEmptyString(input.job);
  const githubEvent = cleanNonEmptyString(input.eventName) || "workflow_job";
  const status = cleanNonEmptyString(input.status) || "completed";
  const conclusion = cleanNonEmptyString(input.conclusion);
  const actorName = cleanNonEmptyString(input.actor);
  const actorIdNum = parseNonNegativeInt(input.actorId);
  const runIdNum = parseNonNegativeInt(input.runId);
  const runNumberNum = parseNonNegativeInt(input.runNumber);
  const runAttemptNum = parseNonNegativeInt(input.runAttempt);
  const ref = cleanNonEmptyString(input.ref);
  const sha = cleanNonEmptyString(input.sha);
  const runnerName = cleanNonEmptyString(input.runnerName);
  const runnerOs = mapRunnerOs(input.runnerOs);
  const isSelfHosted =
    typeof input.isSelfHosted === "boolean"
      ? input.isSelfHosted
      : runnerName !== null && !/^GitHub Actions\b/i.test(runnerName) && !/^Hosted Agent$/i.test(runnerName)
        ? null
        : false;
  const durationMs = parseNonNegativeInt(input.durationMs);
  const serverUrl = cleanNonEmptyString(input.serverUrl) || "https://github.com";
  const htmlUrl =
    cleanNonEmptyString(input.htmlUrl) ||
    (repository && runIdNum !== null ? `${serverUrl.replace(/\/+$/, "")}/${repository}/actions/runs/${runIdNum}` : null);

  const { severity_id, severity } = mapConclusionToSeverity(conclusion, status);

  const logProvider = "github-actions";
  const logName =
    repository && workflow ? `${repository}:${workflow}` : repository || workflow || githubEvent;

  const traceId = cleanCorrelationId(input.traceId);
  const correlationUid = traceId || (runIdNum !== null && runIdNum > 0 ? String(runIdNum) : null);
  const originalEventUid =
    cleanNonEmptyString(input.originalEventUid) ||
    (runIdNum !== null
      ? [String(runIdNum), runAttemptNum !== null ? String(runAttemptNum) : "1", job || "run"].join(":")
      : null);

  const stateStr = conclusion || status;
  const subjectStr = job || workflow || githubEvent;
  const repoStr = repository || "unknown-repo";
  const message =
    cleanNonEmptyString(input.message) || `${githubEvent} ${stateStr}: ${subjectStr} on ${repoStr}`;

  const metadata = {
    version: "1.3.0",
    product: {
      name: "GitHub Actions",
      vendor_name: "GitHub",
    },
    logged_time: nowMs,
    log_provider: logProvider,
    log_name: logName,
  };
  if (originalEventUid !== null) metadata.original_event_uid = originalEventUid;
  if (correlationUid !== null) metadata.correlation_uid = correlationUid;
  if (stateStr) metadata.log_level = stateStr;

  const device = {
    type_id: isSelfHosted === true ? 1 : isSelfHosted === false || runnerName !== null ? 6 : 0,
    type: isSelfHosted === true ? "Server" : isSelfHosted === false || runnerName !== null ? "Virtual" : "Unknown",
  };
  if (runnerName !== null) {
    device.hostname = runnerName;
  } else if (repository !== null) {
    device.hostname = repository;
  }
  if (runnerOs !== null) device.os = runnerOs;

  const actor = {};
  const proc = {};
  if (job || workflow) proc.name = job || workflow;
  if (cleanNonEmptyString(input.workflowRef)) proc.path = cleanNonEmptyString(input.workflowRef);
  if (Object.keys(proc).length > 0) actor.process = proc;

  const usr = {};
  if (actorName !== null) usr.name = actorName;
  if (actorIdNum !== null) {
    usr.uid = String(actorIdNum);
    usr.uid_numeric = actorIdNum;
  }
  if (Object.keys(usr).length > 0) actor.user = usr;

  const unmapped = {
    github_event: githubEvent,
  };
  if (repository !== null) unmapped.repository = repository;
  if (workflow !== null) unmapped.workflow = workflow;
  if (job !== null) unmapped.job = job;
  if (runIdNum !== null) unmapped.run_id = runIdNum;
  if (runNumberNum !== null) unmapped.run_number = runNumberNum;
  if (runAttemptNum !== null) unmapped.run_attempt = runAttemptNum;
  if (status !== null) unmapped.status = status;
  if (conclusion !== null) unmapped.conclusion = conclusion;
  if (ref !== null) unmapped.ref = ref;
  if (sha !== null) unmapped.head_sha = sha;
  if (runnerName !== null) unmapped.runner_name = runnerName;
  if (typeof isSelfHosted === "boolean") unmapped.is_self_hosted = isSelfHosted;
  if (durationMs !== null) unmapped.duration_ms = durationMs;
  if (htmlUrl !== null) unmapped.html_url = htmlUrl;
  if (typeof input.extraUnmapped === "object" && input.extraUnmapped !== null && !Array.isArray(input.extraUnmapped)) {
    for (const [k, v] of Object.entries(input.extraUnmapped)) {
      if (v !== undefined && v !== null && !Object.hasOwn(unmapped, k)) {
        unmapped[k] = v;
      }
    }
  }

  const record = {
    category_uid: 1,
    category_name: "System Activity",
    class_uid: 1008,
    class_name: "Event Log Activity",
    type_uid: 100899,
    type_name: "Event Log Activity: Other",
    activity_id: 99,
    activity_name: "Other",
    severity_id,
    severity,
    time: timeMs,
    time_dt: timeDt,
    message,
    log_name: logName,
    log_provider: logProvider,
    metadata,
    device,
    unmapped,
  };
  if (Object.keys(actor).length > 0) record.actor = actor;

  return record;
}

export async function sendToBasin(events, { endpoint, token, fetchImpl = fetch } = {}) {
  const cleanEndpoint = cleanNonEmptyString(endpoint);
  const cleanToken = cleanNonEmptyString(token);
  if (!cleanEndpoint) {
    throw new Error("Missing OOF_BASIN_ENDPOINT / basin_endpoint");
  }
  if (!cleanToken) {
    throw new Error("Missing OOF_INGEST_TOKEN / ingest_token");
  }
  const batch = Array.isArray(events) ? events : [events];
  const gzipped = zlib.gzipSync(Buffer.from(JSON.stringify(batch), "utf8"));

  const response = await fetchImpl(cleanEndpoint, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${cleanToken}`,
      "Content-Type": "application/json",
      "Content-Encoding": "gzip",
    },
    body: gzipped,
  });

  if (!response.ok) {
    const bodyText = await response.text().catch(() => "");
    throw new Error(`Basin HTTP ingest failed (${response.status}): ${bodyText.slice(0, 200)}`);
  }
  return { status: response.status, count: batch.length };
}

function readInput(env, name, fallbackEnv) {
  const inputKey = `INPUT_${name.toUpperCase()}`;
  const v = cleanNonEmptyString(env[inputKey]);
  if (v !== null) return v;
  return fallbackEnv ? cleanNonEmptyString(env[fallbackEnv]) : null;
}

export function buildInputFromEnv(env = process.env) {
  const isSelfHostedRaw = readInput(env, "is_self_hosted");
  let isSelfHosted;
  if (isSelfHostedRaw === "true") isSelfHosted = true;
  else if (isSelfHostedRaw === "false") isSelfHosted = false;

  const extraJsonRaw = readInput(env, "extra_json");
  let extraUnmapped;
  if (extraJsonRaw) {
    const parsed = JSON.parse(extraJsonRaw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("extra_json input must be a JSON object");
    }
    extraUnmapped = parsed;
  }

  return {
    endpoint: readInput(env, "basin_endpoint", "OOF_BASIN_ENDPOINT"),
    token: readInput(env, "ingest_token", "OOF_INGEST_TOKEN"),
    event: buildOcsfEvent({
      repository: readInput(env, "repository", "GITHUB_REPOSITORY"),
      workflow: readInput(env, "workflow", "GITHUB_WORKFLOW"),
      workflowRef: readInput(env, "workflow_ref", "GITHUB_WORKFLOW_REF"),
      job: readInput(env, "job", "GITHUB_JOB"),
      eventName: readInput(env, "event_name", "GITHUB_EVENT_NAME"),
      status: readInput(env, "status") || "completed",
      conclusion: readInput(env, "conclusion"),
      actor: readInput(env, "actor", "GITHUB_ACTOR"),
      actorId: readInput(env, "actor_id", "GITHUB_ACTOR_ID"),
      runId: readInput(env, "run_id", "GITHUB_RUN_ID"),
      runNumber: readInput(env, "run_number", "GITHUB_RUN_NUMBER"),
      runAttempt: readInput(env, "run_attempt", "GITHUB_RUN_ATTEMPT"),
      ref: readInput(env, "ref", "GITHUB_REF"),
      sha: readInput(env, "sha", "GITHUB_SHA"),
      runnerName: readInput(env, "runner_name", "RUNNER_NAME"),
      runnerOs: readInput(env, "runner_os", "RUNNER_OS"),
      isSelfHosted,
      durationMs: readInput(env, "duration_ms"),
      traceId: readInput(env, "trace_id", "OTEL_TRACE_ID"),
      message: readInput(env, "message"),
      serverUrl: readInput(env, "server_url", "GITHUB_SERVER_URL"),
      extraUnmapped,
    }),
  };
}

async function main() {
  const { endpoint, token, event } = buildInputFromEnv(process.env);
  const result = await sendToBasin([event], { endpoint, token });
  process.stdout.write(
    `Sent ${result.count} OCSF v1.3.0 event(s) to Basin (HTTP ${result.status}, log_name=${event.log_name}, severity=${event.severity})\n`
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`oof-github-actions-direct error: ${err.message}\n`);
    process.exitCode = 1;
  });
}
