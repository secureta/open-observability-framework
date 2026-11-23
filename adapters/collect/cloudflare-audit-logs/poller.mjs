import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { pathToFileURL } from "node:url";

const DEFAULT_API_BASE_URL = "https://api.cloudflare.com/client/v4";
const DEFAULT_POLL_INTERVAL_SECS = 60;
const DEFAULT_PER_PAGE = 100;
const DEFAULT_LOOKBACK_SECS = 300;
const DEFAULT_OVERLAP_MS = 5000;
const DEFAULT_BATCH_SIZE = 500;
const MAX_RFC3339_MS = 253402300799999;
const ACCOUNT_ID_RE = /^[a-fA-F0-9]{32}$/;

function cleanNonEmptyString(val) {
  if (typeof val !== "string") return null;
  const trimmed = val.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function resolveTimestampMs(candidate, fallbackMs) {
  if (typeof candidate === "string" && candidate.trim() !== "") {
    const parsed = Date.parse(candidate.trim());
    if (!Number.isNaN(parsed)) {
      const floored = Math.floor(parsed);
      if (floored >= 1 && floored <= MAX_RFC3339_MS) return floored;
    }
  }
  return fallbackMs;
}

export function normalizeAuditLogToOcsf(entry, { nowMs = Date.now() } = {}) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    return null;
  }

  const auditId = cleanNonEmptyString(entry.id);
  const actionType = cleanNonEmptyString(entry.action?.type) || "unknown";
  const actionResult = typeof entry.action?.result === "boolean" ? entry.action.result : null;
  const actionInfo = cleanNonEmptyString(entry.action?.info);

  const actorId = cleanNonEmptyString(entry.actor?.id);
  const actorEmail = cleanNonEmptyString(entry.actor?.email);
  const actorIp = cleanNonEmptyString(entry.actor?.ip);
  const actorType = cleanNonEmptyString(entry.actor?.type);

  const ownerId = cleanNonEmptyString(entry.owner?.id);
  const resourceId = cleanNonEmptyString(entry.resource?.id);
  const resourceType = cleanNonEmptyString(entry.resource?.type);
  const iface = cleanNonEmptyString(entry.interface);
  const rawTsStr = cleanNonEmptyString(entry.when);

  const safeNowMs = resolveTimestampMs(null, Math.floor(nowMs));
  const timeMs = resolveTimestampMs(rawTsStr, safeNowMs);
  const timeDt = new Date(timeMs).toISOString();

  const actionLc = actionType.toLowerCase();
  const resLc = (resourceType || "").toLowerCase();

  let severityId = 1;
  let severity = "Informational";
  let logLevel = "info";

  if (actionResult === false) {
    severityId = 4;
    severity = "High";
    logLevel = "error";
  } else if (
    actionLc.includes("delete") ||
    actionLc.includes("revoke") ||
    actionLc.includes("remove") ||
    actionLc.includes("purge") ||
    resLc.includes("token") ||
    resLc.includes("member") ||
    resLc.includes("role") ||
    resLc.includes("firewall") ||
    resLc.includes("waf") ||
    resLc.includes("access") ||
    resLc.includes("zero_trust")
  ) {
    severityId = 3;
    severity = "Medium";
    logLevel = "warn";
  }

  const user = {};
  if (actorId !== null) user.uid = actorId;
  if (actorEmail !== null) user.name = actorEmail;
  else if (actorType !== null) user.name = actorType;

  const actor = {};
  if (Object.keys(user).length > 0) actor.user = user;

  const device = {
    type_id: 99,
    type: "Other",
    hostname: "cloudflare.com",
  };
  if (ownerId !== null) device.uid = ownerId;

  const logProvider = "cloudflare-audit-logs";
  const logName = resourceType ? `${resourceType}:${actionType}` : actionType;
  const resLabel = resourceType || "account";
  const actorLabel = actorEmail || actorId || "unknown-actor";
  const outcomeLabel = actionResult === false ? "failed" : "succeeded";
  const message = `cloudflare audit ${actionType} on ${resLabel} by ${actorLabel} (${outcomeLabel})`;

  const metadata = {
    version: "1.3.0",
    product: {
      name: "oof-cloudflare-audit-logs",
      vendor_name: "Open Observability Framework",
    },
    logged_time: safeNowMs,
    log_provider: logProvider,
    log_name: logName,
    log_level: logLevel,
  };
  if (auditId !== null) metadata.original_event_uid = auditId;
  if (rawTsStr !== null) metadata.original_time = rawTsStr;

  const unmapped = {
    cloudflare_dataset: "audit_logs",
    action_type: actionType,
  };
  if (auditId !== null) unmapped.audit_log_id = auditId;
  if (actionResult !== null) unmapped.action_result = actionResult;
  if (actionInfo !== null) unmapped.action_info = actionInfo;
  if (actorType !== null) unmapped.actor_type = actorType;
  if (actorIp !== null) unmapped.actor_ip = actorIp;
  if (ownerId !== null) unmapped.owner_id = ownerId;
  if (resourceType !== null) unmapped.resource_type = resourceType;
  if (resourceId !== null) unmapped.resource_id = resourceId;
  if (iface !== null) unmapped.interface = iface;

  const out = {
    category_uid: 1,
    category_name: "System Activity",
    class_uid: 1008,
    class_name: "Event Log Activity",
    type_uid: 100899,
    type_name: "Event Log Activity: Other",
    activity_id: 99,
    activity_name: "Other",
    severity_id: severityId,
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
  if (Object.keys(actor).length > 0) out.actor = actor;

  return out;
}

export function loadCheckpoint(checkpointPath) {
  if (!checkpointPath || !fs.existsSync(checkpointPath)) {
    return { lastBefore: null, initialSince: null, recentEntries: [] };
  }
  const raw = JSON.parse(fs.readFileSync(checkpointPath, "utf8"));
  const recentEntries = [];
  if (Array.isArray(raw.recentEntries)) {
    for (const item of raw.recentEntries) {
      if (item && typeof item.id === "string" && typeof item.timeMs === "number" && Number.isFinite(item.timeMs)) {
        recentEntries.push({ id: item.id, timeMs: item.timeMs });
      }
    }
  } else if (Array.isArray(raw.recentIds)) {
    // Backward compatibility with legacy id-only checkpoints
    const fallbackMs = typeof raw.lastBefore === "string" ? Date.parse(raw.lastBefore) || 0 : 0;
    for (const id of raw.recentIds) {
      if (typeof id === "string") recentEntries.push({ id, timeMs: fallbackMs });
    }
  }
  return {
    lastBefore: typeof raw.lastBefore === "string" ? raw.lastBefore : null,
    initialSince: typeof raw.initialSince === "string" ? raw.initialSince : null,
    recentEntries,
  };
}

export function saveCheckpoint(checkpointPath, state) {
  if (!checkpointPath) return;
  fs.mkdirSync(path.dirname(checkpointPath), { recursive: true });
  const tmpPath = `${checkpointPath}.tmp.${process.pid}.${Date.now()}`;
  const entries = Array.isArray(state.recentEntries) ? state.recentEntries : [];
  fs.writeFileSync(
    tmpPath,
    JSON.stringify(
      {
        lastBefore: state.lastBefore ?? null,
        initialSince: state.initialSince ?? null,
        recentEntries: entries,
      },
      null,
      2
    ) + "\n",
    { mode: 0o600 }
  );
  fs.renameSync(tmpPath, checkpointPath);
}

async function fetchJsonWithTimeout(url, init, timeoutMs, fetchImpl) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { ...init, signal: controller.signal });
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    return { ok: res.ok, status: res.status, json, text };
  } finally {
    clearTimeout(timer);
  }
}

export async function shipOcsfBatchToBasin(events, { basinEndpoint, ingestToken, timeoutMs = 15000, fetchImpl = fetch } = {}) {
  if (!events.length) return 0;
  let shipped = 0;
  for (let i = 0; i < events.length; i += DEFAULT_BATCH_SIZE) {
    const chunk = events.slice(i, i + DEFAULT_BATCH_SIZE);
    const gz = zlib.gzipSync(Buffer.from(JSON.stringify(chunk), "utf8"));
    const res = await fetchJsonWithTimeout(
      basinEndpoint,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-encoding": "gzip",
          authorization: `Bearer ${ingestToken}`,
        },
        body: gz,
      },
      timeoutMs,
      fetchImpl
    );
    if (!res.ok) {
      throw new Error(`Basin HTTP ingest failed with status ${res.status}: ${res.text.slice(0, 200)}`);
    }
    shipped += chunk.length;
  }
  return shipped;
}

export async function pollOnce(options) {
  const {
    accountId,
    apiToken,
    basinEndpoint,
    ingestToken,
    checkpointPath,
    apiBaseUrl = DEFAULT_API_BASE_URL,
    perPage = DEFAULT_PER_PAGE,
    initialLookbackSecs = DEFAULT_LOOKBACK_SECS,
    overlapMs = DEFAULT_OVERLAP_MS,
    timeoutMs = 15000,
    nowMs = Date.now(),
    fetchImpl = fetch,
  } = options;

  if (!ACCOUNT_ID_RE.test(accountId || "")) {
    throw new Error("OOF_CLOUDFLARE_ACCOUNT_ID must be a 32-character hexadecimal Cloudflare Account ID.");
  }
  if (!apiToken || !basinEndpoint || !ingestToken) {
    throw new Error("OOF_CLOUDFLARE_API_TOKEN, OOF_BASIN_ENDPOINT, and OOF_INGEST_TOKEN are required.");
  }

  const checkpoint = loadCheckpoint(checkpointPath);
  const beforeIso = new Date(nowMs).toISOString();
  const safeOverlapMs = Math.max(1000, Math.floor(overlapMs));

  let sinceIso;
  if (checkpoint.lastBefore) {
    const prevMs = Date.parse(checkpoint.lastBefore);
    const overlappedMs = Number.isNaN(prevMs)
      ? nowMs - initialLookbackSecs * 1000
      : Math.max(1, prevMs - safeOverlapMs);
    sinceIso = new Date(overlappedMs).toISOString();
  } else if (checkpoint.initialSince) {
    sinceIso = checkpoint.initialSince;
  } else {
    sinceIso = new Date(nowMs - initialLookbackSecs * 1000).toISOString();
    // Persist the initial lower bound before the first upload attempt so startup
    // retries (even across restarts) never lose records from the oldest lookback minute.
    saveCheckpoint(checkpointPath, {
      lastBefore: null,
      initialSince: sinceIso,
      recentEntries: checkpoint.recentEntries,
    });
  }

  const seenMap = new Map();
  for (const item of checkpoint.recentEntries) {
    seenMap.set(item.id, item.timeMs);
  }

  const base = apiBaseUrl.replace(/\/+$/, "");
  const collected = [];
  let page = 1;
  let totalPages = null;

  while (true) {
    const url = new URL(`${base}/accounts/${accountId}/audit_logs`);
    url.searchParams.set("since", sinceIso);
    url.searchParams.set("before", beforeIso);
    url.searchParams.set("per_page", String(perPage));
    url.searchParams.set("page", String(page));
    url.searchParams.set("direction", "asc");

    const res = await fetchJsonWithTimeout(
      url.toString(),
      {
        method: "GET",
        headers: {
          authorization: `Bearer ${apiToken}`,
          accept: "application/json",
        },
      },
      timeoutMs,
      fetchImpl
    );

    if (!res.ok || !res.json || res.json.success === false || !Array.isArray(res.json.result)) {
      throw new Error(`Cloudflare Audit Logs API failed (HTTP ${res.status}, page=${page})`);
    }

    const pageRows = res.json.result;
    for (const row of pageRows) {
      const id = cleanNonEmptyString(row?.id);
      if (id && seenMap.has(id)) {
        continue;
      }
      const ocsf = normalizeAuditLogToOcsf(row, { nowMs });
      if (ocsf) {
        collected.push(ocsf);
        if (id) {
          seenMap.set(id, ocsf.time);
        }
      }
    }

    const infoTotalPages = Number(res.json.result_info?.total_pages);
    if (Number.isInteger(infoTotalPages) && infoTotalPages >= 0) {
      totalPages = infoTotalPages;
    }

    if (pageRows.length === 0) break;
    if (totalPages !== null) {
      if (page >= totalPages) break;
    } else if (pageRows.length < perPage) {
      break;
    }
    page += 1;
  }

  const shipped = await shipOcsfBatchToBasin(collected, {
    basinEndpoint,
    ingestToken,
    timeoutMs,
    fetchImpl,
  });

  // Retain every shipped ID whose event timestamp falls inside the next overlap window
  // (no fixed count cap), and expire IDs strictly older than the next overlap lower bound.
  const nextOverlapFloorMs = Math.max(1, nowMs - safeOverlapMs);
  const retainedEntries = [];
  for (const [id, timeMs] of seenMap.entries()) {
    if (timeMs >= nextOverlapFloorMs) {
      retainedEntries.push({ id, timeMs });
    }
  }

  // Advance checkpoint ONLY after all pages have been fetched and shipped to Basin.
  saveCheckpoint(checkpointPath, {
    lastBefore: beforeIso,
    initialSince: null,
    recentEntries: retainedEntries,
  });

  return { since: sinceIso, before: beforeIso, pagesFetched: page, shipped };
}

async function main() {
  const accountId = process.env.OOF_CLOUDFLARE_ACCOUNT_ID || "";
  const apiToken = process.env.OOF_CLOUDFLARE_API_TOKEN || "";
  const basinEndpoint = process.env.OOF_BASIN_ENDPOINT || "";
  const ingestToken = process.env.OOF_INGEST_TOKEN || "";
  const apiBaseUrl = process.env.OOF_CLOUDFLARE_API_BASE_URL || DEFAULT_API_BASE_URL;
  const perPage = Math.max(1, Math.min(1000, Number(process.env.OOF_CLOUDFLARE_AUDIT_PER_PAGE || DEFAULT_PER_PAGE)));
  const pollIntervalSecs = Math.max(5, Number(process.env.OOF_CLOUDFLARE_AUDIT_POLL_INTERVAL_SECS || DEFAULT_POLL_INTERVAL_SECS));
  const initialLookbackSecs = Math.max(60, Number(process.env.OOF_CLOUDFLARE_AUDIT_LOOKBACK_SECS || DEFAULT_LOOKBACK_SECS));
  const checkpointPath =
    process.env.OOF_CF_AUDIT_CHECKPOINT_FILE ||
    path.join(process.env.STATE_DIRECTORY || "/var/lib/oof-cloudflare-audit-logs", "checkpoint.json");

  let stopped = false;
  let timer = null;

  const shutdown = () => {
    stopped = true;
    if (timer) clearTimeout(timer);
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);

  const runLoop = async () => {
    while (!stopped) {
      try {
        const res = await pollOnce({
          accountId,
          apiToken,
          basinEndpoint,
          ingestToken,
          checkpointPath,
          apiBaseUrl,
          perPage,
          initialLookbackSecs,
        });
        process.stdout.write(
          `oof-cloudflare-audit-logs polled window=[${res.since}, ${res.before}] pages=${res.pagesFetched} shipped=${res.shipped}\n`
        );
      } catch (err) {
        process.stderr.write(`oof-cloudflare-audit-logs poll error (checkpoint preserved): ${err.message}\n`);
      }
      if (stopped) break;
      await new Promise((resolve) => {
        timer = setTimeout(resolve, pollIntervalSecs * 1000);
      });
    }
  };

  await runLoop();
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`oof-cloudflare-audit-logs fatal: ${err.message}\n`);
    process.exit(1);
  });
}
