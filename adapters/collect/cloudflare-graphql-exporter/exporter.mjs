import http from "node:http";
import { pathToFileURL } from "node:url";

const DEFAULT_GRAPHQL_ENDPOINT = "https://api.cloudflare.com/client/v4/graphql";
const DEFAULT_LISTEN = "127.0.0.1:9199";
const ZONE_ID_RE = /^[a-fA-F0-9]{32}$/;
const ZONE_ALIAS_RE = /^[a-zA-Z0-9._-]+$/;

const ZONE_ANALYTICS_QUERY = `
query OofZoneAnalytics($zoneTags: [string!], $since: Time!, $until: Time!) {
  viewer {
    zones(filter: { zoneTag_in: $zoneTags }) {
      zoneTag
      httpRequests1mGroups(
        limit: 100
        filter: { datetime_geq: $since, datetime_lt: $until }
      ) {
        sum {
          requests
          cachedRequests
          encryptedRequests
          threats
          bytes
          cachedBytes
          responseStatusMap {
            edgeResponseStatus
            requests
          }
        }
      }
    }
  }
}
`.trim();

export function escapePromLabelValue(val) {
  return String(val)
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .replace(/\n/g, "\\n");
}

export function parseZoneSpecs(raw) {
  if (typeof raw !== "string" || raw.trim() === "") {
    throw new Error("OOF_CLOUDFLARE_ZONE_IDS must contain at least one 32-hex Cloudflare Zone ID (or alias=zoneId).");
  }
  const entries = [];
  const seenIds = new Set();
  for (const token of raw.split(",").map((s) => s.trim()).filter(Boolean)) {
    let alias;
    let zoneId;
    if (token.includes("=")) {
      const idx = token.indexOf("=");
      alias = token.slice(0, idx).trim();
      zoneId = token.slice(idx + 1).trim();
      if (!ZONE_ALIAS_RE.test(alias)) {
        throw new Error(`Invalid zone alias '${alias}'; must match ${ZONE_ALIAS_RE}`);
      }
    } else {
      zoneId = token;
      alias = token;
    }
    if (!ZONE_ID_RE.test(zoneId)) {
      throw new Error(`Invalid Cloudflare Zone ID '${zoneId}'; must be 32 hexadecimal characters.`);
    }
    const lcId = zoneId.toLowerCase();
    if (!seenIds.has(lcId)) {
      seenIds.add(lcId);
      entries.push({ alias, zoneId: lcId });
    }
  }
  if (entries.length === 0) {
    throw new Error("OOF_CLOUDFLARE_ZONE_IDS produced zero valid zone entries.");
  }
  return entries;
}

export function parseListenAddress(listenStr = DEFAULT_LISTEN) {
  const trimmed = String(listenStr).trim();
  const ipv6Match = trimmed.match(/^\[([0-9a-fA-F:]+)\]:([0-9]+)$/);
  if (ipv6Match) {
    const port = Number(ipv6Match[2]);
    if (!Number.isInteger(port) || port < 0 || port > 65535) {
      throw new Error(`Invalid port in listen address: ${listenStr}`);
    }
    return { host: ipv6Match[1], port };
  }
  const lastColon = trimmed.lastIndexOf(":");
  if (lastColon <= 0) {
    throw new Error(`Listen address must be host:port, got: ${listenStr}`);
  }
  const host = trimmed.slice(0, lastColon);
  const port = Number(trimmed.slice(lastColon + 1));
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`Invalid port in listen address: ${listenStr}`);
  }
  return { host, port };
}

export function buildGraphqlPayload(zoneEntries, { nowMs = Date.now(), windowMinutes = 5 } = {}) {
  const safeWindow = Math.max(1, Math.min(60, Math.floor(windowMinutes)));
  const untilMs = Math.floor(nowMs / 60000) * 60000;
  const sinceMs = untilMs - safeWindow * 60000;
  return {
    query: ZONE_ANALYTICS_QUERY,
    variables: {
      zoneTags: zoneEntries.map((z) => z.zoneId),
      since: new Date(sinceMs).toISOString(),
      until: new Date(untilMs).toISOString(),
    },
  };
}

function toSafeNumber(val) {
  const n = Number(val);
  return Number.isFinite(n) && n >= 0 ? n : 0;
}

export function aggregateZoneAnalytics(graphqlBody, zoneEntries) {
  if (!graphqlBody || typeof graphqlBody !== "object") {
    throw new Error("Cloudflare GraphQL response is not a JSON object.");
  }
  if (Array.isArray(graphqlBody.errors) && graphqlBody.errors.length > 0) {
    const firstMsg = graphqlBody.errors[0]?.message || "unknown GraphQL error";
    throw new Error(`Cloudflare GraphQL returned errors: ${firstMsg}`);
  }
  const zones = graphqlBody?.data?.viewer?.zones;
  if (!Array.isArray(zones)) {
    throw new Error("Cloudflare GraphQL response missing data.viewer.zones array.");
  }

  const aliasById = new Map(zoneEntries.map((z) => [z.zoneId.toLowerCase(), z.alias]));
  const aggregated = new Map();

  for (const entry of zoneEntries) {
    aggregated.set(entry.zoneId.toLowerCase(), {
      zone: entry.alias,
      requests: 0,
      cachedRequests: 0,
      encryptedRequests: 0,
      threats: 0,
      bytes: 0,
      cachedBytes: 0,
      status2xx: 0,
      status3xx: 0,
      status4xx: 0,
      status5xx: 0,
    });
  }

  for (const z of zones) {
    if (!z || typeof z.zoneTag !== "string") continue;
    const key = z.zoneTag.toLowerCase();
    const acc = aggregated.get(key) || {
      zone: aliasById.get(key) || key,
      requests: 0,
      cachedRequests: 0,
      encryptedRequests: 0,
      threats: 0,
      bytes: 0,
      cachedBytes: 0,
      status2xx: 0,
      status3xx: 0,
      status4xx: 0,
      status5xx: 0,
    };
    const groups = Array.isArray(z.httpRequests1mGroups) ? z.httpRequests1mGroups : [];
    for (const grp of groups) {
      const s = grp?.sum;
      if (!s || typeof s !== "object") continue;
      acc.requests += toSafeNumber(s.requests);
      acc.cachedRequests += toSafeNumber(s.cachedRequests);
      acc.encryptedRequests += toSafeNumber(s.encryptedRequests);
      acc.threats += toSafeNumber(s.threats);
      acc.bytes += toSafeNumber(s.bytes);
      acc.cachedBytes += toSafeNumber(s.cachedBytes);

      if (Array.isArray(s.responseStatusMap)) {
        for (const row of s.responseStatusMap) {
          const code = Number(row?.edgeResponseStatus);
          const count = toSafeNumber(row?.requests);
          if (code >= 200 && code < 300) acc.status2xx += count;
          else if (code >= 300 && code < 400) acc.status3xx += count;
          else if (code >= 400 && code < 500) acc.status4xx += count;
          else if (code >= 500 && code < 600) acc.status5xx += count;
        }
      }
    }
    aggregated.set(key, acc);
  }

  return Array.from(aggregated.values());
}

export function renderPrometheusMetrics(zoneMetrics, { scrapeSuccess = 1, durationSeconds = 0 } = {}) {
  const lines = [];
  const emitGauge = (name, help, extractor) => {
    lines.push(`# HELP ${name} ${help}`);
    lines.push(`# TYPE ${name} gauge`);
    for (const zm of zoneMetrics) {
      lines.push(`${name}{zone="${escapePromLabelValue(zm.zone)}"} ${extractor(zm)}`);
    }
  };

  if (scrapeSuccess === 1) {
    emitGauge(
      "cloudflare_zone_requests_total",
      "Total HTTP requests observed in the Cloudflare GraphQL Analytics window",
      (z) => z.requests
    );
    emitGauge(
      "cloudflare_zone_requests_cached",
      "Cached HTTP requests observed in the Cloudflare GraphQL Analytics window",
      (z) => z.cachedRequests
    );
    emitGauge(
      "cloudflare_zone_requests_encrypted",
      "Encrypted (HTTPS) requests observed in the Cloudflare GraphQL Analytics window",
      (z) => z.encryptedRequests
    );
    emitGauge(
      "cloudflare_zone_threats_total",
      "Total threats mitigated in the Cloudflare GraphQL Analytics window",
      (z) => z.threats
    );
    emitGauge(
      "cloudflare_zone_bandwidth_bytes",
      "Total bandwidth in bytes observed in the Cloudflare GraphQL Analytics window",
      (z) => z.bytes
    );
    emitGauge(
      "cloudflare_zone_bandwidth_cached_bytes",
      "Cached bandwidth in bytes observed in the Cloudflare GraphQL Analytics window",
      (z) => z.cachedBytes
    );
    emitGauge(
      "cloudflare_zone_requests_status_2xx",
      "HTTP 2xx edge responses in the Cloudflare GraphQL Analytics window",
      (z) => z.status2xx
    );
    emitGauge(
      "cloudflare_zone_requests_status_3xx",
      "HTTP 3xx edge responses in the Cloudflare GraphQL Analytics window",
      (z) => z.status3xx
    );
    emitGauge(
      "cloudflare_zone_requests_status_4xx",
      "HTTP 4xx edge responses in the Cloudflare GraphQL Analytics window",
      (z) => z.status4xx
    );
    emitGauge(
      "cloudflare_zone_requests_status_5xx",
      "HTTP 5xx edge responses in the Cloudflare GraphQL Analytics window",
      (z) => z.status5xx
    );
  }

  lines.push("# HELP cloudflare_graphql_scrape_success Whether the last Cloudflare GraphQL Analytics scrape succeeded (1=yes, 0=no)");
  lines.push("# TYPE cloudflare_graphql_scrape_success gauge");
  lines.push(`cloudflare_graphql_scrape_success ${scrapeSuccess ? 1 : 0}`);

  lines.push("# HELP cloudflare_graphql_scrape_duration_seconds Duration of the last Cloudflare GraphQL Analytics API request in seconds");
  lines.push("# TYPE cloudflare_graphql_scrape_duration_seconds gauge");
  lines.push(`cloudflare_graphql_scrape_duration_seconds ${Number(durationSeconds).toFixed(6)}`);

  return `${lines.join("\n")}\n`;
}

export function createExporterServer(options) {
  const {
    apiToken,
    zoneEntries,
    graphqlEndpoint = DEFAULT_GRAPHQL_ENDPOINT,
    windowMinutes = 5,
    cacheTtlSecs = 60,
    timeoutMs = 10000,
    fetchImpl = fetch,
  } = options;

  if (typeof apiToken !== "string" || apiToken.trim() === "") {
    throw new Error("OOF_CLOUDFLARE_API_TOKEN must be non-empty.");
  }

  let cachedBody = null;
  let cachedAtMs = 0;

  async function scrapeMetrics() {
    const nowMs = Date.now();
    if (cacheTtlSecs > 0 && cachedBody !== null && nowMs - cachedAtMs < cacheTtlSecs * 1000) {
      return cachedBody;
    }

    const startNs = process.hrtime.bigint();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const payload = buildGraphqlPayload(zoneEntries, { nowMs, windowMinutes });
      const res = await fetchImpl(graphqlEndpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          authorization: `Bearer ${apiToken}`,
        },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      const elapsedSec = Number(process.hrtime.bigint() - startNs) / 1e9;
      if (!res.ok) {
        const body = renderPrometheusMetrics([], { scrapeSuccess: 0, durationSeconds: elapsedSec });
        return body;
      }

      const json = await res.json();
      const metrics = aggregateZoneAnalytics(json, zoneEntries);
      const body = renderPrometheusMetrics(metrics, { scrapeSuccess: 1, durationSeconds: elapsedSec });
      cachedBody = body;
      cachedAtMs = Date.now();
      return body;
    } catch {
      const elapsedSec = Number(process.hrtime.bigint() - startNs) / 1e9;
      return renderPrometheusMetrics([], { scrapeSuccess: 0, durationSeconds: elapsedSec });
    } finally {
      clearTimeout(timer);
    }
  }

  const server = http.createServer(async (req, res) => {
    const reqPath = (req.url || "/").split("?")[0];
    if (req.method !== "GET") {
      res.writeHead(405, { "content-type": "text/plain; charset=utf-8" });
      res.end("Method Not Allowed\n");
      return;
    }
    if (reqPath === "/healthz") {
      res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
      res.end("ok\n");
      return;
    }
    if (reqPath === "/metrics") {
      const body = await scrapeMetrics();
      res.writeHead(200, { "content-type": "text/plain; version=0.0.4; charset=utf-8" });
      res.end(body);
      return;
    }
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end("Not Found\n");
  });

  return server;
}

async function main() {
  const apiToken = process.env.OOF_CLOUDFLARE_API_TOKEN || "";
  const zoneEntries = parseZoneSpecs(process.env.OOF_CLOUDFLARE_ZONE_IDS || "");
  const listenAddr = parseListenAddress(process.env.OOF_CF_EXPORTER_LISTEN || DEFAULT_LISTEN);
  const graphqlEndpoint = process.env.OOF_CLOUDFLARE_GRAPHQL_ENDPOINT || DEFAULT_GRAPHQL_ENDPOINT;
  const windowMinutes = Number(process.env.OOF_CF_EXPORTER_WINDOW_MINUTES || 5);
  const cacheTtlSecs = Number(process.env.OOF_CF_EXPORTER_CACHE_TTL_SECS || 60);
  const timeoutMs = Number(process.env.OOF_CF_EXPORTER_TIMEOUT_MS || 10000);

  const server = createExporterServer({
    apiToken,
    zoneEntries,
    graphqlEndpoint,
    windowMinutes,
    cacheTtlSecs,
    timeoutMs,
  });

  server.listen(listenAddr.port, listenAddr.host, () => {
    process.stdout.write(
      `oof-cloudflare-graphql-exporter listening on http://${listenAddr.host}:${listenAddr.port}/metrics (zones=${zoneEntries.length})\n`
    );
  });

  const shutdown = () => {
    server.close(() => process.exit(0));
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`oof-cloudflare-graphql-exporter fatal: ${err.message}\n`);
    process.exit(1);
  });
}
