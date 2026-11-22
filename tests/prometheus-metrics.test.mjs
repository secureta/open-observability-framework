import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import http from "node:http";
import net from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, "..");

const PROM_CONFIG_PATH = path.join(REPO_ROOT, "adapters/collect/prometheus-pull/prometheus.yml");
const PROM_QUERIES_PATH = path.join(REPO_ROOT, "adapters/collect/prometheus-pull/queries.promql");
const FLAKE_NIX_PATH = path.join(REPO_ROOT, "flake.nix");

function requireBinary(name) {
  const pathEntries = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  for (const dir of pathEntries) {
    const candidate = path.join(dir, name);
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      if (fs.statSync(candidate).isFile()) {
        return candidate;
      }
    } catch {
      // continue
    }
  }
  throw new Error(`Required test runtime binary '${name}' is not in PATH`);
}

async function getFreeLoopbackPort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close((err) => {
        if (err) reject(err);
        else resolve(addr.port);
      });
    });
  });
}

function httpGetJson(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { timeout: 3000 }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => {
        body += chunk;
      });
      res.on("end", () => {
        try {
          resolve({ statusCode: res.statusCode, json: JSON.parse(body), raw: body });
        } catch (err) {
          reject(new Error(`Failed to parse JSON from ${url} (HTTP ${res.statusCode}): ${body}`));
        }
      });
    });
    req.on("error", reject);
    req.on("timeout", () => {
      req.destroy(new Error(`HTTP GET timed out: ${url}`));
    });
  });
}

function httpGetStatus(url) {
  return new Promise((resolve, reject) => {
    const req = http.get(url, { timeout: 3000 }, (res) => {
      res.resume();
      res.on("end", () => resolve(res.statusCode));
    });
    req.on("error", reject);
    req.on("timeout", () => req.destroy(new Error(`HTTP GET timed out: ${url}`)));
  });
}

async function waitForCondition(fn, { timeoutMs = 12000, intervalMs = 150, label = "condition" } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const val = await fn();
      if (val) return val;
    } catch (err) {
      lastError = err;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  const detail = lastError ? ` (last error: ${lastError.message})` : "";
  throw new Error(`Timed out waiting for ${label} after ${timeoutMs}ms${detail}`);
}

test("Static contract: reference prometheus.yml is valid, loopback-only, and allowlists cloudflared_tunnel_ha_connections", () => {
  const promtool = requireBinary("promtool");
  const check = spawnSync(promtool, ["check", "config", PROM_CONFIG_PATH], { encoding: "utf8" });
  assert.equal(check.status, 0, `promtool check config failed:\n${check.stdout}\n${check.stderr}`);

  const yamlText = fs.readFileSync(PROM_CONFIG_PATH, "utf8");
  assert.match(yamlText, /127\.0\.0\.1:20241/, "Reference example must target loopback");
  assert.match(yamlText, /\^\(cloudflared_tunnel_ha_connections\)\$/, "Must allowlist only cloudflared_tunnel_ha_connections");
  assert.match(yamlText, /\^\(__name__\|job\)\$/, "Must strip unnecessary labels via labelkeep");
  assert.match(yamlText, /target_label:\s*instance/, "Must scrub IP:port from instance label");

  const queriesText = fs.readFileSync(PROM_QUERIES_PATH, "utf8");
  assert.match(queriesText, /cloudflared_tunnel_ha_connections\{job="cloudflared"\}/);
  assert.match(queriesText, /up\{job="cloudflared"\}/);

  const flakeText = fs.readFileSync(FLAKE_NIX_PATH, "utf8");
  assert.match(flakeText, /prometheus\s*=\s*\{[\s\S]*?enable\s*=\s*lib\.mkEnableOption/, "Prometheus option must default to disabled via mkEnableOption");
});

test("E2E mock endpoint: normal, zero, timeout, malformed, HTTP 500, missing metric, and strict metric/label filtering", async () => {
  const prometheusBin = requireBinary("prometheus");
  const promtoolBin = requireBinary("promtool");

  let mockMode = "normal";
  let scrapeCount = 0;
  const openTimers = new Set();

  const mockServer = http.createServer((req, res) => {
    if (req.url === "/healthz") {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok\n");
      return;
    }

    if (req.url !== "/metrics") {
      res.writeHead(404);
      res.end("not found\n");
      return;
    }

    scrapeCount += 1;

    if (mockMode === "normal") {
      res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" });
      res.end(
        [
          "# HELP cloudflared_tunnel_ha_connections Number of active ha connections",
          "# TYPE cloudflared_tunnel_ha_connections gauge",
          'cloudflared_tunnel_ha_connections{tunnel_id="11111111-2222-3333-4444-555555555555",ip="198.51.100.10",hostname="edge-01.example.invalid",edge_location="example01",instance="spoofed:9999"} 4',
          "# HELP cloudflared_tunnel_total_requests Amount of requests proxied through all the tunnels",
          "# TYPE cloudflared_tunnel_total_requests counter",
          "cloudflared_tunnel_total_requests 99",
          "# HELP cloudflared_tunnel_server_locations Where each tunnel is connected to.",
          "# TYPE cloudflared_tunnel_server_locations gauge",
          'cloudflared_tunnel_server_locations{connection_id="0",edge_location="example01"} 1',
          "# HELP go_goroutines Number of goroutines",
          "# TYPE go_goroutines gauge",
          "go_goroutines 42",
          "",
        ].join("\n")
      );
      return;
    }

    if (mockMode === "zero") {
      res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" });
      res.end(
        [
          "# HELP cloudflared_tunnel_ha_connections Number of active ha connections",
          "# TYPE cloudflared_tunnel_ha_connections gauge",
          "cloudflared_tunnel_ha_connections 0",
          "",
        ].join("\n")
      );
      return;
    }

    if (mockMode === "recovered_3") {
      res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" });
      res.end(
        [
          "# HELP cloudflared_tunnel_ha_connections Number of active ha connections",
          "# TYPE cloudflared_tunnel_ha_connections gauge",
          "cloudflared_tunnel_ha_connections 3",
          "",
        ].join("\n")
      );
      return;
    }

    if (mockMode === "recovered_2") {
      res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" });
      res.end(
        [
          "# HELP cloudflared_tunnel_ha_connections Number of active ha connections",
          "# TYPE cloudflared_tunnel_ha_connections gauge",
          "cloudflared_tunnel_ha_connections 2",
          "",
        ].join("\n")
      );
      return;
    }

    if (mockMode === "timeout") {
      const timer = setTimeout(() => {
        openTimers.delete(timer);
        if (!res.writableEnded) {
          res.writeHead(200, { "Content-Type": "text/plain" });
          res.end("cloudflared_tunnel_ha_connections 4\n");
        }
      }, 1500);
      openTimers.add(timer);
      res.on("close", () => {
        clearTimeout(timer);
        openTimers.delete(timer);
      });
      return;
    }

    if (mockMode === "malformed") {
      res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" });
      res.end("# TYPE broken\nnot valid prometheus exposition {{{\n");
      return;
    }

    if (mockMode === "http_500") {
      res.writeHead(500, { "Content-Type": "text/plain" });
      res.end("internal error\n");
      return;
    }

    if (mockMode === "missing_metric") {
      res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" });
      res.end(
        [
          "# HELP go_goroutines Number of goroutines",
          "# TYPE go_goroutines gauge",
          "go_goroutines 10",
          "",
        ].join("\n")
      );
      return;
    }

    res.writeHead(500);
    res.end("unknown mode\n");
  });

  await new Promise((resolve) => mockServer.listen(0, "127.0.0.1", resolve));
  const mockPort = mockServer.address().port;
  const promPort = await getFreeLoopbackPort();
  const promBaseUrl = `http://127.0.0.1:${promPort}`;
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "oof-prom-e2e-"));
  const tsdbDir = path.join(tmpDir, "tsdb");
  const promCfgPath = path.join(tmpDir, "prometheus.yml");

  const promCfg = [
    "global:",
    "  scrape_interval: 500ms",
    "  scrape_timeout: 300ms",
    "scrape_configs:",
    "  - job_name: cloudflared",
    "    metrics_path: /metrics",
    "    scheme: http",
    "    honor_labels: false",
    "    static_configs:",
    `      - targets: ["127.0.0.1:${mockPort}"]`,
    "    relabel_configs:",
    "      - target_label: instance",
    "        replacement: cloudflared",
    "    metric_relabel_configs:",
    "      - source_labels: [__name__]",
    "        regex: ^(cloudflared_tunnel_ha_connections)$",
    "        action: keep",
    "      - regex: ^(__name__|job)$",
    "        action: labelkeep",
    "",
  ].join("\n");

  fs.writeFileSync(promCfgPath, promCfg, "utf8");

  const cfgCheck = spawnSync(promtoolBin, ["check", "config", promCfgPath], { encoding: "utf8" });
  assert.equal(cfgCheck.status, 0, `Generated test prometheus.yml failed promtool check:\n${cfgCheck.stdout}\n${cfgCheck.stderr}`);

  const promLogs = [];
  const promProc = spawn(
    prometheusBin,
    [
      `--config.file=${promCfgPath}`,
      `--storage.tsdb.path=${tsdbDir}`,
      `--web.listen-address=127.0.0.1:${promPort}`,
      "--log.level=warn",
    ],
    { stdio: ["ignore", "pipe", "pipe"] }
  );
  promProc.stdout.on("data", (d) => promLogs.push(d.toString()));
  promProc.stderr.on("data", (d) => promLogs.push(d.toString()));

  const queryInstant = async (expr) => {
    const url = `${promBaseUrl}/api/v1/query?query=${encodeURIComponent(expr)}`;
    const { statusCode, json } = await httpGetJson(url);
    assert.equal(statusCode, 200, `Query HTTP ${statusCode} for ${expr}`);
    assert.equal(json.status, "success", `Query failed for ${expr}: ${JSON.stringify(json)}`);
    return json.data.result;
  };

  const testStartSec = Math.floor(Date.now() / 1000) - 1;

  try {
    await waitForCondition(
      async () => (await httpGetStatus(`${promBaseUrl}/-/ready`)) === 200,
      { label: "prometheus /-/ready" }
    );

    // Phase 1: Normal sample + strict metric/label filtering
    const normalRes = await waitForCondition(
      async () => {
        const r = await queryInstant('cloudflared_tunnel_ha_connections{job="cloudflared"}');
        return r.length === 1 && r[0].value[1] === "4" ? r : null;
      },
      { label: "phase 1 normal sample (4)" }
    );
    assert.deepEqual(
      Object.keys(normalRes[0].metric).sort(),
      ["__name__", "job"],
      `Disallowed labels leaked into stored sample: ${JSON.stringify(normalRes[0].metric)}`
    );
    assert.equal(normalRes[0].metric.__name__, "cloudflared_tunnel_ha_connections");
    assert.equal(normalRes[0].metric.job, "cloudflared");
    assert.ok(typeof normalRes[0].value[0] === "number" && normalRes[0].value[0] > 0, "Sample must carry timestamp");

    const upNormal = await queryInstant('up{job="cloudflared"}');
    assert.equal(upNormal.length, 1);
    assert.equal(upNormal[0].value[1], "1");
    assert.equal(upNormal[0].metric.instance, "cloudflared", "instance label must not contain IP:port");

    const namesResp = await httpGetJson(`${promBaseUrl}/api/v1/label/__name__/values`);
    assert.equal(namesResp.statusCode, 200);
    const metricNames = new Set(namesResp.json.data);
    assert.ok(metricNames.has("cloudflared_tunnel_ha_connections"));
    assert.ok(!metricNames.has("cloudflared_tunnel_total_requests"), "Disallowed metric must be dropped");
    assert.ok(!metricNames.has("cloudflared_tunnel_server_locations"), "Disallowed metric must be dropped");
    assert.ok(!metricNames.has("go_goroutines"), "Disallowed metric must be dropped");

    // Phase 2: Zero connections (healthy scrape with value 0, NOT missing)
    mockMode = "zero";
    await waitForCondition(
      async () => {
        const r = await queryInstant('cloudflared_tunnel_ha_connections{job="cloudflared"}');
        return r.length === 1 && r[0].value[1] === "0" ? r : null;
      },
      { label: "phase 2 zero sample (0)" }
    );
    const upZero = await queryInstant('up{job="cloudflared"}');
    assert.equal(upZero.length, 1);
    assert.equal(upZero[0].value[1], "1");
    const zeroDistinguished = await queryInstant(
      '(cloudflared_tunnel_ha_connections{job="cloudflared"} == 0) and on(job) (up{job="cloudflared"} == 1)'
    );
    assert.equal(zeroDistinguished.length, 1, "Zero connections must be explicitly queryable as healthy zero");
    const absentOnZero = await queryInstant('absent(cloudflared_tunnel_ha_connections{job="cloudflared"})');
    assert.equal(absentOnZero.length, 0, "Zero sample must NOT be treated as absent");

    // Phase 3: Timeout -> up == 0, metric absent (distinguished from zero), target unaffected
    mockMode = "timeout";
    await waitForCondition(
      async () => {
        const u = await queryInstant('up{job="cloudflared"}');
        const m = await queryInstant('cloudflared_tunnel_ha_connections{job="cloudflared"}');
        return u.length === 1 && u[0].value[1] === "0" && m.length === 0 ? true : null;
      },
      { label: "phase 3 timeout (up=0, metric absent)" }
    );
    const absentOnTimeout = await queryInstant('absent(cloudflared_tunnel_ha_connections{job="cloudflared"})');
    assert.equal(absentOnTimeout.length, 1, "Timeout must result in absent metric, distinct from 0");
    assert.equal(
      await httpGetStatus(`http://127.0.0.1:${mockPort}/healthz`),
      200,
      "Scrape timeout must not impact monitored target health"
    );

    // Recovery after timeout
    mockMode = "recovered_3";
    await waitForCondition(
      async () => {
        const u = await queryInstant('up{job="cloudflared"}');
        const m = await queryInstant('cloudflared_tunnel_ha_connections{job="cloudflared"}');
        return u.length === 1 && u[0].value[1] === "1" && m.length === 1 && m[0].value[1] === "3" ? true : null;
      },
      { label: "recovery after timeout (3)" }
    );

    // Phase 4: Malformed exposition response -> up == 0, metric absent, target unaffected
    mockMode = "malformed";
    await waitForCondition(
      async () => {
        const u = await queryInstant('up{job="cloudflared"}');
        const m = await queryInstant('cloudflared_tunnel_ha_connections{job="cloudflared"}');
        return u.length === 1 && u[0].value[1] === "0" && m.length === 0 ? true : null;
      },
      { label: "phase 4 malformed response (up=0, metric absent)" }
    );
    assert.equal(
      await httpGetStatus(`http://127.0.0.1:${mockPort}/healthz`),
      200,
      "Malformed metrics scrape must not impact monitored target health"
    );

    // Recovery after malformed response
    mockMode = "recovered_2";
    await waitForCondition(
      async () => {
        const u = await queryInstant('up{job="cloudflared"}');
        const m = await queryInstant('cloudflared_tunnel_ha_connections{job="cloudflared"}');
        return u.length === 1 && u[0].value[1] === "1" && m.length === 1 && m[0].value[1] === "2" ? true : null;
      },
      { label: "recovery after malformed (2)" }
    );

    // Phase 5: HTTP 500 -> up == 0, metric absent, target unaffected
    mockMode = "http_500";
    await waitForCondition(
      async () => {
        const u = await queryInstant('up{job="cloudflared"}');
        const m = await queryInstant('cloudflared_tunnel_ha_connections{job="cloudflared"}');
        return u.length === 1 && u[0].value[1] === "0" && m.length === 0 ? true : null;
      },
      { label: "phase 5 HTTP 500 (up=0, metric absent)" }
    );
    assert.equal(await httpGetStatus(`http://127.0.0.1:${mockPort}/healthz`), 200);

    // Phase 6: Missing metric on HTTP 200 -> up == 1 AND absent(metric) == 1 (distinguished from both zero and scrape failure)
    mockMode = "missing_metric";
    await waitForCondition(
      async () => {
        const u = await queryInstant('up{job="cloudflared"}');
        const m = await queryInstant('cloudflared_tunnel_ha_connections{job="cloudflared"}');
        return u.length === 1 && u[0].value[1] === "1" && m.length === 0 ? true : null;
      },
      { label: "phase 6 missing metric on HTTP 200 (up=1, metric absent)" }
    );
    const missingDistinguished = await queryInstant(
      'absent(cloudflared_tunnel_ha_connections{job="cloudflared"}) and on(job) (up{job="cloudflared"} == 1)'
    );
    assert.equal(
      missingDistinguished.length,
      1,
      "Missing metric on HTTP 200 must be distinguishable from both zero and scrape failure"
    );

    // Phase 7: Time-series range query and promtool CLI query
    const testEndSec = Math.ceil(Date.now() / 1000) + 1;
    const rangeMetric = await httpGetJson(
      `${promBaseUrl}/api/v1/query_range?query=${encodeURIComponent(
        'cloudflared_tunnel_ha_connections{job="cloudflared"}'
      )}&start=${testStartSec}&end=${testEndSec}&step=500ms`
    );
    assert.equal(rangeMetric.statusCode, 200);
    assert.equal(rangeMetric.json.status, "success");
    assert.equal(rangeMetric.json.data.result.length, 1);
    const metricVals = new Set(rangeMetric.json.data.result[0].values.map(([, v]) => v));
    assert.ok(metricVals.has("4"), `Range query should contain normal value 4, got ${[...metricVals]}`);
    assert.ok(metricVals.has("0"), `Range query should contain zero value 0, got ${[...metricVals]}`);

    const rangeUp = await httpGetJson(
      `${promBaseUrl}/api/v1/query_range?query=${encodeURIComponent(
        'up{job="cloudflared"}'
      )}&start=${testStartSec}&end=${testEndSec}&step=500ms`
    );
    assert.equal(rangeUp.statusCode, 200);
    assert.equal(rangeUp.json.data.result.length, 1);
    const upVals = new Set(rangeUp.json.data.result[0].values.map(([, v]) => v));
    assert.ok(upVals.has("1"), `Range query for up should contain 1, got ${[...upVals]}`);
    assert.ok(upVals.has("0"), `Range query for up should contain 0, got ${[...upVals]}`);

    const cliRes = spawnSync(
      promtoolBin,
      ["query", "instant", promBaseUrl, 'up{job="cloudflared"}'],
      { encoding: "utf8" }
    );
    assert.equal(cliRes.status, 0, `promtool query instant failed:\n${cliRes.stdout}\n${cliRes.stderr}`);
    assert.match(cliRes.stdout, /up\{.*job="cloudflared".*\}\s*=>\s*1/);

    assert.ok(scrapeCount >= 6, `Expected multiple scrapes, saw ${scrapeCount}`);
  } catch (err) {
    err.message += `\n--- Prometheus logs ---\n${promLogs.join("")}`;
    throw err;
  } finally {
    for (const t of openTimers) clearTimeout(t);
    promProc.kill("SIGTERM");
    await new Promise((resolve) => {
      const killTimer = setTimeout(() => {
        promProc.kill("SIGKILL");
        resolve();
      }, 3000);
      promProc.once("exit", () => {
        clearTimeout(killTimer);
        resolve();
      });
    });
    await new Promise((resolve) => mockServer.close(resolve));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
