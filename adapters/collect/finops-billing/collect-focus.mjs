import zlib from "node:zlib";
import { pathToFileURL } from "node:url";

const DEFAULT_CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4";
const DEFAULT_GITHUB_API_BASE = "https://api.github.com";

export const DEFAULT_CLOUDFLARE_PRICING = {
  // Public Cloudflare standard list prices (USD)
  r2StoragePerGbMonth: 0.015,
  r2ClassAPerMillionOps: 4.5,
  r2ClassBPerMillionOps: 0.36,
  pipelinesPerGbIngested: 0.025,
  daysPerBillingMonth: 30,
};

const R2_CLASS_A_ACTIONS = new Set([
  "ListBuckets",
  "PutBucket",
  "ListObjects",
  "ListObjectsV2",
  "PutObject",
  "CopyObject",
  "CompleteMultipartUpload",
  "CreateMultipartUpload",
  "ListMultipartUploads",
  "UploadPart",
  "UploadPartCopy",
  "ListParts",
  "PutBucketEncryption",
  "PutBucketCors",
  "PutBucketLifecycleConfiguration",
  "LifecycleStorageTierTransition",
  "RecordUsage",
]);

function cleanNonEmptyString(val) {
  if (typeof val !== "string") return null;
  const trimmed = val.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function toFiniteNumber(val, fallback = 0) {
  if (typeof val === "number" && Number.isFinite(val)) return val;
  if (typeof val === "string" && val.trim() !== "") {
    const n = Number(val.trim());
    if (Number.isFinite(n)) return n;
  }
  return fallback;
}

function roundCost(val) {
  return Math.round(toFiniteNumber(val, 0) * 1e6) / 1e6;
}

function validateUrl(rawUrl, label, allowInsecureHttp = false) {
  const clean = cleanNonEmptyString(rawUrl);
  if (!clean) throw new Error(`Missing ${label}`);
  let parsed;
  try {
    parsed = new URL(clean);
  } catch {
    throw new Error(`Invalid ${label} URL`);
  }
  if (parsed.protocol !== "https:" && !(allowInsecureHttp && parsed.protocol === "http:")) {
    throw new Error(`${label} must use https:// to protect credentials in transit`);
  }
  return clean.replace(/\/+$/, "");
}

export function resolveUtcDayWindow(dateInput, nowDate = new Date()) {
  let targetDate;
  if (typeof dateInput === "string" && /^\d{4}-\d{2}-\d{2}$/.test(dateInput.trim())) {
    targetDate = new Date(`${dateInput.trim()}T00:00:00.000Z`);
  } else {
    // Default to previous complete UTC day
    const d = new Date(Date.UTC(nowDate.getUTCFullYear(), nowDate.getUTCMonth(), nowDate.getUTCDate() - 1));
    targetDate = d;
  }
  if (Number.isNaN(targetDate.getTime())) {
    throw new Error(`Invalid UTC date window: ${String(dateInput)}`);
  }
  const start = new Date(Date.UTC(targetDate.getUTCFullYear(), targetDate.getUTCMonth(), targetDate.getUTCDate(), 0, 0, 0, 0));
  const end = new Date(Date.UTC(targetDate.getUTCFullYear(), targetDate.getUTCMonth(), targetDate.getUTCDate() + 1, 0, 0, 0, 0));
  const billingStart = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), 1, 0, 0, 0, 0));
  const billingEnd = new Date(Date.UTC(start.getUTCFullYear(), start.getUTCMonth() + 1, 1, 0, 0, 0, 0));

  return {
    year: start.getUTCFullYear(),
    month: start.getUTCMonth() + 1,
    day: start.getUTCDate(),
    dateString: start.toISOString().slice(0, 10),
    chargePeriodStart: start.toISOString(),
    chargePeriodEnd: end.toISOString(),
    billingPeriodStart: billingStart.toISOString(),
    billingPeriodEnd: billingEnd.toISOString(),
  };
}

export function buildFocusRecord(input) {
  const record = {
    BilledCost: roundCost(input.BilledCost),
    BillingAccountId: cleanNonEmptyString(input.BillingAccountId) || "unknown",
    BillingCurrency: cleanNonEmptyString(input.BillingCurrency) || "USD",
    BillingPeriodEnd: cleanNonEmptyString(input.BillingPeriodEnd),
    BillingPeriodStart: cleanNonEmptyString(input.BillingPeriodStart),
    ChargeCategory: cleanNonEmptyString(input.ChargeCategory) || "Usage",
    ChargeDescription: cleanNonEmptyString(input.ChargeDescription) || "Cloud usage charge",
    ChargePeriodEnd: cleanNonEmptyString(input.ChargePeriodEnd),
    ChargePeriodStart: cleanNonEmptyString(input.ChargePeriodStart),
    EffectiveCost: roundCost(input.EffectiveCost ?? input.BilledCost),
    InvoiceIssuerName: cleanNonEmptyString(input.InvoiceIssuerName) || cleanNonEmptyString(input.ProviderName) || "Unknown",
    ProviderName: cleanNonEmptyString(input.ProviderName) || "Unknown",
    PublisherName: cleanNonEmptyString(input.PublisherName) || cleanNonEmptyString(input.ProviderName) || "Unknown",
    ServiceCategory: cleanNonEmptyString(input.ServiceCategory) || "Other",
    ServiceName: cleanNonEmptyString(input.ServiceName) || "Unknown",
  };

  const optionalStrings = [
    "AvailabilityZone",
    "BillingAccountName",
    "ChargeClass",
    "ChargeFrequency",
    "CommitmentDiscountCategory",
    "CommitmentDiscountId",
    "CommitmentDiscountName",
    "CommitmentDiscountStatus",
    "CommitmentDiscountType",
    "ConsumedUnit",
    "PricingCategory",
    "PricingUnit",
    "RegionId",
    "RegionName",
    "ResourceId",
    "ResourceName",
    "ResourceType",
    "SkuId",
    "SkuPriceId",
    "SubAccountId",
    "SubAccountName",
  ];
  for (const key of optionalStrings) {
    const v = cleanNonEmptyString(input[key]);
    if (v !== null) record[key] = v;
  }

  const optionalNumbers = [
    "ConsumedQuantity",
    "ContractedCost",
    "ContractedUnitPrice",
    "ListCost",
    "ListUnitPrice",
    "PricingQuantity",
  ];
  for (const key of optionalNumbers) {
    if (input[key] !== undefined && input[key] !== null) {
      const n = toFiniteNumber(input[key], NaN);
      if (Number.isFinite(n)) record[key] = roundCost(n);
    }
  }

  if (typeof input.Tags === "object" && input.Tags !== null && !Array.isArray(input.Tags)) {
    const cleanTags = {};
    for (const [k, v] of Object.entries(input.Tags)) {
      if (v !== undefined && v !== null) cleanTags[k] = v;
    }
    if (Object.keys(cleanTags).length > 0) record.Tags = cleanTags;
  }

  return record;
}

export function classifyR2Action(actionType) {
  if (typeof actionType !== "string") return "B";
  return R2_CLASS_A_ACTIONS.has(actionType) ? "A" : "B";
}

export function normalizeCloudflareAnalyticsToFocus(
  graphqlData,
  {
    accountId,
    accountName = null,
    window,
    pricing = DEFAULT_CLOUDFLARE_PRICING,
  }
) {
  const effectivePricing = { ...DEFAULT_CLOUDFLARE_PRICING, ...pricing };
  const accounts = graphqlData?.data?.viewer?.accounts;
  if (!Array.isArray(accounts) || accounts.length === 0) return [];

  const acct = accounts[0];
  const records = [];

  // 1. Cloudflare R2 Storage (bytes -> daily prorated GB-month)
  const storageGroups = Array.isArray(acct.r2StorageAdaptiveGroups) ? acct.r2StorageAdaptiveGroups : [];
  const storageByBucket = new Map();
  for (const g of storageGroups) {
    const bucket = cleanNonEmptyString(g?.dimensions?.bucketName) || "unknown-bucket";
    const payloadBytes = toFiniteNumber(g?.max?.payloadSize, 0);
    const metaBytes = toFiniteNumber(g?.max?.metadataSize, 0);
    const totalBytes = payloadBytes + metaBytes;
    const prev = storageByBucket.get(bucket) || 0;
    if (totalBytes > prev) storageByBucket.set(bucket, totalBytes);
  }

  for (const [bucket, totalBytes] of storageByBucket.entries()) {
    const gb = totalBytes / 1e9;
    const gbMonthDaily = gb / effectivePricing.daysPerBillingMonth;
    const cost = gbMonthDaily * effectivePricing.r2StoragePerGbMonth;
    records.push(
      buildFocusRecord({
        BillingAccountId: accountId,
        BillingAccountName: accountName,
        BillingCurrency: "USD",
        BillingPeriodStart: window.billingPeriodStart,
        BillingPeriodEnd: window.billingPeriodEnd,
        ChargeCategory: "Usage",
        ChargeDescription: `Cloudflare R2 storage for bucket ${bucket} (${window.dateString})`,
        ChargeFrequency: "Usage-Based",
        ChargePeriodStart: window.chargePeriodStart,
        ChargePeriodEnd: window.chargePeriodEnd,
        ProviderName: "Cloudflare",
        PublisherName: "Cloudflare",
        InvoiceIssuerName: "Cloudflare",
        ServiceCategory: "Storage",
        ServiceName: "Cloudflare R2",
        ResourceId: `r2:${accountId}:${bucket}`,
        ResourceName: bucket,
        ResourceType: "R2 Bucket",
        SkuId: "r2_storage_standard",
        PricingCategory: "Standard",
        ConsumedQuantity: gbMonthDaily,
        ConsumedUnit: "GB-Month",
        PricingQuantity: gbMonthDaily,
        PricingUnit: "GB-Month",
        ListUnitPrice: effectivePricing.r2StoragePerGbMonth,
        ContractedUnitPrice: effectivePricing.r2StoragePerGbMonth,
        ListCost: cost,
        ContractedCost: cost,
        BilledCost: cost,
        EffectiveCost: cost,
        Tags: {
          oof_collector: "oof-finops-billing",
          source_api: "cloudflare-graphql-analytics",
          bucket,
          peak_storage_bytes: totalBytes,
        },
      })
    );
  }

  // 2. Cloudflare R2 Operations (Class A & Class B)
  const opsGroups = Array.isArray(acct.r2OperationsAdaptiveGroups) ? acct.r2OperationsAdaptiveGroups : [];
  const opsByBucketAndClass = new Map();
  for (const g of opsGroups) {
    const bucket = cleanNonEmptyString(g?.dimensions?.bucketName) || "unknown-bucket";
    const actionType = cleanNonEmptyString(g?.dimensions?.actionType) || "Unknown";
    const requests = toFiniteNumber(g?.sum?.requests, 0);
    if (requests <= 0) continue;
    const opClass = classifyR2Action(actionType);
    const key = `${bucket}::${opClass}`;
    opsByBucketAndClass.set(key, (opsByBucketAndClass.get(key) || 0) + requests);
  }

  for (const [key, requests] of opsByBucketAndClass.entries()) {
    const [bucket, opClass] = key.split("::");
    const isClassA = opClass === "A";
    const unitPricePerMillion = isClassA
      ? effectivePricing.r2ClassAPerMillionOps
      : effectivePricing.r2ClassBPerMillionOps;
    const millionOps = requests / 1e6;
    const cost = millionOps * unitPricePerMillion;

    records.push(
      buildFocusRecord({
        BillingAccountId: accountId,
        BillingAccountName: accountName,
        BillingCurrency: "USD",
        BillingPeriodStart: window.billingPeriodStart,
        BillingPeriodEnd: window.billingPeriodEnd,
        ChargeCategory: "Usage",
        ChargeDescription: `Cloudflare R2 Class ${opClass} operations for bucket ${bucket} (${window.dateString})`,
        ChargeFrequency: "Usage-Based",
        ChargePeriodStart: window.chargePeriodStart,
        ChargePeriodEnd: window.chargePeriodEnd,
        ProviderName: "Cloudflare",
        PublisherName: "Cloudflare",
        InvoiceIssuerName: "Cloudflare",
        ServiceCategory: "Storage",
        ServiceName: "Cloudflare R2",
        ResourceId: `r2:${accountId}:${bucket}`,
        ResourceName: bucket,
        ResourceType: "R2 Bucket",
        SkuId: isClassA ? "r2_class_a_ops" : "r2_class_b_ops",
        PricingCategory: "Standard",
        ConsumedQuantity: requests,
        ConsumedUnit: "Requests",
        PricingQuantity: millionOps,
        PricingUnit: "1M Requests",
        ListUnitPrice: unitPricePerMillion,
        ContractedUnitPrice: unitPricePerMillion,
        ListCost: cost,
        ContractedCost: cost,
        BilledCost: cost,
        EffectiveCost: cost,
        Tags: {
          oof_collector: "oof-finops-billing",
          source_api: "cloudflare-graphql-analytics",
          bucket,
          r2_operation_class: opClass,
        },
      })
    );
  }

  // 3. Optional Cloudflare Pipelines / Basin ingestion volume (when returned by API)
  const pipelineGroups = Array.isArray(acct.pipelinesAdaptiveGroups) ? acct.pipelinesAdaptiveGroups : [];
  for (const g of pipelineGroups) {
    const pipelineName = cleanNonEmptyString(g?.dimensions?.pipelineName) || "default-pipeline";
    const bytesIngested = toFiniteNumber(g?.sum?.bytesIngested ?? g?.sum?.bytes, 0);
    if (bytesIngested <= 0) continue;
    const gb = bytesIngested / 1e9;
    const cost = gb * effectivePricing.pipelinesPerGbIngested;
    records.push(
      buildFocusRecord({
        BillingAccountId: accountId,
        BillingAccountName: accountName,
        BillingCurrency: "USD",
        BillingPeriodStart: window.billingPeriodStart,
        BillingPeriodEnd: window.billingPeriodEnd,
        ChargeCategory: "Usage",
        ChargeDescription: `Cloudflare Pipelines ingestion for ${pipelineName} (${window.dateString})`,
        ChargeFrequency: "Usage-Based",
        ChargePeriodStart: window.chargePeriodStart,
        ChargePeriodEnd: window.chargePeriodEnd,
        ProviderName: "Cloudflare",
        PublisherName: "Cloudflare",
        InvoiceIssuerName: "Cloudflare",
        ServiceCategory: "Analytics",
        ServiceName: "Cloudflare Pipelines",
        ResourceId: `pipelines:${accountId}:${pipelineName}`,
        ResourceName: pipelineName,
        ResourceType: "Basin Pipeline",
        SkuId: "pipelines_ingest_gb",
        PricingCategory: "Standard",
        ConsumedQuantity: gb,
        ConsumedUnit: "GB",
        PricingQuantity: gb,
        PricingUnit: "GB",
        ListUnitPrice: effectivePricing.pipelinesPerGbIngested,
        ContractedUnitPrice: effectivePricing.pipelinesPerGbIngested,
        ListCost: cost,
        ContractedCost: cost,
        BilledCost: cost,
        EffectiveCost: cost,
        Tags: {
          oof_collector: "oof-finops-billing",
          source_api: "cloudflare-graphql-analytics",
          pipeline: pipelineName,
          bytes_ingested: bytesIngested,
        },
      })
    );
  }

  return records;
}

export async function collectCloudflareFocus({
  accountId,
  accountName = null,
  apiToken,
  window,
  apiBaseUrl = DEFAULT_CLOUDFLARE_API_BASE,
  pricing = DEFAULT_CLOUDFLARE_PRICING,
  fetchImpl = fetch,
  allowInsecureHttp = false,
}) {
  const cleanAccountId = cleanNonEmptyString(accountId);
  const cleanToken = cleanNonEmptyString(apiToken);
  if (!cleanAccountId || !/^[a-fA-F0-9]{32}$/.test(cleanAccountId)) {
    throw new Error("CLOUDFLARE_ACCOUNT_ID must be a 32-character hexadecimal account ID");
  }
  if (!cleanToken) {
    throw new Error("Missing CLOUDFLARE_API_TOKEN for Cloudflare FinOps collection");
  }
  const base = validateUrl(apiBaseUrl, "CLOUDFLARE_API_BASE_URL", allowInsecureHttp);

  const query = `
    query OofFinopsR2Usage($accountTag: string!, $start: Time!, $end: Time!) {
      viewer {
        accounts(filter: { accountTag: $accountTag }) {
          r2StorageAdaptiveGroups(
            limit: 1000
            filter: { datetime_geq: $start, datetime_lt: $end }
          ) {
            dimensions { bucketName }
            max { payloadSize metadataSize }
          }
          r2OperationsAdaptiveGroups(
            limit: 5000
            filter: { datetime_geq: $start, datetime_lt: $end }
          ) {
            dimensions { bucketName actionType }
            sum { requests }
          }
        }
      }
    }
  `;

  const response = await fetchImpl(`${base}/graphql`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${cleanToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      query,
      variables: {
        accountTag: cleanAccountId,
        start: window.chargePeriodStart,
        end: window.chargePeriodEnd,
      },
    }),
  });

  if (!response.ok) {
    throw new Error(`Cloudflare GraphQL API failed with HTTP ${response.status}`);
  }
  const body = await response.json();
  if (Array.isArray(body?.errors) && body.errors.length > 0) {
    const firstMsg = cleanNonEmptyString(body.errors[0]?.message) || "GraphQL error";
    throw new Error(`Cloudflare GraphQL API returned errors: ${firstMsg}`);
  }

  return normalizeCloudflareAnalyticsToFocus(body, {
    accountId: cleanAccountId,
    accountName,
    window,
    pricing,
  });
}

function mapGitHubProduct(product) {
  const p = (cleanNonEmptyString(product) || "").toLowerCase();
  if (p === "actions") return { serviceName: "GitHub Actions", serviceCategory: "Developer Tools" };
  if (p === "packages") return { serviceName: "GitHub Packages", serviceCategory: "Developer Tools" };
  if (p === "shared_storage" || p === "shared storage") {
    return { serviceName: "GitHub Shared Storage", serviceCategory: "Storage" };
  }
  if (p === "copilot") return { serviceName: "GitHub Copilot", serviceCategory: "AI and Machine Learning" };
  if (p === "codespaces") return { serviceName: "GitHub Codespaces", serviceCategory: "Compute" };
  return {
    serviceName: p ? `GitHub ${product}` : "GitHub",
    serviceCategory: "Developer Tools",
  };
}

export function normalizeGitHubBillingUsageToFocus(
  payload,
  { billingAccountId, billingAccountName = null, window }
) {
  const items = Array.isArray(payload?.usageItems) ? payload.usageItems : [];
  const records = [];

  for (const item of items) {
    const { serviceName, serviceCategory } = mapGitHubProduct(item?.product);
    const sku = cleanNonEmptyString(item?.sku) || "unknown_sku";
    const unitType = cleanNonEmptyString(item?.unitType) || "Units";
    const quantity = toFiniteNumber(item?.quantity, 0);
    const unitPrice = toFiniteNumber(item?.pricePerUnit, 0);
    const grossAmount = toFiniteNumber(item?.grossAmount, quantity * unitPrice);
    const discountAmount = toFiniteNumber(item?.discountAmount, 0);
    const netAmount = toFiniteNumber(item?.netAmount, Math.max(grossAmount - discountAmount, 0));

    const itemDateStr = cleanNonEmptyString(item?.date);
    let itemWindow = window;
    if (itemDateStr) {
      const parsedDate = new Date(itemDateStr);
      if (!Number.isNaN(parsedDate.getTime())) {
        itemWindow = resolveUtcDayWindow(parsedDate.toISOString().slice(0, 10));
      }
    }

    const orgName = cleanNonEmptyString(item?.organizationName) || billingAccountName || billingAccountId;
    const repoName = cleanNonEmptyString(item?.repositoryName);
    const resourceName = repoName || orgName;
    const resourceType = repoName ? "GitHub Repository" : "GitHub Organization";
    const resourceId = repoName ? `github:${orgName}/${repoName}` : `github:${orgName}`;

    records.push(
      buildFocusRecord({
        BillingAccountId: billingAccountId,
        BillingAccountName: orgName,
        BillingCurrency: "USD",
        BillingPeriodStart: itemWindow.billingPeriodStart,
        BillingPeriodEnd: itemWindow.billingPeriodEnd,
        ChargeCategory: "Usage",
        ChargeDescription: `${serviceName} (${sku}) usage for ${resourceName}`,
        ChargeFrequency: "Usage-Based",
        ChargePeriodStart: itemWindow.chargePeriodStart,
        ChargePeriodEnd: itemWindow.chargePeriodEnd,
        ProviderName: "GitHub",
        PublisherName: "GitHub",
        InvoiceIssuerName: "GitHub",
        ServiceCategory: serviceCategory,
        ServiceName: serviceName,
        ResourceId: resourceId,
        ResourceName: resourceName,
        ResourceType: resourceType,
        SkuId: sku,
        PricingCategory: "Standard",
        ConsumedQuantity: quantity,
        ConsumedUnit: unitType,
        PricingQuantity: quantity,
        PricingUnit: unitType,
        ListUnitPrice: unitPrice,
        ContractedUnitPrice: unitPrice,
        ListCost: grossAmount,
        ContractedCost: grossAmount,
        BilledCost: netAmount,
        EffectiveCost: netAmount,
        SubAccountId: orgName,
        SubAccountName: orgName,
        Tags: {
          oof_collector: "oof-finops-billing",
          source_api: "github-billing-usage",
          github_product: cleanNonEmptyString(item?.product) || "unknown",
          organization: orgName,
          repository: repoName,
          discount_amount: discountAmount,
        },
      })
    );
  }

  return records;
}

export async function collectGitHubFocus({
  org = null,
  user = null,
  token,
  window,
  apiBaseUrl = DEFAULT_GITHUB_API_BASE,
  fetchImpl = fetch,
  allowInsecureHttp = false,
}) {
  const cleanOrg = cleanNonEmptyString(org);
  const cleanUser = cleanNonEmptyString(user);
  const cleanToken = cleanNonEmptyString(token);
  if (!cleanOrg && !cleanUser) {
    throw new Error("Either GITHUB_ORG or GITHUB_USER must be set for GitHub FinOps collection");
  }
  if (!cleanToken) {
    throw new Error("Missing GITHUB_TOKEN for GitHub FinOps collection");
  }
  const base = validateUrl(apiBaseUrl, "GITHUB_API_BASE_URL", allowInsecureHttp);

  const scopePath = cleanOrg
    ? `/organizations/${encodeURIComponent(cleanOrg)}/settings/billing/usage`
    : `/users/${encodeURIComponent(cleanUser)}/settings/billing/usage`;

  const url = new URL(`${base}${scopePath}`);
  url.searchParams.set("year", String(window.year));
  url.searchParams.set("month", String(window.month));
  url.searchParams.set("day", String(window.day));

  const response = await fetchImpl(url.toString(), {
    method: "GET",
    headers: {
      Authorization: `Bearer ${cleanToken}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "oof-finops-billing",
    },
  });

  if (!response.ok) {
    throw new Error(`GitHub Billing Usage API failed with HTTP ${response.status}`);
  }
  const payload = await response.json();
  const billingAccountId = cleanOrg || cleanUser;

  return normalizeGitHubBillingUsageToFocus(payload, {
    billingAccountId,
    billingAccountName: billingAccountId,
    window,
  });
}

export async function sendFocusToBasin(
  records,
  { endpoint, token, fetchImpl = fetch, allowInsecureHttp = false } = {}
) {
  const cleanEndpoint = validateUrl(endpoint, "OOF_FOCUS_BASIN_ENDPOINT", allowInsecureHttp);
  const cleanToken = cleanNonEmptyString(token);
  if (!cleanToken) {
    throw new Error("Missing OOF_INGEST_TOKEN for Basin HTTP ingest");
  }
  const batch = Array.isArray(records) ? records : [records];
  if (batch.length === 0) {
    return { status: 204, count: 0 };
  }

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
    throw new Error(`Basin FOCUS HTTP ingest failed with HTTP ${response.status}`);
  }
  return { status: response.status, count: batch.length };
}

export async function runFinopsCollection({ env = process.env, dryRun = false, fetchImpl = fetch, allowInsecureHttp = false } = {}) {
  const window = resolveUtcDayWindow(cleanNonEmptyString(env.OOF_FINOPS_DATE));
  let pricing = DEFAULT_CLOUDFLARE_PRICING;
  const pricingJson = cleanNonEmptyString(env.OOF_CF_PRICING_JSON);
  if (pricingJson) {
    const parsed = JSON.parse(pricingJson);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("OOF_CF_PRICING_JSON must be a JSON object");
    }
    pricing = { ...DEFAULT_CLOUDFLARE_PRICING, ...parsed };
  }

  const allRecords = [];
  let sourcesConfigured = 0;

  const cfAccountId = cleanNonEmptyString(env.CLOUDFLARE_ACCOUNT_ID);
  const cfToken = cleanNonEmptyString(env.CLOUDFLARE_API_TOKEN);
  if (cfAccountId && cfToken) {
    sourcesConfigured += 1;
    const cfRecords = await collectCloudflareFocus({
      accountId: cfAccountId,
      accountName: cleanNonEmptyString(env.CLOUDFLARE_ACCOUNT_NAME),
      apiToken: cfToken,
      window,
      apiBaseUrl: cleanNonEmptyString(env.CLOUDFLARE_API_BASE_URL) || DEFAULT_CLOUDFLARE_API_BASE,
      pricing,
      fetchImpl,
      allowInsecureHttp,
    });
    allRecords.push(...cfRecords);
  }

  const ghOrg = cleanNonEmptyString(env.GITHUB_ORG);
  const ghUser = cleanNonEmptyString(env.GITHUB_USER);
  const ghToken = cleanNonEmptyString(env.GITHUB_TOKEN);
  if ((ghOrg || ghUser) && ghToken) {
    sourcesConfigured += 1;
    const ghRecords = await collectGitHubFocus({
      org: ghOrg,
      user: ghUser,
      token: ghToken,
      window,
      apiBaseUrl: cleanNonEmptyString(env.GITHUB_API_BASE_URL) || DEFAULT_GITHUB_API_BASE,
      fetchImpl,
      allowInsecureHttp,
    });
    allRecords.push(...ghRecords);
  }

  if (sourcesConfigured === 0) {
    throw new Error(
      "No FinOps billing source configured. Set CLOUDFLARE_ACCOUNT_ID+CLOUDFLARE_API_TOKEN and/or GITHUB_ORG (or GITHUB_USER)+GITHUB_TOKEN."
    );
  }

  if (dryRun) {
    return { dryRun: true, date: window.dateString, count: allRecords.length, records: allRecords };
  }

  const sendResult = await sendFocusToBasin(allRecords, {
    endpoint: cleanNonEmptyString(env.OOF_FOCUS_BASIN_ENDPOINT),
    token: cleanNonEmptyString(env.OOF_INGEST_TOKEN),
    fetchImpl,
    allowInsecureHttp,
  });

  return {
    dryRun: false,
    date: window.dateString,
    count: sendResult.count,
    status: sendResult.status,
  };
}

async function main() {
  const dryRun = process.argv.includes("--dry-run");
  const result = await runFinopsCollection({ env: process.env, dryRun });
  if (dryRun) {
    process.stdout.write(`${JSON.stringify({ date: result.date, count: result.count, records: result.records }, null, 2)}\n`);
  } else {
    process.stdout.write(
      `Sent ${result.count} FOCUS v1.0 record(s) for ${result.date} to Basin (HTTP ${result.status})\n`
    );
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    process.stderr.write(`oof-finops-billing error: ${err.message}\n`);
    process.exitCode = 1;
  });
}
