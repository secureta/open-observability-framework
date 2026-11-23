import * as pulumi from "@pulumi/pulumi";
import * as cloudflare from "@pulumi/cloudflare";
import {
  BasinStructuredStream,
  DEFAULT_API_BASE_URL,
  extractHostFromEndpoint,
  loadBasinSchemaFields,
  renderPipelineSql,
  requireEnvApiToken,
  resolveDefaultRepoPaths,
  validateBasinSettings,
} from "./stream";

const config = new pulumi.Config();
const cfConfig = new pulumi.Config("cloudflare");

if (config.get("apiToken") !== undefined || cfConfig.get("apiToken") !== undefined) {
  throw new Error(
    "Do not set apiToken in Pulumi config; export CLOUDFLARE_API_TOKEN in the environment so create, refresh, and destroy all authenticate without storing API tokens in dynamic resource state."
  );
}
requireEnvApiToken();

const accountId = config.require("accountId");
const catalogToken = config.requireSecret("catalogToken");
const apiBaseUrl =
  config.get("apiBaseUrl") ?? cfConfig.get("baseUrl") ?? DEFAULT_API_BASE_URL;

const bucketNameConfig = config.get("bucketName") ?? "oof-telemetry";
const createBucket = config.getBoolean("createBucket") ?? true;
const enableCatalog = config.getBoolean("enableCatalog") ?? true;
const namespace = config.get("namespace") ?? "siem";
const tableName = config.get("tableName") ?? "ocsf_event_log_activity";
const streamNameConfig = config.get("streamName") ?? "ocsf_event_log_stream";
const sinkName = config.get("sinkName") ?? "ocsf_event_log_sink";
const pipelineName = config.get("pipelineName") ?? "ocsf_event_log_to_iceberg";
const rollIntervalSeconds = config.getNumber("rollIntervalSeconds") ?? 300;
const streamCorsOrigins = config.getObject<string[]>("streamCorsOrigins") ?? [];

const createIngestToken = config.getBoolean("createIngestToken") ?? false;
const ingestTokenName = config.get("ingestTokenName") ?? "oof-basin-ingest";
const ingestTokenPermissionGroupId = config.get("ingestTokenPermissionGroupId");

const enableFinops = config.getBoolean("enableFinops") ?? false;
const finopsNamespace = config.get("finopsNamespace") ?? "finops";
const finopsTableName = config.get("finopsTableName") ?? "focus_cost_and_usage";
const finopsStreamNameConfig = config.get("finopsStreamName") ?? "focus_cost_and_usage_stream";
const finopsSinkName = config.get("finopsSinkName") ?? "focus_cost_and_usage_sink";
const finopsPipelineName = config.get("finopsPipelineName") ?? "focus_cost_and_usage_to_iceberg";

interface LogpushJobConfig {
  scope?: "zone" | "account";
  zoneId?: string;
  dataset: string;
  destinationConf: string;
  enabled?: boolean;
  frequency?: "high" | "low";
  name?: string;
  filter?: string;
  outputOptions?: {
    fieldNames?: string[];
    timestampFormat?: string;
    outputType?: string;
  };
}

const logpushJobsConfig = config.getObject<Record<string, LogpushJobConfig>>("logpushJobs") ?? {};
for (const [jobKey, job] of Object.entries(logpushJobsConfig)) {
  const scope = job.scope ?? "zone";
  if (scope !== "zone" && scope !== "account") {
    throw new Error(`logpushJobs.${jobKey}.scope must be 'zone' or 'account'.`);
  }
  if (scope === "zone" && (!job.zoneId || !/^[a-fA-F0-9]{32}$/.test(job.zoneId))) {
    throw new Error(`logpushJobs.${jobKey}.zoneId must be a 32-hex Cloudflare Zone ID when scope is 'zone'.`);
  }
  if (scope === "account" && job.zoneId !== undefined) {
    throw new Error(`logpushJobs.${jobKey}.zoneId must not be set when scope is 'account'.`);
  }
  if (!job.dataset || job.dataset.trim() === "") {
    throw new Error(`logpushJobs.${jobKey}.dataset must be non-empty.`);
  }
  if (!job.destinationConf || job.destinationConf.trim() === "") {
    throw new Error(`logpushJobs.${jobKey}.destinationConf must be non-empty.`);
  }
}

const enableAiUsage = config.getBoolean("enableAiUsage") ?? false;
const aiNamespace = config.get("aiNamespace") ?? "ai";
const aiTableName = config.get("aiTableName") ?? "genai_usage";
const aiStreamNameConfig = config.get("aiStreamName") ?? "ai_genai_usage_stream";
const aiSinkName = config.get("aiSinkName") ?? "ai_genai_usage_sink";
const aiPipelineName = config.get("aiPipelineName") ?? "ai_genai_usage_to_iceberg";

const defaults = resolveDefaultRepoPaths(__dirname);
const schemaFile = config.get("schemaFile") ?? defaults.schemaFile;
const pipelineSqlFile = config.get("pipelineSqlFile") ?? defaults.pipelineSqlFile;
const finopsSchemaFile = config.get("finopsSchemaFile") ?? defaults.focusSchemaFile;
const finopsPipelineSqlFile = config.get("finopsPipelineSqlFile") ?? defaults.focusPipelineSqlFile;
const aiSchemaFile = config.get("aiSchemaFile") ?? defaults.aiSchemaFile;
const aiPipelineSqlFile = config.get("aiPipelineSqlFile") ?? defaults.aiPipelineSqlFile;

// Validate non-secret inputs synchronously and secret catalogToken on resolution.
validateBasinSettings({
  accountId,
  catalogToken: "placeholder-validated-separately",
  apiBaseUrl,
  bucketName: bucketNameConfig,
  namespace,
  tableName,
  streamName: streamNameConfig,
  sinkName,
  pipelineName,
  rollIntervalSeconds,
  ingestTokenName,
});

const validatedCatalogToken = catalogToken.apply((token) => {
  validateBasinSettings({
    accountId,
    catalogToken: token,
    apiBaseUrl,
    bucketName: bucketNameConfig,
    namespace,
    tableName,
    streamName: streamNameConfig,
    sinkName,
    pipelineName,
    rollIntervalSeconds,
    ingestTokenName,
  });
  return token;
});

const schemaFields = loadBasinSchemaFields(schemaFile);
const renderedSql = renderPipelineSql(pipelineSqlFile, sinkName, streamNameConfig);

const cfProvider = new cloudflare.Provider("cloudflare", {
  baseUrl: apiBaseUrl,
});

const bucket = createBucket
  ? new cloudflare.R2Bucket(
      "oof-lake-bucket",
      {
        accountId,
        name: bucketNameConfig,
      },
      { provider: cfProvider }
    )
  : undefined;

const effectiveBucketName = bucket ? bucket.name : pulumi.output(bucketNameConfig);

const catalog = enableCatalog
  ? new cloudflare.R2DataCatalog(
      "oof-lake-catalog",
      {
        accountId,
        bucketName: effectiveBucketName,
      },
      {
        provider: cfProvider,
        dependsOn: bucket ? [bucket] : [],
      }
    )
  : undefined;

const stream = new BasinStructuredStream("oof-ocsf-stream", {
  accountId,
  apiBaseUrl,
  name: streamNameConfig,
  format: {
    type: "json",
  },
  http: {
    enabled: true,
    authentication: true,
    cors: {
      origins: streamCorsOrigins,
    },
  },
  workerBinding: {
    enabled: false,
  },
  schema: {
    fields: schemaFields,
  },
});

const sinkDependencies: pulumi.Resource[] = [];
if (bucket) sinkDependencies.push(bucket);
if (catalog) sinkDependencies.push(catalog);

const sink = new cloudflare.PipelineSink(
  "oof-ocsf-sink",
  {
    accountId,
    name: sinkName,
    type: "r2_data_catalog",
    format: {
      type: "parquet",
    },
    config: {
      accountId,
      bucket: effectiveBucketName,
      namespace,
      tableName,
      token: validatedCatalogToken,
      rollingPolicy: {
        intervalSeconds: rollIntervalSeconds,
      },
    },
  },
  {
    provider: cfProvider,
    dependsOn: sinkDependencies,
  }
);

const pipeline = new cloudflare.Pipeline(
  "oof-ocsf-pipeline",
  {
    accountId,
    name: pipelineName,
    // Encode stream.id and sink.id into SQL comment so replacement of either forces pipeline replacement first.
    sql: pulumi.interpolate`-- stream_id=${stream.id} sink_id=${sink.id}\n${renderedSql}`,
  },
  {
    provider: cfProvider,
    dependsOn: [stream, sink],
    replaceOnChanges: ["sql"],
    deleteBeforeReplace: true,
  }
);

let ingestTokenOutput: pulumi.Output<string | undefined> = pulumi.output(undefined);
if (createIngestToken) {
  const permissionGroupId: pulumi.Output<string> = ingestTokenPermissionGroupId
    ? pulumi.output(ingestTokenPermissionGroupId)
    : cloudflare
        .getAccountApiTokenPermissionGroupsListOutput(
          { accountId },
          { provider: cfProvider }
        )
        .apply((res) => {
          const match = res.results.find(
            (g) =>
              (g.name === "Pipelines Send" || g.name === "Basin Pipelines Send") &&
              g.isSelectable !== false
          );
          if (!match) {
            throw new Error(
              "Could not resolve 'Pipelines Send' permission group ID; set ingestTokenPermissionGroupId explicitly."
            );
          }
          return match.id;
        });

  const tokenResource = new cloudflare.AccountToken(
    "oof-ingest-token",
    {
      accountId,
      name: ingestTokenName,
      policies: [
        {
          effect: "allow",
          permissionGroups: [{ id: permissionGroupId }],
          resources: JSON.stringify({
            [`com.cloudflare.api.account.${accountId}`]: "*",
          }),
        },
      ],
    },
    { provider: cfProvider }
  );

  ingestTokenOutput = pulumi.secret(tokenResource.value);
}

let focusStream: BasinStructuredStream | undefined;
let focusSink: cloudflare.PipelineSink | undefined;
let focusPipeline: cloudflare.Pipeline | undefined;

if (enableFinops) {
  validateBasinSettings({
    accountId,
    catalogToken: "placeholder-validated-separately",
    apiBaseUrl,
    bucketName: bucketNameConfig,
    namespace: finopsNamespace,
    tableName: finopsTableName,
    streamName: finopsStreamNameConfig,
    sinkName: finopsSinkName,
    pipelineName: finopsPipelineName,
    rollIntervalSeconds,
    ingestTokenName,
  });
  if (finopsStreamNameConfig === streamNameConfig || finopsSinkName === sinkName) {
    throw new Error("FOCUS stream/sink names must be distinct from the OCSF stream/sink names.");
  }

  const focusSchemaFields = loadBasinSchemaFields(finopsSchemaFile);
  const renderedFocusSql = renderPipelineSql(
    finopsPipelineSqlFile,
    finopsSinkName,
    finopsStreamNameConfig
  );

  focusStream = new BasinStructuredStream("oof-focus-stream", {
    accountId,
    apiBaseUrl,
    name: finopsStreamNameConfig,
    format: {
      type: "json",
    },
    http: {
      enabled: true,
      authentication: true,
      cors: {
        origins: streamCorsOrigins,
      },
    },
    workerBinding: {
      enabled: false,
    },
    schema: {
      fields: focusSchemaFields,
    },
  });

  focusSink = new cloudflare.PipelineSink(
    "oof-focus-sink",
    {
      accountId,
      name: finopsSinkName,
      type: "r2_data_catalog",
      format: {
        type: "parquet",
      },
      config: {
        accountId,
        bucket: effectiveBucketName,
        namespace: finopsNamespace,
        tableName: finopsTableName,
        token: validatedCatalogToken,
        rollingPolicy: {
          intervalSeconds: rollIntervalSeconds,
        },
      },
    },
    {
      provider: cfProvider,
      dependsOn: sinkDependencies,
    }
  );

  focusPipeline = new cloudflare.Pipeline(
    "oof-focus-pipeline",
    {
      accountId,
      name: finopsPipelineName,
      sql: pulumi.interpolate`-- stream_id=${focusStream.id} sink_id=${focusSink.id}\n${renderedFocusSql}`,
    },
    {
      provider: cfProvider,
      dependsOn: [focusStream, focusSink],
      replaceOnChanges: ["sql"],
      deleteBeforeReplace: true,
    }
  );
}

const logpushJobResources: Record<string, pulumi.Output<string>> = {};
for (const [jobKey, job] of Object.entries(logpushJobsConfig)) {
  const scope = job.scope ?? "zone";
  const lpJob = new cloudflare.LogpushJob(
    `oof-logpush-${jobKey}`,
    {
      accountId: scope === "account" ? accountId : undefined,
      zoneId: scope === "zone" ? job.zoneId : undefined,
      name: job.name ?? jobKey,
      dataset: job.dataset,
      destinationConf: pulumi.secret(job.destinationConf),
      enabled: job.enabled ?? true,
      frequency: job.frequency ?? "high",
      filter: job.filter,
      outputOptions: job.outputOptions,
    },
    { provider: cfProvider }
  );
  logpushJobResources[jobKey] = lpJob.id;
}

export const bucketName = effectiveBucketName;
export const catalogId = catalog ? catalog.id : pulumi.output(undefined);
export const streamId = stream.id;
export const streamName = stream.name;
export const streamEndpoint = stream.endpoint;
export const streamHost = stream.endpoint.apply(extractHostFromEndpoint);
export const sinkId = sink.id;
export const pipelineId = pipeline.id;
export const ingestToken = ingestTokenOutput;
export const focusStreamId = focusStream ? focusStream.id : pulumi.output(undefined);
export const focusStreamName = focusStream ? focusStream.name : pulumi.output(undefined);
export const focusStreamEndpoint = focusStream ? focusStream.endpoint : pulumi.output(undefined);
export const focusStreamHost = focusStream
  ? focusStream.endpoint.apply(extractHostFromEndpoint)
  : pulumi.output(undefined);
export const focusSinkId = focusSink ? focusSink.id : pulumi.output(undefined);
export const focusPipelineId = focusPipeline ? focusPipeline.id : pulumi.output(undefined);
export const logpushJobIds = logpushJobResources;

let aiStream: BasinStructuredStream | undefined;
let aiSink: cloudflare.PipelineSink | undefined;
let aiPipeline: cloudflare.Pipeline | undefined;

if (enableAiUsage) {
  validateBasinSettings({
    accountId,
    catalogToken: "placeholder-validated-separately",
    apiBaseUrl,
    bucketName: bucketNameConfig,
    namespace: aiNamespace,
    tableName: aiTableName,
    streamName: aiStreamNameConfig,
    sinkName: aiSinkName,
    pipelineName: aiPipelineName,
    rollIntervalSeconds,
    ingestTokenName,
  });

  const aiSchemaFields = loadBasinSchemaFields(aiSchemaFile);
  const aiRenderedSql = renderPipelineSql(aiPipelineSqlFile, aiSinkName, aiStreamNameConfig);

  aiStream = new BasinStructuredStream("oof-ai-usage-stream", {
    accountId,
    apiBaseUrl,
    name: aiStreamNameConfig,
    format: {
      type: "json",
    },
    http: {
      enabled: true,
      authentication: true,
      cors: {
        origins: streamCorsOrigins,
      },
    },
    workerBinding: {
      enabled: false,
    },
    schema: {
      fields: aiSchemaFields,
    },
  });

  aiSink = new cloudflare.PipelineSink(
    "oof-ai-usage-sink",
    {
      accountId,
      name: aiSinkName,
      type: "r2_data_catalog",
      format: {
        type: "parquet",
      },
      config: {
        accountId,
        bucket: effectiveBucketName,
        namespace: aiNamespace,
        tableName: aiTableName,
        token: validatedCatalogToken,
        rollingPolicy: {
          intervalSeconds: rollIntervalSeconds,
        },
      },
    },
    {
      provider: cfProvider,
      dependsOn: sinkDependencies,
    }
  );

  aiPipeline = new cloudflare.Pipeline(
    "oof-ai-usage-pipeline",
    {
      accountId,
      name: aiPipelineName,
      sql: pulumi.interpolate`-- stream_id=${aiStream.id} sink_id=${aiSink.id}\n${aiRenderedSql}`,
    },
    {
      provider: cfProvider,
      dependsOn: [aiStream, aiSink],
      replaceOnChanges: ["sql"],
      deleteBeforeReplace: true,
    }
  );
}

export const aiStreamId = aiStream ? aiStream.id : pulumi.output(undefined);
export const aiStreamName = aiStream ? aiStream.name : pulumi.output(undefined);
export const aiStreamEndpoint = aiStream ? aiStream.endpoint : pulumi.output(undefined);
export const aiStreamHost = aiStream
  ? aiStream.endpoint.apply(extractHostFromEndpoint)
  : pulumi.output(undefined);
export const aiSinkId = aiSink ? aiSink.id : pulumi.output(undefined);
export const aiPipelineId = aiPipeline ? aiPipeline.id : pulumi.output(undefined);
