import * as pulumi from "@pulumi/pulumi";
import * as cloudflare from "@pulumi/cloudflare";
import {
  BasinStructuredStream,
  DEFAULT_API_BASE_URL,
  extractHostFromEndpoint,
  loadBasinSchemaFields,
  renderPipelineSql,
  resolveDefaultRepoPaths,
  validateBasinSettings,
} from "./stream";

const config = new pulumi.Config();
const cfConfig = new pulumi.Config("cloudflare");

const accountId = config.require("accountId");
const catalogToken = config.requireSecret("catalogToken");
const apiToken = config.getSecret("apiToken") ?? cfConfig.getSecret("apiToken");
const apiBaseUrl =
  config.get("apiBaseUrl") ?? cfConfig.get("baseUrl") ?? DEFAULT_API_BASE_URL;

const bucketNameConfig = config.get("bucketName") ?? "oof-security-lake";
const createBucket = config.getBoolean("createBucket") ?? true;
const enableCatalog = config.getBoolean("enableCatalog") ?? true;
const namespace = config.get("namespace") ?? "ocsf";
const tableName = config.get("tableName") ?? "event_log_activity";
const streamNameConfig = config.get("streamName") ?? "oof_ocsf_event_log_activity_stream";
const sinkName = config.get("sinkName") ?? "oof_ocsf_event_log_activity_sink";
const pipelineName = config.get("pipelineName") ?? "oof_ocsf_event_log_activity_pipeline";
const rollIntervalSeconds = config.getNumber("rollIntervalSeconds") ?? 300;
const streamCorsOrigins = config.getObject<string[]>("streamCorsOrigins") ?? [];

const createIngestToken = config.getBoolean("createIngestToken") ?? false;
const ingestTokenName = config.get("ingestTokenName") ?? "oof-basin-ingest";
const ingestTokenPermissionGroupId = config.get("ingestTokenPermissionGroupId");

const defaults = resolveDefaultRepoPaths(__dirname);
const schemaFile = config.get("schemaFile") ?? defaults.schemaFile;
const pipelineSqlFile = config.get("pipelineSqlFile") ?? defaults.pipelineSqlFile;

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
  ...(apiToken ? { apiToken } : {}),
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
  ...(apiToken ? { apiToken } : {}),
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
    // Anchor replacement ordering when stream or sink IDs rotate.
    sql: pulumi.all([stream.id, sink.id]).apply(() => renderedSql),
  },
  {
    provider: cfProvider,
    dependsOn: [stream, sink],
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

export const bucketName = effectiveBucketName;
export const catalogId = catalog ? catalog.id : pulumi.output(undefined);
export const streamId = stream.id;
export const streamName = stream.name;
export const streamEndpoint = stream.endpoint;
export const streamHost = stream.endpoint.apply(extractHostFromEndpoint);
export const sinkId = sink.id;
export const pipelineId = pipeline.id;
export const ingestToken = ingestTokenOutput;
