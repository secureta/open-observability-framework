import * as pulumi from "@pulumi/pulumi";
import {
  BasinStructuredStreamProvider,
  DEFAULT_API_BASE_URL,
  type BasinStreamFormat,
  type BasinStreamHttpConfig,
  type BasinStreamSchema,
  type BasinStreamWorkerBinding,
  type BasinStructuredStreamInputs,
  type BasinStructuredStreamState,
} from "./basin-core";

export {
  DEFAULT_API_BASE_URL,
  BasinStructuredStreamProvider,
  canonicalJson,
  extractHostFromEndpoint,
  loadBasinSchemaFields,
  renderPipelineSql,
  resolveDefaultRepoPaths,
  validateBasinSettings,
  type BasinField,
  type BasinSettingsValidationInput,
  type BasinStreamFormat,
  type BasinStreamHttpConfig,
  type BasinStreamSchema,
  type BasinStreamWorkerBinding,
  type BasinStructuredStreamInputs,
  type BasinStructuredStreamState,
} from "./basin-core";

export interface BasinStructuredStreamArgs {
  accountId: pulumi.Input<string>;
  apiBaseUrl?: pulumi.Input<string>;
  apiToken?: pulumi.Input<string>;
  name: pulumi.Input<string>;
  format: pulumi.Input<BasinStreamFormat>;
  http: pulumi.Input<BasinStreamHttpConfig>;
  workerBinding: pulumi.Input<BasinStreamWorkerBinding>;
  schema: pulumi.Input<BasinStreamSchema>;
}

/**
 * Pulumi dynamic resource managing Cloudflare Basin Pipelines streams directly over REST v4
 * so recursive `type: "struct"` OCSF schema fields are preserved verbatim.
 */
export class BasinStructuredStream extends pulumi.dynamic.Resource {
  public readonly accountId!: pulumi.Output<string>;
  public readonly apiBaseUrl!: pulumi.Output<string>;
  public readonly name!: pulumi.Output<string>;
  public readonly endpoint!: pulumi.Output<string>;
  public readonly version!: pulumi.Output<number>;

  constructor(
    resourceName: string,
    args: BasinStructuredStreamArgs,
    opts?: pulumi.CustomResourceOptions
  ) {
    const provider: pulumi.dynamic.ResourceProvider<
      BasinStructuredStreamInputs,
      BasinStructuredStreamState
    > = new BasinStructuredStreamProvider();

    super(
      provider,
      resourceName,
      {
        accountId: args.accountId,
        apiBaseUrl: args.apiBaseUrl ?? DEFAULT_API_BASE_URL,
        ...(args.apiToken !== undefined ? { apiToken: pulumi.secret(args.apiToken) } : {}),
        name: args.name,
        format: args.format,
        http: args.http,
        workerBinding: args.workerBinding,
        schema: args.schema,
        endpoint: undefined,
        version: undefined,
      },
      opts
    );
  }
}
