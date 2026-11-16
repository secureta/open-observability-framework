locals {
  schema_path       = var.schema_file != "" ? var.schema_file : "${path.module}/../../../../contracts/ocsf/event-log-activity.basin.json"
  pipeline_sql_path = var.pipeline_sql_file != "" ? var.pipeline_sql_file : "${path.module}/../pipeline.sql"

  ocsf_schema  = jsondecode(file(local.schema_path))
  rendered_sql = replace(replace(file(local.pipeline_sql_path), "__SINK_NAME__", var.sink_name), "__STREAM_NAME__", var.stream_name)

  bucket_name = var.create_bucket ? cloudflare_r2_bucket.lake[0].name : var.bucket_name

  discovered_ingest_permission_group_ids = var.create_ingest_token && var.ingest_token_permission_group_id == null ? [
    for g in data.cloudflare_account_api_token_permission_groups_list.account[0].result :
    g.id if contains(["Pipelines Send", "Basin Pipelines Send"], g.name) && coalesce(try(g.is_selectable, null), true)
  ] : []

  resolved_ingest_permission_group_id = (
    var.ingest_token_permission_group_id != null
    ? var.ingest_token_permission_group_id
    : try(local.discovered_ingest_permission_group_ids[0], null)
  )
}

resource "cloudflare_r2_bucket" "lake" {
  count = var.create_bucket ? 1 : 0

  account_id = var.cloudflare_account_id
  name       = var.bucket_name
}

resource "cloudflare_r2_data_catalog" "lake" {
  count = var.enable_catalog ? 1 : 0

  account_id  = var.cloudflare_account_id
  bucket_name = local.bucket_name
}

# Managed via magodo/restful because cloudflare_pipeline_stream v5.x drops nested `type = "struct"`
# from its schema validation, whereas Basin REST API preserves full OCSF struct columns natively.
resource "restful_resource" "ocsf_stream" {
  path            = "/accounts/${var.cloudflare_account_id}/pipelines/v1/streams"
  read_path       = "$(path)/$(body.id)"
  update_path     = "$(path)/$(body.id)"
  delete_path     = "$(path)/$(body.id)"
  update_method   = "PATCH"
  create_selector = "result"
  read_selector   = "result"
  force_new_attrs = ["name", "format", "schema"]
  output_attrs    = ["id", "name", "endpoint", "version"]

  body = {
    name = var.stream_name
    format = {
      type = "json"
    }
    http = {
      enabled        = true
      authentication = true
      cors = {
        origins = var.stream_cors_origins
      }
    }
    worker_binding = {
      enabled = false
    }
    schema = {
      fields = local.ocsf_schema.fields
    }
  }
}

resource "cloudflare_pipeline_sink" "ocsf" {
  account_id = var.cloudflare_account_id
  name       = var.sink_name
  type       = "r2_data_catalog"

  format = {
    type = "parquet"
  }

  config = {
    account_id = var.cloudflare_account_id
    bucket     = local.bucket_name
    namespace  = var.namespace
    table_name = var.table_name
    token      = var.catalog_token
    rolling_policy = {
      interval_seconds = var.roll_interval_seconds
    }
  }

  depends_on = [
    cloudflare_r2_bucket.lake,
    cloudflare_r2_data_catalog.lake,
  ]
}

resource "cloudflare_pipeline" "ocsf" {
  account_id = var.cloudflare_account_id
  name       = var.pipeline_name
  sql        = local.rendered_sql

  depends_on = [
    restful_resource.ocsf_stream,
    cloudflare_pipeline_sink.ocsf,
  ]

  lifecycle {
    replace_triggered_by = [
      restful_resource.ocsf_stream.id,
      cloudflare_pipeline_sink.ocsf.id,
    ]

    precondition {
      condition     = var.stream_name != var.sink_name
      error_message = "stream_name and sink_name must be distinct SQL identifiers."
    }
  }
}

data "cloudflare_account_api_token_permission_groups_list" "account" {
  count = var.create_ingest_token && var.ingest_token_permission_group_id == null ? 1 : 0

  account_id = var.cloudflare_account_id
}

resource "cloudflare_account_token" "ingest" {
  count = var.create_ingest_token ? 1 : 0

  account_id = var.cloudflare_account_id
  name       = var.ingest_token_name

  policies = [
    {
      effect = "allow"
      permission_groups = [
        {
          id = coalesce(local.resolved_ingest_permission_group_id, "missing")
        }
      ]
      resources = jsonencode({
        "com.cloudflare.api.account.${var.cloudflare_account_id}" = "*"
      })
    }
  ]

  lifecycle {
    precondition {
      condition     = local.resolved_ingest_permission_group_id != null
      error_message = "Could not resolve 'Pipelines Send' permission group ID; set ingest_token_permission_group_id explicitly."
    }
  }
}
