locals {
  schema_path       = var.schema_file != "" ? var.schema_file : "${path.module}/../../../../contracts/ocsf/event-log-activity.basin.json"
  pipeline_sql_path = var.pipeline_sql_file != "" ? var.pipeline_sql_file : "${path.module}/../pipeline.sql"

  ocsf_schema  = jsondecode(file(local.schema_path))
  rendered_sql = replace(replace(file(local.pipeline_sql_path), "__SINK_NAME__", var.sink_name), "__STREAM_NAME__", var.stream_name)

  focus_schema_path       = var.finops_schema_file != "" ? var.finops_schema_file : "${path.module}/../../../../contracts/focus/cost-and-usage.basin.json"
  focus_pipeline_sql_path = var.finops_pipeline_sql_file != "" ? var.finops_pipeline_sql_file : "${path.module}/../focus_pipeline.sql"

  focus_schema       = var.enable_finops ? jsondecode(file(local.focus_schema_path)) : null
  rendered_focus_sql = var.enable_finops ? replace(replace(file(local.focus_pipeline_sql_path), "__SINK_NAME__", var.finops_sink_name), "__STREAM_NAME__", var.finops_stream_name) : ""

  ai_schema_path       = var.ai_schema_file != "" ? var.ai_schema_file : "${path.module}/../../../../contracts/otel-genai/genai-usage.basin.json"
  ai_pipeline_sql_path = var.ai_pipeline_sql_file != "" ? var.ai_pipeline_sql_file : "${path.module}/../pipeline_ai_usage.sql"

  ai_usage_schema = var.enable_ai_usage ? jsondecode(file(local.ai_schema_path)) : null
  ai_rendered_sql = var.enable_ai_usage ? replace(replace(file(local.ai_pipeline_sql_path), "__SINK_NAME__", var.ai_sink_name), "__STREAM_NAME__", var.ai_stream_name) : ""

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

# Optional FOCUS v1.0 FinOps cost & usage stream / sink / pipeline (enable_finops = true)
resource "restful_resource" "focus_stream" {
  count = var.enable_finops ? 1 : 0

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
    name = var.finops_stream_name
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
      fields = local.focus_schema.fields
    }
  }
}

resource "cloudflare_pipeline_sink" "focus" {
  count = var.enable_finops ? 1 : 0

  account_id = var.cloudflare_account_id
  name       = var.finops_sink_name
  type       = "r2_data_catalog"

  format = {
    type = "parquet"
  }

  config = {
    account_id = var.cloudflare_account_id
    bucket     = local.bucket_name
    namespace  = var.finops_namespace
    table_name = var.finops_table_name
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

resource "cloudflare_pipeline" "focus" {
  count = var.enable_finops ? 1 : 0

  account_id = var.cloudflare_account_id
  name       = var.finops_pipeline_name
  sql        = local.rendered_focus_sql

  depends_on = [
    restful_resource.focus_stream,
    cloudflare_pipeline_sink.focus,
  ]

  lifecycle {
    replace_triggered_by = [
      restful_resource.focus_stream[0].id,
      cloudflare_pipeline_sink.focus[0].id,
    ]

    precondition {
      condition     = var.finops_stream_name != var.finops_sink_name
      error_message = "finops_stream_name and finops_sink_name must be distinct SQL identifiers."
    }

    precondition {
      condition     = var.finops_stream_name != var.stream_name && var.finops_sink_name != var.sink_name
      error_message = "FOCUS stream/sink names must be distinct from the OCSF stream/sink names."
    }
  }
}

resource "cloudflare_logpush_job" "telemetry" {
  for_each = toset(nonsensitive(keys(var.logpush_jobs)))

  account_id       = var.logpush_jobs[each.key].scope == "account" ? var.cloudflare_account_id : null
  zone_id          = var.logpush_jobs[each.key].scope == "zone" ? var.logpush_jobs[each.key].zone_id : null
  name             = coalesce(var.logpush_jobs[each.key].name, each.key)
  dataset          = var.logpush_jobs[each.key].dataset
  destination_conf = var.logpush_jobs[each.key].destination_conf
  enabled          = var.logpush_jobs[each.key].enabled
  frequency        = var.logpush_jobs[each.key].frequency
  filter           = var.logpush_jobs[each.key].filter
  output_options   = var.logpush_jobs[each.key].output_options
}

# Optional OTel GenAI coding-agent usage stream / sink / pipeline (enable_ai_usage = true)
resource "restful_resource" "ai_usage_stream" {
  count = var.enable_ai_usage ? 1 : 0

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
    name = var.ai_stream_name
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
      fields = local.ai_usage_schema.fields
    }
  }
}

resource "cloudflare_pipeline_sink" "ai_usage" {
  count = var.enable_ai_usage ? 1 : 0

  account_id = var.cloudflare_account_id
  name       = var.ai_sink_name
  type       = "r2_data_catalog"

  format = {
    type = "parquet"
  }

  config = {
    account_id = var.cloudflare_account_id
    bucket     = local.bucket_name
    namespace  = var.ai_namespace
    table_name = var.ai_table_name
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

resource "cloudflare_pipeline" "ai_usage" {
  count = var.enable_ai_usage ? 1 : 0

  account_id = var.cloudflare_account_id
  name       = var.ai_pipeline_name
  sql        = local.ai_rendered_sql

  depends_on = [
    restful_resource.ai_usage_stream,
    cloudflare_pipeline_sink.ai_usage,
  ]

  lifecycle {
    replace_triggered_by = [
      restful_resource.ai_usage_stream[0].id,
      cloudflare_pipeline_sink.ai_usage[0].id,
    ]

    precondition {
      condition     = var.ai_stream_name != var.ai_sink_name
      error_message = "ai_stream_name and ai_sink_name must be distinct SQL identifiers."
    }
  }
}
