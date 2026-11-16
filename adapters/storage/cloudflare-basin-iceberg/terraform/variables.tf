variable "cloudflare_account_id" {
  type        = string
  description = "Cloudflare 32-character hexadecimal account ID."

  validation {
    condition     = can(regex("^[a-fA-F0-9]{32}$", var.cloudflare_account_id))
    error_message = "cloudflare_account_id must be a 32-character hexadecimal Cloudflare account ID."
  }
}

variable "cloudflare_api_token" {
  type        = string
  sensitive   = true
  description = "Cloudflare API token with R2, R2 Data Catalog, and Pipelines write permissions (prefer TF_VAR_cloudflare_api_token)."

  validation {
    condition     = can(regex("^[A-Za-z0-9_-]{40,}$", var.cloudflare_api_token))
    error_message = "cloudflare_api_token must be a valid Cloudflare API token (at least 40 [A-Za-z0-9_-] characters)."
  }
}

variable "catalog_token" {
  type        = string
  sensitive   = true
  description = "Cloudflare API token with R2 Data Catalog + R2 Storage write permissions used by the Basin Iceberg sink (prefer TF_VAR_catalog_token)."

  validation {
    condition     = length(trimspace(var.catalog_token)) > 0
    error_message = "catalog_token must not be empty."
  }
}

variable "cloudflare_api_base_url" {
  type        = string
  default     = "https://api.cloudflare.com/client/v4"
  description = "Cloudflare v4 REST API base URL (override only for local loopback mock tests)."

  validation {
    condition = can(regex(
      "^(https://[A-Za-z0-9.-]+(:[0-9]+)?|http://(127\\.0\\.0\\.1|localhost):[0-9]+)/client/v4$",
      var.cloudflare_api_base_url
    ))
    error_message = "cloudflare_api_base_url must end with /client/v4 and use https:// (or loopback http://127.0.0.1:<port> / http://localhost:<port> for local tests)."
  }
}

variable "bucket_name" {
  type        = string
  default     = "oof-telemetry"
  description = "Target Cloudflare R2 bucket name for Iceberg table storage."

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "bucket_name must be 3-63 lowercase DNS-label characters matching ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$."
  }
}

variable "create_bucket" {
  type        = bool
  default     = true
  description = "Whether Terraform/OpenTofu creates the R2 bucket (set false if reusing an existing bucket)."
}

variable "enable_catalog" {
  type        = bool
  default     = true
  description = "Whether Terraform/OpenTofu enables R2 Data Catalog on the target bucket."
}

variable "namespace" {
  type        = string
  default     = "siem"
  description = "Apache Iceberg namespace in R2 Data Catalog."

  validation {
    condition     = can(regex("^[A-Za-z_][A-Za-z0-9_]*$", var.namespace))
    error_message = "namespace must match ^[A-Za-z_][A-Za-z0-9_]*$."
  }
}

variable "table_name" {
  type        = string
  default     = "ocsf_event_log_activity"
  description = "Apache Iceberg table name for OCSF v1.3.0 Event Log Activity (1008)."

  validation {
    condition     = can(regex("^[A-Za-z_][A-Za-z0-9_]*$", var.table_name))
    error_message = "table_name must match ^[A-Za-z_][A-Za-z0-9_]*$."
  }
}

variable "stream_name" {
  type        = string
  default     = "ocsf_event_log_stream"
  description = "Basin SQL stream identifier (must match SQL identifier rules and differ from sink_name)."

  validation {
    condition     = can(regex("^[A-Za-z_][A-Za-z0-9_]*$", var.stream_name))
    error_message = "stream_name must match ^[A-Za-z_][A-Za-z0-9_]*$."
  }
}

variable "sink_name" {
  type        = string
  default     = "ocsf_event_log_sink"
  description = "Basin SQL sink identifier (must match SQL identifier rules and differ from stream_name)."

  validation {
    condition     = can(regex("^[A-Za-z_][A-Za-z0-9_]*$", var.sink_name))
    error_message = "sink_name must match ^[A-Za-z_][A-Za-z0-9_]*$."
  }
}

variable "pipeline_name" {
  type        = string
  default     = "ocsf_event_log_to_iceberg"
  description = "Basin Pipeline name."

  validation {
    condition     = can(regex("^[A-Za-z0-9_]+$", var.pipeline_name))
    error_message = "pipeline_name must match ^[A-Za-z0-9_]+$."
  }
}

variable "roll_interval_seconds" {
  type        = number
  default     = 300
  description = "Iceberg Parquet file rolling interval in seconds (minimum 60)."

  validation {
    condition     = var.roll_interval_seconds >= 60 && var.roll_interval_seconds <= 2147483647 && floor(var.roll_interval_seconds) == var.roll_interval_seconds
    error_message = "roll_interval_seconds must be an integer between 60 and 2147483647."
  }
}

variable "stream_cors_origins" {
  type        = list(string)
  default     = []
  description = "Optional CORS origins allowed on the authenticated Basin HTTP stream endpoint."
}

variable "create_ingest_token" {
  type        = bool
  default     = false
  description = "Optionally mint a scoped Account API Token with 'Pipelines Send' for collector ingestion (stored encrypted in state!)."
}

variable "ingest_token_name" {
  type        = string
  default     = "oof-basin-ingest"
  description = "Name of the collector ingest Account API Token when create_ingest_token = true."

  validation {
    condition     = length(trimspace(var.ingest_token_name)) > 0
    error_message = "ingest_token_name must not be empty."
  }
}

variable "ingest_token_permission_group_id" {
  type        = string
  default     = null
  nullable    = true
  description = "Optional explicit Cloudflare permission group ID for Pipelines Send (auto-discovered when null and create_ingest_token = true)."
}

variable "schema_file" {
  type        = string
  default     = ""
  description = "Optional override path to OCSF Basin schema JSON (defaults to contracts/ocsf/event-log-activity.basin.json)."
}

variable "pipeline_sql_file" {
  type        = string
  default     = ""
  description = "Optional override path to Basin pipeline SQL template (defaults to ../pipeline.sql)."
}
