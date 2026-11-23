output "bucket_name" {
  description = "R2 bucket backing the OCSF Iceberg tables."
  value       = local.bucket_name
}

output "catalog_id" {
  description = "R2 Data Catalog identifier (null when enable_catalog = false)."
  value       = var.enable_catalog ? cloudflare_r2_data_catalog.lake[0].id : null
}

output "stream_id" {
  description = "Provisioned Basin HTTP stream ID."
  value       = restful_resource.ocsf_stream.output.id
}

output "stream_name" {
  description = "Provisioned Basin HTTP stream SQL identifier."
  value       = restful_resource.ocsf_stream.output.name
}

output "stream_endpoint" {
  description = "Authenticated Basin HTTPS ingest URL (use for Vector OOF_BASIN_ENDPOINT)."
  value       = restful_resource.ocsf_stream.output.endpoint
}

output "stream_host" {
  description = "Hostname portion of stream_endpoint (use for Fluent Bit OOF_BASIN_HOST)."
  value       = regex("^https?://([^/]+)", restful_resource.ocsf_stream.output.endpoint)[0]
}

output "sink_id" {
  description = "Provisioned Basin R2 Data Catalog sink ID."
  value       = cloudflare_pipeline_sink.ocsf.id
}

output "pipeline_id" {
  description = "Provisioned Basin SQL pipeline ID."
  value       = cloudflare_pipeline.ocsf.id
}

output "ingest_token" {
  description = "Scoped Account API Token value for collector OOF_INGEST_TOKEN (only populated when create_ingest_token = true)."
  value       = var.create_ingest_token ? cloudflare_account_token.ingest[0].value : null
  sensitive   = true
}

output "logpush_job_ids" {
  description = "Map of provisioned Cloudflare Logpush job names to their numeric IDs (omits destination_conf secrets)."
  value = {
    for k, job in cloudflare_logpush_job.telemetry : k => job.id
  }
}

output "ai_stream_id" {
  description = "Provisioned Basin HTTP stream ID for AI usage telemetry (null when enable_ai_usage = false)."
  value       = var.enable_ai_usage ? restful_resource.ai_usage_stream[0].output.id : null
}

output "ai_stream_name" {
  description = "Provisioned Basin HTTP stream SQL identifier for AI usage telemetry (null when enable_ai_usage = false)."
  value       = var.enable_ai_usage ? restful_resource.ai_usage_stream[0].output.name : null
}

output "ai_stream_endpoint" {
  description = "Authenticated Basin HTTPS ingest URL for AI usage telemetry (use for Vector OOF_AI_BASIN_ENDPOINT)."
  value       = var.enable_ai_usage ? restful_resource.ai_usage_stream[0].output.endpoint : null
}

output "ai_stream_host" {
  description = "Hostname portion of ai_stream_endpoint (null when enable_ai_usage = false)."
  value       = var.enable_ai_usage ? regex("^https?://([^/]+)", restful_resource.ai_usage_stream[0].output.endpoint)[0] : null
}

output "ai_sink_id" {
  description = "Provisioned Basin R2 Data Catalog sink ID for AI usage telemetry (null when enable_ai_usage = false)."
  value       = var.enable_ai_usage ? cloudflare_pipeline_sink.ai_usage[0].id : null
}

output "ai_pipeline_id" {
  description = "Provisioned Basin SQL pipeline ID for AI usage telemetry (null when enable_ai_usage = false)."
  value       = var.enable_ai_usage ? cloudflare_pipeline.ai_usage[0].id : null
}
