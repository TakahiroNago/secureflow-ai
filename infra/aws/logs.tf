# The container logs and what is counted in them (docs/operations.md §4.7, docs/security-design.md §22 A-4).
# The Docker daemon on the host writes every container's stdout and stderr to this group, one stream per container.
# The application's lines are JSON (LOG_STDERR_FORMATTER in compose.prod.yaml), so the filters select on the fields
# the code writes: context.metric, context.value, context.storage_scope and the level. The patterns and sample
# lines are in metric-filters.json, which test-metric-filters.sh checks against the real CloudWatch parser.

resource "aws_cloudwatch_log_group" "containers" {
  name              = local.log_group
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.this.arn

  tags = { Name = local.log_group }
}

resource "aws_cloudwatch_log_metric_filter" "this" {
  for_each = local.filters

  name           = "${var.project}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.containers.name
  pattern        = each.value.pattern

  metric_transformation {
    name          = each.key
    namespace     = "SecureFlow/Logs"
    value         = "1"
    default_value = "0"
    unit          = "Count"
  }
}
