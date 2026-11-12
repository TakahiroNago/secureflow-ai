# What the operator needs after an apply (docs/operations.md §6.2): the two DNS records to create, how to reach the
# host, and the names the scripts use.

output "acm_validation_records" {
  description = "The CNAME that validates the certificate. Create it at the DNS provider (Cloudflare: DNS only, no proxy), then set enable_https = true."
  value = [
    for option in aws_acm_certificate.this.domain_validation_options : {
      name  = option.resource_record_name
      type  = option.resource_record_type
      value = option.resource_record_value
    }
  ]
}

output "public_dns_record" {
  description = "The record that publishes the service, created at the DNS provider in step 5-4 (Cloudflare: DNS only, no proxy)."
  value = {
    name  = var.public_host
    type  = "CNAME"
    value = aws_lb.this.dns_name
  }
}

output "alb_dns_name" {
  description = "The load balancer's name, for a check before DNS: curl --resolve <public host>:443:<one of its addresses> (docs/operations.md §6.2, step 5)."
  value       = aws_lb.this.dns_name
}

output "https_enabled" {
  description = "Whether the HTTPS listener exists (enable_https)."
  value       = var.enable_https
}

output "instance_id" {
  description = "The host. Session: aws ssm start-session --target <id>"
  value       = aws_instance.host.id
}

output "backup_bucket" {
  description = "The bucket of the dumps and audit heads (BACKUP_BUCKET in the parameter store)."
  value       = aws_s3_bucket.backups.bucket
}

output "parameter_path" {
  description = "The parameter store path of the environment (put-secrets.sh, scripts/prod/fetch-env.sh)."
  value       = local.parameter_path
}

output "kms_key_alias" {
  description = "The key the secrets are stored with (put-secrets.sh --key-alias)."
  value       = aws_kms_alias.this.name
}

output "log_group" {
  description = "The container log group."
  value       = aws_cloudwatch_log_group.containers.name
}

output "alerts_topic_arn" {
  description = "The topic the alarms publish to. Its email subscription must be confirmed from the mail SNS sent."
  value       = aws_sns_topic.alerts.arn
}
