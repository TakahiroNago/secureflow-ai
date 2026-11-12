# The parameter store: what scripts/prod/fetch-env.sh turns into /etc/secureflow/.env (docs/operations.md §3.1).
# Terraform writes the values that are not secret. The secrets (APP_KEY and the passwords) are written once by
# put-secrets.sh as SecureString under the same path and never pass through Terraform or its state.

locals {
  parameters = {
    APP_ENV                   = "production"
    APP_URL                   = "https://${var.public_host}"
    PUBLIC_HOST               = var.public_host
    TRUSTED_PROXY_CIDR        = var.vpc_cidr
    NGINX_BIND                = "0.0.0.0"
    NGINX_PORT                = "80"
    COMPOSE_PROJECT_NAME      = var.project
    BACKUP_BUCKET             = aws_s3_bucket.backups.bucket
    AI_PROVIDER               = "mock"
    LOG_LEVEL                 = "info"
    DB_DATABASE               = "secureflow"
    DB_TEST_DATABASE          = "secureflow_test"
    DB_USERNAME               = "secureflow_app"
    DB_MIGRATOR_USERNAME      = "secureflow_owner"
    DB_TEST_USERNAME          = "secureflow_test_app"
    DB_TEST_MIGRATOR_USERNAME = "secureflow_test_owner"
  }
}

resource "aws_ssm_parameter" "config" {
  for_each = local.parameters

  name  = "${local.parameter_path}/${each.key}"
  type  = "String"
  value = each.value
  tier  = "Standard"

  tags = { Name = each.key }
}
