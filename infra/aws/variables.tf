# Inputs. The values that are not secret and not the operator's live in terraform.tfvars.example; the operator's own
# copy (terraform.tfvars: the alert address, the profile) is ignored by git.

variable "aws_region" {
  description = "The region. Tokyo (D33)."
  type        = string
  default     = "ap-northeast-1"
}

variable "aws_profile" {
  description = "The AWS CLI profile to apply with. Null uses the environment (AWS_PROFILE or the default credentials)."
  type        = string
  default     = null
}

variable "project" {
  description = "Prefix of every resource name, and the compose project name on the host (COMPOSE_PROJECT_NAME)."
  type        = string
  default     = "secureflow-prod"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,30}$", var.project))
    error_message = "Lowercase letters, digits and hyphens, 2 to 31 characters."
  }
}

variable "public_host" {
  description = "The public host name (PUBLIC_HOST, the certificate's name, the CNAME the operator creates at the DNS provider)."
  type        = string

  validation {
    condition     = can(regex("^([a-z0-9]([a-z0-9-]*[a-z0-9])?\\.)+[a-z]{2,}$", var.public_host))
    error_message = "A lowercase host name such as secureflow.example.com, without a scheme, port or path."
  }
}

variable "alert_email" {
  description = "Where the alarms and the budget notifications go. Confirm the SNS subscription from the mail it sends."
  type        = string
  sensitive   = true

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "One email address."
  }
}

variable "enable_https" {
  description = <<-EOT
    False on the first apply: the certificate is requested and its validation record is in the outputs. Set it to true
    once that CNAME exists at the DNS provider; the next apply waits for the certificate and creates the HTTPS listener
    (docs/operations.md §6.2).
  EOT
  type        = bool
  default     = false
}

variable "instance_type" {
  description = "t3.small to start; t3.medium if the measurements of step 5-3 ask for it (in place: the instance stops and starts)."
  type        = string
  default     = "t3.small"
}

variable "root_volume_gb" {
  description = "The root volume (the OS, Docker and the agents). gp3, encrypted."
  type        = number
  default     = 16
}

variable "data_volume_gb" {
  description = "The separate volume mounted at /var/lib/docker (the database and Redis volumes). It survives a replacement of the instance."
  type        = number
  default     = 20
}

variable "vpc_cidr" {
  description = "The VPC. Its value is also TRUSTED_PROXY_CIDR: the load balancer's addresses are in it and nothing else reaches the host's port 80."
  type        = string
  default     = "10.0.0.0/16"
}

variable "repository_url" {
  description = "The public repository the host clones to /opt/secureflow at first boot (scripts/prod/deploy.sh checks out the release tags from it)."
  type        = string
  default     = "https://github.com/TakahiroNago/secureflow-ai.git"
}

variable "log_retention_days" {
  description = "Retention of the container log group (docs/operations.md §4.7: 90 days)."
  type        = number
  default     = 90
}

variable "dump_retention_days" {
  description = "How long a database dump stays in the bucket (current and previous versions). Audit heads are kept."
  type        = number
  default     = 35
}

variable "monthly_budget_usd" {
  description = "The monthly budget; a mail at 80% of it and when the forecast exceeds it."
  type        = number
  default     = 60
}

variable "deletion_protection" {
  description = "Deletion protection on the load balancer. The bucket and the data volume are protected by lifecycle rules whatever this says."
  type        = bool
  default     = true
}
