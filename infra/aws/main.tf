# Shared data and names.

data "aws_caller_identity" "current" {}

data "aws_availability_zones" "available" {
  state = "available"
}

# Canonical's current Ubuntu 24.04 LTS image for the region. It moves with time; the instance ignores the change
# (ec2.tf), so a later apply does not replace the host by itself.
data "aws_ssm_parameter" "ubuntu_ami" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  # The load balancer needs two availability zones; the host is in the first.
  azs            = slice(data.aws_availability_zones.available.names, 0, 2)
  log_group      = "/${var.project}/containers"
  parameter_path = "/secureflow/prod"
  bucket_name    = "${var.project}-backups-${local.account_id}"
  # The log filters and their sample lines (metric-filters.json) are shared with test-metric-filters.sh.
  filters = jsondecode(file("${path.module}/metric-filters.json")).filters
}
