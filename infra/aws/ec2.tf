# The host: one Ubuntu 24.04 instance in the first public subnet, reached through Session Manager only. The first
# boot (user-data.sh.tftpl) installs Docker with the awslogs driver, the AWS CLI, the CloudWatch agent, mounts the
# data volume at /var/lib/docker and clones the repository; the operator then deploys (docs/operations.md §4.2).
#
# The data volume is separate from the root volume and protected against destruction: the instance can be replaced
# (a new Ubuntu, a change of the first-boot script) and the volume reattached with the database on it. Changes to
# the image and to the first-boot script are ignored on purpose; to apply them, replace the instance with
# `terraform apply -replace=aws_instance.host` after a backup.

resource "aws_ebs_volume" "data" {
  availability_zone = local.azs[0]
  size              = var.data_volume_gb
  type              = "gp3"
  encrypted         = true

  lifecycle {
    prevent_destroy = true
  }

  tags = { Name = "${var.project}-data" }
}

#trivy:ignore:AVD-AWS-0009 the host needs a public address because there is no NAT gateway (D33); no inbound port is open
resource "aws_instance" "host" {
  ami                         = nonsensitive(data.aws_ssm_parameter.ubuntu_ami.value)
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public[0].id
  vpc_security_group_ids      = [aws_security_group.host.id]
  iam_instance_profile        = aws_iam_instance_profile.host.name
  associate_public_ip_address = true
  ebs_optimized               = true

  # IMDSv2 only, and one hop: the containers cannot reach the instance's credentials.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type           = "gp3"
    volume_size           = var.root_volume_gb
    encrypted             = true
    delete_on_termination = true
  }

  user_data = templatefile("${path.module}/user-data.sh.tftpl", {
    region         = var.aws_region
    log_group      = local.log_group
    repository_url = var.repository_url
  })
  user_data_replace_on_change = false

  lifecycle {
    ignore_changes = [ami, user_data]
  }

  tags = { Name = "${var.project}-host" }
}

resource "aws_volume_attachment" "data" {
  device_name                    = "/dev/sdf"
  volume_id                      = aws_ebs_volume.data.id
  instance_id                    = aws_instance.host.id
  stop_instance_before_detaching = true
}
