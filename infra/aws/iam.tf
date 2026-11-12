# The host's role: what scripts/prod/*.sh, the Docker log driver, the CloudWatch agent and Session Manager need, and
# nothing more. No delete on the bucket, no parameter outside /secureflow/prod, no key use except through S3 and the
# parameter store, metrics in the two namespaces only. The managed policy AmazonSSMManagedInstanceCore is not used:
# it would allow reading every parameter of the account.

data "aws_iam_policy_document" "host_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "host" {
  name               = "${var.project}-host"
  assume_role_policy = data.aws_iam_policy_document.host_assume.json

  tags = { Name = "${var.project}-host" }
}

data "aws_iam_policy_document" "host" {
  # Session Manager (the only way onto the host). These actions take no resource.
  statement {
    sid    = "SessionManager"
    effect = "Allow"
    actions = [
      "ssm:UpdateInstanceInformation",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    resources = ["*"]
  }

  # scripts/prod/fetch-env.sh
  statement {
    sid     = "Parameters"
    effect  = "Allow"
    actions = ["ssm:GetParametersByPath"]
    resources = [
      "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter${local.parameter_path}",
      "arn:aws:ssm:${var.aws_region}:${local.account_id}:parameter${local.parameter_path}/*",
    ]
  }

  statement {
    sid    = "KeyThroughServices"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey",
    ]
    resources = [aws_kms_key.this.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values = [
        "ssm.${var.aws_region}.amazonaws.com",
        "s3.${var.aws_region}.amazonaws.com",
      ]
    }
  }

  # scripts/prod/backup.sh, restore.sh --from-s3, audit-anchor.sh: put and get under the two prefixes, list the bucket.
  statement {
    sid    = "Backups"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:GetObject",
    ]
    resources = [
      "${aws_s3_bucket.backups.arn}/dumps/*",
      "${aws_s3_bucket.backups.arn}/audit-heads/*",
    ]
  }

  statement {
    sid       = "ListBackups"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.backups.arn]
  }

  # The Docker daemon's awslogs driver (one stream per container in the group).
  statement {
    sid    = "ContainerLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "logs:DescribeLogStreams",
    ]
    resources = ["${aws_cloudwatch_log_group.containers.arn}:*"]
  }

  # scripts/prod/lib.sh put_metric (SecureFlow) and the CloudWatch agent (CWAgent). The action takes no resource.
  statement {
    sid       = "Metrics"
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["SecureFlow", "CWAgent"]
    }
  }
}

resource "aws_iam_role_policy" "host" {
  name   = "${var.project}-host"
  role   = aws_iam_role.host.id
  policy = data.aws_iam_policy_document.host.json
}

resource "aws_iam_instance_profile" "host" {
  name = "${var.project}-host"
  role = aws_iam_role.host.name
}
