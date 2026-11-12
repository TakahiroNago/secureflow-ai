# One customer managed key for what this environment stores outside the host: the dumps and audit heads in S3, the
# secrets in the parameter store, the container logs and the alert topic. The host's role may decrypt and generate
# data keys only through S3 and the parameter store (iam.tf); the services get the permissions below.

data "aws_iam_policy_document" "kms" {
  statement {
    sid       = "AccountAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid    = "CloudWatchLogs"
    effect = "Allow"
    actions = [
      "kms:Encrypt*",
      "kms:Decrypt*",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${local.account_id}:log-group:/${var.project}/*"]
    }
  }

  # The alarms publish to the encrypted topic, and SNS decrypts to deliver.
  statement {
    sid    = "AlarmsAndNotifications"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com", "sns.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_kms_key" "this" {
  description             = "SecureFlow ${var.project}: backups, parameters, logs and alerts"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.kms.json

  tags = { Name = var.project }
}

resource "aws_kms_alias" "this" {
  name          = "alias/${var.project}"
  target_key_id = aws_kms_key.this.key_id
}
