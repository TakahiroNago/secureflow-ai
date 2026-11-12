# The bucket for the dumps (scripts/prod/backup.sh) and the audit heads (scripts/prod/audit-anchor.sh). Versioned, so
# that an overwritten head keeps its earlier versions; encrypted with the key; closed to the public; TLS only. The
# host's role may put, get and list (iam.tf) and cannot delete a version, which is what protects the heads against a
# database owner on the host (threat-model R-03). Object Lock is not used (decision 5 of step 5-2).

resource "aws_s3_bucket" "backups" {
  bucket = local.bucket_name

  lifecycle {
    prevent_destroy = true
  }

  tags = { Name = local.bucket_name }
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.this.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket = aws_s3_bucket.backups.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "backups" {
  bucket = aws_s3_bucket.backups.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id

  # A dump a day, kept for dump_retention_days, previous versions too.
  rule {
    id     = "dumps"
    status = "Enabled"

    filter {
      prefix = "dumps/"
    }

    expiration {
      days = var.dump_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.dump_retention_days
    }
  }

  # The heads stay; only versions replaced by an overwrite expire, after a year.
  rule {
    id     = "audit-heads"
    status = "Enabled"

    filter {
      prefix = "audit-heads/"
    }

    noncurrent_version_expiration {
      noncurrent_days = 365
    }
  }

  rule {
    id     = "incomplete-uploads"
    status = "Enabled"

    filter {}

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.backups]
}

data "aws_iam_policy_document" "backups_bucket" {
  statement {
    sid       = "TlsOnly"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.backups.arn, "${aws_s3_bucket.backups.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "backups" {
  bucket = aws_s3_bucket.backups.id
  policy = data.aws_iam_policy_document.backups_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.backups]
}
