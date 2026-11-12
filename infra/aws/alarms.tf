# The alarms and where they go (docs/operations.md §4.7). Every alarm notifies the one topic, whose subscriber is the
# operator's address; the subscription is confirmed from the mail SNS sends. Alarms also notify when they clear.
#
# Three kinds of source: the log filters (logs.tf), the metrics the host's scripts publish (SecureFlow namespace, once
# a day: "no data" is itself a failure, noticed about two days after the timers stop), and the load balancer, the
# instance and the CloudWatch agent.

resource "aws_sns_topic" "alerts" {
  name              = "${var.project}-alerts"
  kms_master_key_id = aws_kms_key.this.id

  tags = { Name = "${var.project}-alerts" }
}

data "aws_iam_policy_document" "alerts_topic" {
  statement {
    sid       = "CloudWatchAlarms"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.alerts_topic.json
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

locals {
  notify = [aws_sns_topic.alerts.arn]

  # From the log filters: the key is the filter's name in metric-filters.json.
  log_alarms = {
    AuditUnavailable = {
      description = "The audit log is unavailable (audit.unavailable value=1, or its state cannot be read). Highest."
      comparison  = "GreaterThanOrEqualToThreshold"
      threshold   = 1
      period      = 60
      periods     = 1
      missing     = "notBreaching"
    }
    AuditGauge = {
      description = "The audit:housekeeping gauge was not seen for 5 minutes: the scheduler, the application or the log pipeline is down. No signal does not mean healthy."
      comparison  = "LessThanThreshold"
      threshold   = 1
      period      = 300
      periods     = 1
      missing     = "breaching"
    }
    DbSuspected = {
      description = "An audit outage whose storage scope is db_suspected. Highest; do not restart the containers (docs/security-design.md §16.5)."
      comparison  = "GreaterThanOrEqualToThreshold"
      threshold   = 1
      period      = 60
      periods     = 1
      missing     = "notBreaching"
    }
    OutageStarted = {
      description = "An outage started (audit, database or a readiness dependency)."
      comparison  = "GreaterThanOrEqualToThreshold"
      threshold   = 1
      period      = 60
      periods     = 1
      missing     = "notBreaching"
    }
    RecordingFailed = {
      description = "An audit record, a suppression total, a verification or a security signal could not be recorded (docs/security-design.md §16.5.3)."
      comparison  = "GreaterThanOrEqualToThreshold"
      threshold   = 1
      period      = 60
      periods     = 1
      missing     = "notBreaching"
    }
    LogCritical = {
      description = "Any line at CRITICAL or above from a container."
      comparison  = "GreaterThanOrEqualToThreshold"
      threshold   = 1
      period      = 60
      periods     = 1
      missing     = "notBreaching"
    }
    LogError = {
      description = "Five or more ERROR lines in five minutes."
      comparison  = "GreaterThanOrEqualToThreshold"
      threshold   = 5
      period      = 300
      periods     = 1
      missing     = "notBreaching"
    }
  }

  # From scripts/prod/lib.sh put_metric, once a day.
  script_alarms = {
    AuditVerifyFailed = "audit:verify failed against the stored anchor, or did not run for about two days (scripts/prod/audit-anchor.sh)."
    AuditAnchorFailed = "The audit head could not be stored in S3, or the anchor job did not run for about two days."
    BackupFailed      = "The daily dump failed or was not uploaded, or the backup job did not run for about two days (scripts/prod/backup.sh)."
  }
}

resource "aws_cloudwatch_metric_alarm" "logs" {
  for_each = local.log_alarms

  alarm_name          = "${var.project}-${each.key}"
  alarm_description   = each.value.description
  namespace           = "SecureFlow/Logs"
  metric_name         = each.key
  statistic           = "Sum"
  period              = each.value.period
  evaluation_periods  = each.value.periods
  datapoints_to_alarm = each.value.periods
  comparison_operator = each.value.comparison
  threshold           = each.value.threshold
  treat_missing_data  = each.value.missing
  alarm_actions       = local.notify
  ok_actions          = local.notify

  depends_on = [aws_cloudwatch_log_metric_filter.this]
}

resource "aws_cloudwatch_metric_alarm" "scripts" {
  for_each = local.script_alarms

  alarm_name          = "${var.project}-${each.key}"
  alarm_description   = each.value
  namespace           = "SecureFlow"
  metric_name         = each.key
  statistic           = "Maximum"
  period              = 86400
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "breaching"
  alarm_actions       = local.notify
  ok_actions          = local.notify
}

resource "aws_cloudwatch_metric_alarm" "alb_unhealthy" {
  alarm_name          = "${var.project}-AlbUnhealthyHost"
  alarm_description   = "The load balancer sees the host unhealthy for two minutes. If liveness answers 504, suspect php-fpm worker exhaustion (§22 A-3)."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "UnHealthyHostCount"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.notify
  ok_actions          = local.notify

  dimensions = {
    LoadBalancer = aws_lb.this.arn_suffix
    TargetGroup  = aws_lb_target_group.host.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_target_5xx" {
  alarm_name          = "${var.project}-AlbTarget5xx"
  alarm_description   = "Ten or more 5xx answers from the application in five minutes."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_Target_5XX_Count"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 10
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.notify
  ok_actions          = local.notify

  dimensions = {
    LoadBalancer = aws_lb.this.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "alb_elb_5xx" {
  alarm_name          = "${var.project}-AlbElb5xx"
  alarm_description   = "Ten or more 5xx answers from the load balancer itself in five minutes (the host did not answer, or not in time)."
  namespace           = "AWS/ApplicationELB"
  metric_name         = "HTTPCode_ELB_5XX_Count"
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 10
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.notify
  ok_actions          = local.notify

  dimensions = {
    LoadBalancer = aws_lb.this.arn_suffix
  }
}

resource "aws_cloudwatch_metric_alarm" "instance_status" {
  alarm_name          = "${var.project}-InstanceStatusCheck"
  alarm_description   = "The instance or the system status check fails for two minutes."
  namespace           = "AWS/EC2"
  metric_name         = "StatusCheckFailed"
  statistic           = "Maximum"
  period              = 60
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 1
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.notify
  ok_actions          = local.notify

  dimensions = {
    InstanceId = aws_instance.host.id
  }
}

resource "aws_cloudwatch_metric_alarm" "disk" {
  for_each = toset(["/", "/var/lib/docker"])

  alarm_name          = "${var.project}-Disk${each.value == "/" ? "Root" : "Data"}"
  alarm_description   = "${each.value} is 80% full (threat-model R-18: before the WAL runs out of space)."
  namespace           = "CWAgent"
  metric_name         = "disk_used_percent"
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  datapoints_to_alarm = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 80
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.notify
  ok_actions          = local.notify

  dimensions = {
    InstanceId = aws_instance.host.id
    path       = each.value
  }
}

resource "aws_cloudwatch_metric_alarm" "memory" {
  alarm_name          = "${var.project}-Memory"
  alarm_description   = "Memory is 90% used for ten minutes."
  namespace           = "CWAgent"
  metric_name         = "mem_used_percent"
  statistic           = "Average"
  period              = 300
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  comparison_operator = "GreaterThanOrEqualToThreshold"
  threshold           = 90
  treat_missing_data  = "notBreaching"
  alarm_actions       = local.notify
  ok_actions          = local.notify

  dimensions = {
    InstanceId = aws_instance.host.id
  }
}
