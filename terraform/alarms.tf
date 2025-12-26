############################################
# Root login detected (high signal)
############################################
resource "aws_cloudwatch_log_metric_filter" "root_login" {
  name           = "baseline-root-login"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  # Detect only successful root console logins (no false positives)
  pattern = "{ ($.eventName = \"ConsoleLogin\") && ($.userIdentity.type = \"Root\") && ($.responseElements.ConsoleLogin = \"Success\") }"

  metric_transformation {
    name      = "RootLoginCount"
    namespace = "Baseline/Security"
    value     = "1"
  }
}


resource "aws_cloudwatch_metric_alarm" "root_login" {
  alarm_name          = "baseline-root-login-alarm"
  alarm_description   = "Triggers when an interactive root login is detected."
  namespace           = "Baseline/Security"
  metric_name         = aws_cloudwatch_log_metric_filter.root_login.metric_transformation[0].name
  statistic           = "Sum"
  period              = 60
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}

############################################
# IAM changes detected (high signal)
############################################
resource "aws_cloudwatch_log_metric_filter" "iam_changes" {
  name           = "baseline-iam-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name

  # High-signal IAM changes (user/role/policy/access key changes)
  pattern = "{ ($.eventSource = \"iam.amazonaws.com\") && ((($.eventName = \"CreateUser\") || ($.eventName = \"DeleteUser\") || ($.eventName = \"CreateRole\") || ($.eventName = \"DeleteRole\") || ($.eventName = \"AttachUserPolicy\") || ($.eventName = \"DetachUserPolicy\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"DetachRolePolicy\") || ($.eventName = \"PutUserPolicy\") || ($.eventName = \"DeleteUserPolicy\") || ($.eventName = \"PutRolePolicy\") || ($.eventName = \"DeleteRolePolicy\") || ($.eventName = \"CreatePolicy\") || ($.eventName = \"DeletePolicy\") || ($.eventName = \"CreateAccessKey\") || ($.eventName = \"DeleteAccessKey\"))) }"

  metric_transformation {
    name      = "IamChangeCount"
    namespace = "Baseline/Security"
    value     = "1"
  }
}


resource "aws_cloudwatch_metric_alarm" "iam_changes" {
  alarm_name          = "baseline-iam-changes-alarm"
  alarm_description   = "Triggers on any IAM change detected in CloudTrail logs."
  namespace           = "Baseline/Security"
  metric_name         = aws_cloudwatch_log_metric_filter.iam_changes.metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.alerts.arn]
}
