output "sns_topic_arn" {
  description = "SNS topic ARN for alerts."
  value       = aws_sns_topic.alerts.arn
}

output "cloudtrail_bucket_name" {
  description = "S3 bucket that stores CloudTrail logs."
  value       = aws_s3_bucket.cloudtrail.id
}

output "cloudtrail_log_group_name" {
  description = "CloudWatch Log Group for CloudTrail."
  value       = aws_cloudwatch_log_group.cloudtrail.name
}
