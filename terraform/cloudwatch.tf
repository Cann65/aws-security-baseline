resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/baseline"
  retention_in_days = 90
}
