variable "aws_region" {
  description = "AWS region for this project (Frankfurt)."
  type        = string
  default     = "eu-central-1"
}

variable "aws_profile" {
  description = "AWS CLI profile name (SSO) used by Terraform."
  type        = string
  default     = "cann65-adminaccess"
}

variable "alert_email" {
  description = "Email address that receives SNS alerts (must confirm subscription)."
  type        = string
}
