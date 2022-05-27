variable "tags" {
  description = "A map of tags (key-value pairs) passed to resources."
  type        = map(string)
  default     = {}
}

variable "schedule_expression" {
  description = "Schedule expression for cloudwatch rule"
  type        = string
}

variable "metrics_namespace" {
  description = "Cloudwatch metric namespace for custom metric."
  type        = string
  default     = "Security"
}

variable "security_reporter_lambda_name" {
  description = "Name of the security reporter lambda and it's role."
  type        = string
}

variable "sns_topic_arn" {
  description = "ARN of an SNS topic lambda will report the result to."
  type        = string
}

variable "security_controls" {
  description = "Comma separated list of controls that should be checked."
  type        = string
}

variable "publish_ok_message_to_slack" {
  description = "If set to true, Lambda will publish message to Slack even if no issues were found."
  type        = bool
  default     = false
}
