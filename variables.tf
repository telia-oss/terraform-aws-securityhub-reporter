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
  description = "ARN of an SNS topic lambda will report the result to. If default value is not overridden, Slack integration will be disabled."
  type        = string
  default     = "DUMMY"
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

variable "ps_root_path" {
  description = "ssm parameters path under which the parameters are created."
  type        = string
  default     = "/SecurityReporter/"
}

variable "ps_key_security_controls_api_resource_path" {
  description = "Name of the SSM parameter where resource path to REST API returning controls ID is stored."
  type        = string
  default     = "securityControlsApiResourcePath"

}

variable "ps_key_security_controls_api_key" {
  description = "Name of the SSM parameter where api key to REST API returning controls ID is stored."
  type        = string
  default     = "securityControlsApiKey"
}

variable "ps_key_security_controls_api_host" {
  description = "Name of the SSM parameter where a host to REST API returning controls ID is stored."
  type        = string
  default     = "securityControlsApiHost"
}