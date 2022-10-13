terraform {
  required_version = ">= 0.13"
}

provider "aws" {
  region = var.region
}

module "securityhub-reporter" {
  source = "../"

  security_controls             = "S3.2, S3.3, S3.8"
  security_reporter_lambda_name = "security-reporter-lambda"
  sns_topic_arn                 = "arn:aws:sns:{region}:{accountId}:{topicName}"
  schedule_expression           = "rate(1 day)"
}
