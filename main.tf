data "aws_iam_policy_document" "security_reporter_lambda_assume" {
  statement {
    effect = "Allow"

    actions = [
      "sts:AssumeRole",
    ]

    principals {
      type = "Service"

      identifiers = [
        "lambda.amazonaws.com",
      ]
    }
  }
}

resource "aws_iam_role" "security_reporter_lambda_role" {
  name               = "${var.security_reporter_lambda_name}-role"
  assume_role_policy = data.aws_iam_policy_document.security_reporter_lambda_assume.json
  description        = "IAM role for ${var.security_reporter_lambda_name}"

  tags = var.tags
}

data "aws_iam_policy_document" "security_reporter_lambda_policy_document" {
  statement {
    effect = "Allow"

    actions = [
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
      "cloudwatch:PutMetricData",
    ]

    resources = [
      "*",
    ]
  }



  statement {
    effect = "Allow"

    actions = [
      "securityhub:Get*",
      "securityhub:List*",
      "securityhub:Describe*",
    ]

    resources = [
      "*",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "ssm:GetParametersByPath"
    ]

    resources = [
      "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter${var.ps_root_path}*",
    ]
  }


  dynamic "statement" {
    for_each = var.sns_topic_arn != "DUMMY" ? [1] : []

    content {
      effect = "Allow"
      actions = [
        "sns:Publish",
      ]
      resources = [
        var.sns_topic_arn,
      ]
    }
  }
}

resource "aws_iam_role_policy" "security_reporter_lambda_role_policy" {
  name   = "${var.security_reporter_lambda_name}-policy"
  role   = aws_iam_role.security_reporter_lambda_role.name
  policy = data.aws_iam_policy_document.security_reporter_lambda_policy_document.json
}

data "archive_file" "security_reporter_lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/src"
  output_path = "${path.module}/${var.security_reporter_lambda_name}.zip"
}

resource "aws_lambda_function" "security_reporter_lambda" {
  function_name = var.security_reporter_lambda_name
  description   = "Function reports security problems not compliant with selected controls in AWS security baseline."
  filename      = data.archive_file.security_reporter_lambda_zip.output_path
  memory_size   = 128
  timeout       = 300

  runtime          = "python3.9"
  role             = aws_iam_role.security_reporter_lambda_role.arn
  source_code_hash = data.archive_file.security_reporter_lambda_zip.output_base64sha256
  handler          = "security_hub_reporter.lambda_handler"

  environment {
    variables = {
      METRICS_NAMESPACE                     = var.metrics_namespace
      SECURITY_CONTROLS                     = var.security_controls
      SNS_TOPIC_ARN                         = var.sns_topic_arn
      ACCOUNT_ID                            = data.aws_caller_identity.current.account_id
      ACCOUNT_ALIAS                         = data.aws_iam_account_alias.current.account_alias
      PUBLISH_OK_MESSAGE_TO_SLACK           = var.publish_ok_message_to_slack
      PS_ROOT_PATH                          = var.ps_root_path
      PS_KEY_CONTROLS_IDS_API_HOST          = var.ps_key_security_controls_api_host
      PS_KEY_CONTROLS_IDS_API_KEY           = var.ps_key_security_controls_api_key
      PS_KEY_CONTROLS_IDS_API_RESOURCE_PATH = var.ps_key_security_controls_api_resource_path

    }
  }

  tags = merge(var.tags, {
    Purpose = "For reporting compliance with selected controls in AWS security baseline."
  })
}

resource "aws_lambda_permission" "security_reporter_rule_permission" {
  statement_id  = "AllowExecutionFrom-${aws_cloudwatch_event_rule.security_reporter_rule.name}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_reporter_lambda.arn
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.security_reporter_rule.arn
}

resource "aws_cloudwatch_event_rule" "security_reporter_rule" {
  name                = "${var.security_reporter_lambda_name}-rule"
  schedule_expression = var.schedule_expression
  description         = "Rule firing security reporter lambda at a specific interval"
}

resource "aws_cloudwatch_event_target" "security_reporter_rule_target" {
  target_id = aws_lambda_function.security_reporter_lambda.function_name
  rule      = aws_cloudwatch_event_rule.security_reporter_rule.name
  arn       = aws_lambda_function.security_reporter_lambda.arn
}

resource "aws_ssm_parameter" "security_controls_api_host" {
  name  = "${var.ps_root_path}${var.ps_key_security_controls_api_host}"
  type  = "String"
  value = "NOT_SET"
  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "security_controls_api_key" {
  name  = "${var.ps_root_path}${var.ps_key_security_controls_api_key}"
  type  = "SecureString"
  value = "NOT_SET"
  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_ssm_parameter" "security_controls_api_resource_path" {
  name  = "${var.ps_root_path}${var.ps_key_security_controls_api_resource_path}"
  type  = "String"
  value = "NOT_SET"
  lifecycle {
    ignore_changes = [value]
  }
}

data "aws_caller_identity" "current" {}
data "aws_iam_account_alias" "current" {}
data "aws_region" "current" {}
