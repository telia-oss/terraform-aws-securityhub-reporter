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

  runtime          = "python3.8"
  role             = aws_iam_role.security_reporter_lambda_role.arn
  source_code_hash = data.archive_file.security_reporter_lambda_zip.output_base64sha256
  handler          = "security_hub_reporter.lambda_handler"

  environment {
    variables = {
      METRICS_NAMESPACE           = var.metrics_namespace
      SECURITY_CONTROLS           = var.security_controls
      SNS_TOPIC_ARN               = var.sns_topic_arn
      ACCOUNT_ID                  = data.aws_caller_identity.current.account_id
      ACCOUNT_ALIAS               = data.aws_iam_account_alias.current.account_alias
      PUBLISH_OK_MESSAGE_TO_SLACK = var.publish_ok_message_to_slack
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

data "aws_caller_identity" "current" {}
data "aws_iam_account_alias" "current" {}
