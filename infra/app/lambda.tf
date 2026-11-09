# Two functions from one package:
#   api    - FastAPI behind a function URL that only CloudFront can call (IAM auth + OAC).
#   worker - runs one audit; the API invokes it asynchronously.

locals {
  functions = {
    api    = { name = local.api_name, handler = "app.lambda_handler.api", memory = var.api_memory_mb, timeout = 20 }
    worker = { name = local.worker_name, handler = "app.lambda_handler.worker", memory = var.worker_memory_mb, timeout = var.scan_timeout_s + 60 }
  }

  app_env = {
    APP_MODE            = "public"
    RUNTIME             = "lambda"
    TABLE_NAME          = aws_dynamodb_table.main.name
    WORKER_FUNCTION     = local.worker_name
    LLM_API_KEY_PARAM   = var.llm_api_key_param
    CLIENT_IP_HEADER    = "cloudfront-viewer-address"
    LLM_BASE_URL        = var.llm_base_url
    MODEL               = var.model
    ENABLE_THINKING     = tostring(var.enable_thinking)
    MAX_TOKENS          = tostring(var.max_tokens)
    ENABLE_DYNAMIC      = "false"
    RATE_LIMIT_PER_HOUR = tostring(var.rate_limit_per_hour)
    DAILY_SCAN_CAP      = tostring(var.daily_scan_cap)
    MAX_RUNNING_SCANS   = tostring(var.max_running_scans)
    SCAN_TIMEOUT_S      = tostring(var.scan_timeout_s)
    MAX_SNIPPET_LINES   = tostring(var.max_snippet_lines)
    RESULT_TTL_HOURS    = tostring(var.result_ttl_hours)
    CACHE_TTL_HOURS     = tostring(var.cache_ttl_hours)
    DATA_DIR            = "/tmp/vibeaudit"
  }
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "fn" {
  for_each           = local.functions
  name               = "${var.name}-app-${each.key}"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "fn" {
  for_each = local.functions

  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.fn[each.key].arn}:*"]
  }
  statement {
    sid       = "Table"
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"]
    resources = [aws_dynamodb_table.main.arn]
  }
  statement {
    sid       = "ModelKey" # SecureString under the AWS-managed aws/ssm key: no KMS grant needed
    actions   = ["ssm:GetParameter"]
    resources = ["arn:aws:ssm:${var.region}:${local.account}:parameter/${trimprefix(var.llm_api_key_param, "/")}"]
  }
  dynamic "statement" {
    for_each = each.key == "api" ? [1] : []
    content {
      sid       = "StartWorker"
      actions   = ["lambda:InvokeFunction"]
      resources = ["arn:aws:lambda:${var.region}:${local.account}:function:${local.worker_name}"]
    }
  }
}

resource "aws_iam_role_policy" "fn" {
  for_each = local.functions
  name     = "runtime"
  role     = aws_iam_role.fn[each.key].id
  policy   = data.aws_iam_policy_document.fn[each.key].json
}

resource "aws_cloudwatch_log_group" "fn" {
  for_each          = local.functions
  name              = "/aws/lambda/${each.value.name}"
  retention_in_days = var.log_retention_days
}

resource "aws_lambda_function" "fn" {
  for_each         = local.functions
  function_name    = each.value.name
  role             = aws_iam_role.fn[each.key].arn
  handler          = each.value.handler
  runtime          = "python3.12"
  architectures    = [var.lambda_arch]
  filename         = var.lambda_zip
  source_code_hash = filebase64sha256(var.lambda_zip)
  memory_size      = each.value.memory
  timeout          = each.value.timeout

  reserved_concurrent_executions = each.key == "worker" ? var.worker_reserved_concurrency : -1

  environment {
    variables = local.app_env
  }

  logging_config {
    log_format = "Text"
    log_group  = aws_cloudwatch_log_group.fn[each.key].name
  }

  depends_on = [aws_cloudwatch_log_group.fn]
}

# A failed worker run is not retried: a retry would bill the model a second time.
resource "aws_lambda_function_event_invoke_config" "worker" {
  function_name                = aws_lambda_function.fn["worker"].function_name
  maximum_retry_attempts       = 0
  maximum_event_age_in_seconds = 900
}

resource "aws_lambda_function_url" "api" {
  function_name      = aws_lambda_function.fn["api"].function_name
  authorization_type = "AWS_IAM" # only CloudFront (signing via OAC) can call it
  invoke_mode        = "BUFFERED"
}

resource "aws_lambda_permission" "cloudfront_url" {
  statement_id           = "AllowCloudFrontInvokeFunctionUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.fn["api"].function_name
  principal              = "cloudfront.amazonaws.com"
  source_arn             = aws_cloudfront_distribution.site.arn
  function_url_auth_type = "AWS_IAM"
}

resource "aws_lambda_permission" "cloudfront_invoke" {
  statement_id  = "AllowCloudFrontInvokeFunction"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fn["api"].function_name
  principal     = "cloudfront.amazonaws.com"
  source_arn    = aws_cloudfront_distribution.site.arn
}
