output "site_url" {
  value = "https://${aws_cloudfront_distribution.site.domain_name}"
}

output "site_bucket" {
  value = aws_s3_bucket.site.bucket
}

output "distribution_id" {
  value = aws_cloudfront_distribution.site.id
}

output "api_function" {
  value = aws_lambda_function.fn["api"].function_name
}

output "worker_function" {
  value = aws_lambda_function.fn["worker"].function_name
}

output "table" {
  value = aws_dynamodb_table.main.name
}
