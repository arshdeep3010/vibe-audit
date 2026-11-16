output "state_bucket" {
  description = "Set as the GitHub variable TF_STATE_BUCKET."
  value       = aws_s3_bucket.state.bucket
}

output "deploy_role_arn" {
  description = "Set as the GitHub variable AWS_DEPLOY_ROLE_ARN."
  value       = aws_iam_role.deploy.arn
}

output "worker_repository_url" {
  description = "ECR repository the pipeline pushes the worker image to."
  value       = aws_ecr_repository.worker.repository_url
}

output "region" {
  description = "Set as the GitHub variable AWS_REGION."
  value       = var.region
}
