# First deploy from your own machine. After this, pushes to main deploy through GitHub Actions.
# Needs: AWS CLI signed in with admin rights, Terraform >= 1.10, the project's .venv.
#
#   powershell -ExecutionPolicy Bypass -File infra\deploy.ps1
#
# Terraform shows each plan and waits for "yes" before changing anything.
param(
    [string]$Region = "us-east-1",
    [string]$GithubRepo = "arshdeep3010/vibe-audit"
)
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
function Check($what) { if ($LASTEXITCODE -ne 0) { throw "$what failed (exit $LASTEXITCODE)" } }

Write-Host "`n== 1/4 bootstrap: state bucket + GitHub deploy role ==" -ForegroundColor Cyan
Push-Location "$PSScriptRoot\bootstrap"
terraform init -input=false; Check "bootstrap init"
terraform apply -input=false -var "region=$Region" -var "github_repo=$GithubRepo"; Check "bootstrap apply"
$stateBucket = terraform output -raw state_bucket
$roleArn = terraform output -raw deploy_role_arn
Pop-Location

Write-Host "`n== 2/4 build the Lambda package ==" -ForegroundColor Cyan
& "$root\.venv\Scripts\python.exe" "$PSScriptRoot\build_lambda.py"; Check "build"

Write-Host "`n== 3/4 app stack: Lambda, DynamoDB, S3, CloudFront ==" -ForegroundColor Cyan
Push-Location "$PSScriptRoot\app"
terraform init -input=false -reconfigure `
    "-backend-config=bucket=$stateBucket" "-backend-config=key=vibe-audit/app.tfstate" `
    "-backend-config=region=$Region" "-backend-config=use_lockfile=true"; Check "app init"
terraform apply -input=false -var "region=$Region"; Check "app apply"
$site = terraform output -raw site_bucket
$dist = terraform output -raw distribution_id
$url = terraform output -raw site_url
Pop-Location

Write-Host "`n== 4/4 upload the frontend ==" -ForegroundColor Cyan
aws s3 cp "$root\frontend\index.html" "s3://$site/index.html" --cache-control "no-cache" --content-type "text/html; charset=utf-8"; Check "upload"
aws cloudfront create-invalidation --distribution-id $dist --paths "/*" --query "Invalidation.Id" --output text; Check "invalidation"

Write-Host "`nLive at $url" -ForegroundColor Green
Write-Host "GitHub repository variables for the deploy workflow:"
Write-Host "  AWS_REGION          = $Region"
Write-Host "  AWS_DEPLOY_ROLE_ARN = $roleArn"
Write-Host "  TF_STATE_BUCKET     = $stateBucket"
Write-Host "`nIf you haven't yet, store the model key (the site picks it up within a minute):"
Write-Host "  aws ssm put-parameter --name /vibeaudit/llm-api-key --type SecureString --value <your-new-key> --region $Region"
