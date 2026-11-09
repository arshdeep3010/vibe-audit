variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  description = "Prefix for every resource name (must match infra/bootstrap)."
  type        = string
  default     = "vibeaudit"
}

variable "lambda_zip" {
  description = "Deployment package built by infra/build_lambda.py."
  type        = string
  default     = "../../build/lambda.zip"
}

variable "lambda_arch" {
  description = "arm64 is ~20% cheaper; must match the --arch the package was built for."
  type        = string
  default     = "arm64"
}

variable "llm_api_key_param" {
  description = "SSM SecureString with the model API key. You create it yourself (see README), so the key never enters Terraform state."
  type        = string
  default     = "/vibeaudit/llm-api-key"
}

# ---- model ----
variable "model" {
  type    = string
  default = "nvidia/nemotron-3-ultra-550b-a55b"
}

variable "llm_base_url" {
  type    = string
  default = "https://integrate.api.nvidia.com/v1"
}

variable "enable_thinking" {
  type    = bool
  default = true
}

variable "max_tokens" {
  type    = number
  default = 8192
}

# ---- cost and abuse limits ----
variable "rate_limit_per_hour" {
  description = "New audits per visitor IP per clock hour."
  type        = number
  default     = 5
}

variable "daily_scan_cap" {
  description = "New audits across all visitors per UTC day: the hard ceiling on model spend."
  type        = number
  default     = 100
}

variable "max_running_scans" {
  type    = number
  default = 2
}

variable "scan_timeout_s" {
  type    = number
  default = 300
}

variable "max_snippet_lines" {
  type    = number
  default = 400
}

variable "result_ttl_hours" {
  type    = number
  default = 24
}

variable "cache_ttl_hours" {
  type    = number
  default = 24
}

# ---- runtime ----
variable "api_memory_mb" {
  type    = number
  default = 512
}

variable "worker_memory_mb" {
  type    = number
  default = 512
}

variable "worker_reserved_concurrency" {
  description = "Cap on worker instances (-1 = no cap). New accounts with a 10-instance account limit can't reserve any."
  type        = number
  default     = -1
}

variable "log_retention_days" {
  type    = number
  default = 14
}

variable "price_class" {
  description = "PriceClass_200 includes India and Asia edge locations; PriceClass_100 is NA/EU only."
  type        = string
  default     = "PriceClass_200"
}

# ---- budget alert ----
variable "budget_email" {
  description = "Email for the monthly cost alert. Empty = no budget."
  type        = string
  default     = ""
}

variable "budget_usd" {
  type    = number
  default = 5
}
