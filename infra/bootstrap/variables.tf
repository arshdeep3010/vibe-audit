variable "region" {
  type    = string
  default = "us-east-1"
}

variable "name" {
  description = "Prefix for every resource name."
  type        = string
  default     = "vibeaudit"
}

variable "github_repo" {
  description = "GitHub repository allowed to deploy, as owner/name."
  type        = string
  default     = "arshdeep3010/vibe-audit"
}

variable "github_environment" {
  description = "GitHub environment the deploy job runs in."
  type        = string
  default     = "production"
}

variable "github_sub_prefix" {
  description = "Override the token subject prefix if your repo uses a customised OIDC sub claim (default: repo:<owner>/<name>)."
  type        = string
  default     = ""
}

variable "create_github_oidc_provider" {
  description = "false if the account already has the token.actions.githubusercontent.com provider (another stack made it)."
  type        = bool
  default     = false
}
