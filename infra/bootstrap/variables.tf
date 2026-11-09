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
  # Repos created since 2026 send an immutable subject with owner and repo IDs, so a deleted
  # and re-created repo of the same name can't deploy. Check yours with:
  #   gh api repos/<owner>/<name>/actions/oidc/customization/sub
  # Set "" for the older repo:<owner>/<name> form.
  description = "Token subject prefix for the GitHub repo (the sub claim before :environment/:ref)."
  type        = string
  default     = "repo:arshdeep3010@188484562/vibe-audit@1450950874"
}

variable "create_github_oidc_provider" {
  description = "false if the account already has the token.actions.githubusercontent.com provider (another stack made it)."
  type        = bool
  default     = false
}
