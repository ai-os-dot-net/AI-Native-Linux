# =============================================================================
# AI-OS.NET Packer — Shared Variables
# Revision 7
# =============================================================================
# Shared variables for all cloud provider Packer templates.
# Override via command-line: packer build -var 'profile=stig' ...
# =============================================================================

variable "aios_version" {
  type        = string
  default     = "0.2.0"
  description = "AI-OS.NET version string"
}

variable "profile" {
  type        = string
  default     = "dev"
  description = "Security profile: dev, secure, stig, or airgap"
  validation {
    condition     = contains(["dev", "secure", "stig", "airgap"], var.profile)
    error_message = "Profile must be one of: dev, secure, stig, airgap."
  }
}

variable "cloud" {
  type        = string
  default     = "aws"
  description = "Cloud provider: aws, gcp, azure, or oci"
}

variable "ssh_username" {
  type        = string
  default     = "admin"
  description = "SSH username for provisioner connections"
}

variable "region" {
  type        = string
  default     = "us-east-1"
  description = "Default cloud region"
}

# ── AWS-specific ──────────────────────────────────────────────────────────────

variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for AMI build"
}

variable "aws_ami_regions" {
  type        = list(string)
  default     = ["us-east-1", "eu-west-1"]
  description = "AWS regions to copy the AMI to"
}

variable "aws_instance_type" {
  type        = string
  default     = "t3.medium"
  description = "AWS EC2 instance type for the builder"
}

variable "aws_root_volume_size" {
  type        = number
  default     = 20
  description = "Root volume size in GB for the AMI"
}

variable "aws_encrypt_boot" {
  type        = bool
  default     = true
  description = "Encrypt the AMI boot volume"
}

variable "aws_kms_key_id" {
  type        = string
  default     = ""
  description = "KMS key ID for AMI encryption (uses AWS-managed key if empty)"
}

# ── GCP-specific ──────────────────────────────────────────────────────────────

variable "gcp_project_id" {
  type        = string
  default     = ""
  description = "GCP project ID"
}

variable "gcp_zone" {
  type        = string
  default     = "us-central1-a"
  description = "GCP zone for the builder instance"
}

variable "gcp_machine_type" {
  type        = string
  default     = "e2-medium"
  description = "GCE machine type for the builder"
}

variable "gcp_disk_size" {
  type        = number
  default     = 20
  description = "GCE disk size in GB"
}

variable "gcp_kms_key_name" {
  type        = string
  default     = ""
  description = "GCP KMS key for image encryption (uses Google-managed if empty)"
}
