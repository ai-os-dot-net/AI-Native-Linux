# =============================================================================
# AI-OS.NET Packer Template — AWS AMI Builder
# Revision 7
# =============================================================================
# Builds an AWS AMI from Debian 12 base with AIOS installed via
# build-cloud-image.sh. Registers the AMI in configured AWS regions.
#
# Usage:
#   packer build -var 'aws_region=us-east-1' \
#                -var 'profile=dev' \
#                -var 'aios_version=0.2.0' \
#                aws-ami.pkr.hcl
# =============================================================================

packer {
  required_plugins {
    amazon = {
      version = ">= 1.2.1"
      source  = "github.com/hashicorp/amazon"
    }
  }
}

# ── Source: Debian 12 AMI ────────────────────────────────────────────────────

data "amazon-ami" "debian" {
  filters = {
    name                = "debian-12-amd64-*"
    root-device-type    = "ebs"
    virtualization-type = "hvm"
    architecture        = "x86_64"
  }
  most_recent = true
  owners      = ["136693071363"]
  region      = var.aws_region
}

# ── Locals ────────────────────────────────────────────────────────────────────

locals {
  timestamp       = formatdate("YYYY-MM-DD", timestamp())
  ami_name        = "aios-${var.aios_version}-${var.profile}-hvm-x86_64-${formatdate("YYYYMMDD", timestamp())}"
  ami_description = "AI-OS.NET ${var.aios_version} — ${var.profile} profile — built ${local.timestamp}"
}

# ── Builder ───────────────────────────────────────────────────────────────────

source "amazon-ebs" "aios" {
  ami_name        = local.ami_name
  ami_description = local.ami_description
  instance_type   = var.aws_instance_type
  region          = var.aws_region
  source_ami      = data.amazon-ami.debian.id
  ssh_username    = var.ssh_username
  ssh_clear_authorized_keys = true
  ssh_timeout     = "20m"

  launch_block_device_mappings {
    device_name = "/dev/xvda"
    volume_size = var.aws_root_volume_size
    volume_type = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name        = local.ami_name
    Profile     = var.profile
    Version     = var.aios_version
    Cloud       = var.cloud
    BuildDate   = local.timestamp
    OS          = "AI-OS.NET"
    Revision    = "7"
    ManagedBy   = "packer"
  }

  snapshot_tags = {
    Name      = "${local.ami_name}-snapshot"
    Profile   = var.profile
    Version   = var.aios_version
    BuildDate = local.timestamp
  }

  ami_regions = var.aws_ami_regions
  encrypt_boot = var.aws_encrypt_boot
  kms_key_id   = var.aws_kms_key_id

  user_data = <<EOF
#!/bin/bash
set -euo pipefail

apt-get update -qq
apt-get install -y -qq \
    qemu-utils \
    cloud-image-utils \
    qemu-guest-agent \
    cloud-init \
    systemd-boot \
    busybox-static \
    squashfs-tools \
    cryptsetup \
    tpm2-tools \
    policycoreutils \
    curl wget git \
    jq unzip

systemctl enable qemu-guest-agent
systemctl enable systemd-networkd
systemctl enable systemd-resolved
EOF
}

# ── Build steps ───────────────────────────────────────────────────────────────

build {
  name    = "aios-aws-ami"
  sources = ["source.amazon-ebs.aios"]

  provisioner "file" {
    source      = "${path.root}/../cloud-init/aios-cloud-config.yml"
    destination = "/tmp/aios-cloud-config.yml"
  }

  provisioner "file" {
    source      = "${path.root}/../build-cloud-image.sh"
    destination = "/tmp/build-cloud-image.sh"
  }

  provisioner "shell" {
    inline = [
      "sudo mkdir -p /opt/aios-builder",
      "sudo cp /tmp/build-cloud-image.sh /opt/aios-builder/",
      "sudo cp /tmp/aios-cloud-config.yml /opt/aios-builder/",
      "sudo chmod +x /opt/aios-builder/build-cloud-image.sh",
      "echo 'AIOS builder staged at /opt/aios-builder'"
    ]
  }

  provisioner "shell" {
    inline = [
      "sudo mkdir -p /var/log/aios",
      "sudo /opt/aios-builder/build-cloud-image.sh \
          --cloud ${var.cloud} \
          --format qcow2 \
          --profile ${var.profile} \
          --version ${var.aios_version} \
          --output-dir /opt/aios-builder/out \
          2>&1 | sudo tee /var/log/aios/cloud-build.log || true"
    ]
  }

  provisioner "shell" {
    inline = [
      "echo 'AMI build complete.'",
      "echo 'AIOS version: ${var.aios_version}'",
      "echo 'Profile: ${var.profile}'"
    ]
  }

  post-processor "manifest" {
    output     = "manifest-aws.json"
    strip_path = true
    custom_data = {
      cloud   = var.cloud
      profile = var.profile
      version = var.aios_version
    }
  }
}
