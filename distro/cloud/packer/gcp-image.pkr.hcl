# =============================================================================
# AI-OS.NET Packer Template — GCP Image Builder
# Revision 7
# =============================================================================
# Builds a GCP Compute Engine image from Debian 12 base with AIOS installed.
# Registers the image as a GCP image in the configured project.
#
# Usage:
#   packer build -var 'gcp_project_id=my-project' \
#                -var 'gcp_zone=us-central1-a' \
#                -var 'profile=dev' \
#                -var 'aios_version=0.2.0' \
#                gcp-image.pkr.hcl
# =============================================================================

packer {
  required_plugins {
    googlecompute = {
      version = ">= 1.1.6"
      source  = "github.com/hashicorp/googlecompute"
    }
  }
}

# ── Locals ────────────────────────────────────────────────────────────────────

locals {
  timestamp    = formatdate("YYYY-MM-DD", timestamp())
  image_name   = "aios-${var.aios_version}-${var.profile}-${formatdate("YYYYMMDD", timestamp())}"
  image_family = "aios-${var.aios_version}-${var.profile}"
}

# ── Builder ───────────────────────────────────────────────────────────────────

source "googlecompute" "aios" {
  project_id          = var.gcp_project_id
  zone                = var.gcp_zone
  image_name          = local.image_name
  image_description   = "AI-OS.NET ${var.aios_version} — ${var.profile} profile — built ${local.timestamp}"
  image_family        = local.image_family
  image_labels = {
    profile   = var.profile
    version   = var.aios_version
    cloud     = var.cloud
    os        = "aios"
    revision  = "7"
    builddate = formatdate("YYYYMMDD", timestamp())
  }
  image_encryption_key {
    kms_key_name = var.gcp_kms_key_name
  }
  machine_type       = var.gcp_machine_type
  source_image_family = "debian-12"
  source_image_project_id = ["debian-cloud"]
  ssh_username       = var.ssh_username
  ssh_timeout        = "20m"

  disk_size    = var.gcp_disk_size
  disk_type    = "pd-ssd"
  use_internal_ip = false
  preemptible  = false

  metadata = {
    enable-oslogin = "FALSE"
    startup-script = <<EOF
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

  tags = ["aios", "builder", var.profile]
}

# ── Build steps ───────────────────────────────────────────────────────────────

build {
  name    = "aios-gcp-image"
  sources = ["source.googlecompute.aios"]

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
          --format raw \
          --profile ${var.profile} \
          --version ${var.aios_version} \
          --output-dir /opt/aios-builder/out \
          2>&1 | sudo tee /var/log/aios/cloud-build.log || true"
    ]
  }

  provisioner "shell" {
    inline = [
      "echo 'GCP image build complete.'",
      "echo 'AIOS version: ${var.aios_version}'",
      "echo 'Profile: ${var.profile}'",
      "ls -la /opt/aios-builder/out/"
    ]
  }

  post-processor "manifest" {
    output     = "manifest-gcp.json"
    strip_path = true
    custom_data = {
      cloud   = var.cloud
      profile = var.profile
      version = var.aios_version
    }
  }
}
