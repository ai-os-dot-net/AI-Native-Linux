# AI-OS.NET Cloud Image Infrastructure — Revision 7

Cloud image builders that produce AWS AMI, GCP image, Azure VHD, and
OCI-compatible qcow2/raw images from the shared AIOS rootfs.

## Architecture

```
distro/cloud/
├── build-cloud-image.sh         Master builder (10-phase pipeline)
├── cloud-init/
│   └── aios-cloud-config.yml    Cloud-init configuration
├── packer/
│   ├── variables.pkr.hcl        Shared variables
│   ├── aws-ami.pkr.hcl          AWS AMI builder
│   └── gcp-image.pkr.hcl        GCP image builder
├── tests/
│   ├── test-build-syntax.sh     Bash syntax check
│   ├── test-packer-validate.sh  Packer validation
│   └── test-cloud-init-syntax.sh YAML validation
└── README.md                    This file
```

## Supported Cloud Providers

| Provider | Status | Agent | Format |
|----------|--------|-------|--------|
| AWS      | Full   | cloud-init | qcow2 -> AMI |
| GCP      | Full   | cloud-init | raw -> GCP image |
| Azure    | Beta   | waagent + cloud-init | vhd |
| OCI      | Full   | cloud-init | qcow2 |

## Image Format Reference

| Format | Use Case | Build Command |
|--------|----------|---------------|
| qcow2  | KVM/QEMU, OpenStack, OCI | `--format qcow2` |
| raw    | GCP, direct block device | `--format raw` |
| vhd    | Azure, Hyper-V | `--format vhd` |
| vmdk   | VMware | `--format vmdk` |

## Fleet Enrollment Flow on Cloud Boot

1. Instance boots → cloud-init reads instance metadata
2. cloud-init writes `/etc/aios/config.toml` with `fleet.enroll_on_boot = true`
3. cloud-init writes `/etc/aios/fleet-coordinator` from user-data
4. `aios-first-boot --headless --accept-defaults` runs post-boot
5. AIOS auto-discovers fleet coordinator via cloud-init metadata
6. Node enrolls into fleet with provided token
7. SELinux relabel completes (`.autorelabel` touch file)

## Security Considerations

- No secrets baked into images (fleet tokens via cloud-init user-data)
- SSH password auth disabled (keys only)
- Root login disabled
- TPM2 enrollment attempted but skipped on cloud VMs (no physical TPM)
- SELinux enforcing for secure/stig/airgap profiles
- Boot volume encryption via cloud provider (AWS KMS, GCP CSEK)
- Images should be scanned for CVEs before distribution

## Build Commands

### Quick local build
```bash
./build-cloud-image.sh --cloud aws --format qcow2 --profile dev --output-dir /tmp/aios-cloud
```

### Packer — AWS AMI
```bash
cd distro/cloud/packer
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
packer build -var 'aws_region=us-east-1' -var 'profile=dev' aws-ami.pkr.hcl
```

### Packer — GCP Image
```bash
cd distro/cloud/packer
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
packer build \
    -var 'gcp_project_id=my-project' \
    -var 'gcp_zone=us-central1-a' \
    -var 'profile=dev' \
    gcp-image.pkr.hcl
```

### Azure (manual via qemu-img)
```bash
./build-cloud-image.sh --cloud azure --format vhd --profile dev --output-dir /tmp/aios-cloud
az vm image create --resource-group my-rg --name aios-dev --os-type Linux \
    --hyper-v-generation V2 --source /tmp/aios-cloud/aios-rev7-azure-dev-*.vhd
```

### Azure (via waagent injection)
```bash
./build-cloud-image.sh --cloud azure --format raw --profile dev --output-dir /tmp/aios-cloud
# then use Azure Image Builder or Packer with the raw image
```

## Profiles

| Profile | SELinux | Debug | Doc Stripping |
|---------|---------|-------|---------------|
| dev     | Permissive | Full | None |
| secure  | Enforcing | Minimal | Remove man |
| stig    | Enforcing | None | Remove doc+man |
| airgap  | Enforcing | None | Full strip |

## Testing

```bash
cd distro/cloud/tests
./test-build-syntax.sh         # bash -n on all scripts
./test-packer-validate.sh      # packer validate (if packer installed)
./test-cloud-init-syntax.sh    # YAML validation (if yamllint installed)
```

## Dependencies

- `qemu-utils` (qemu-img)
- `cloud-image-utils` (cloud-localds)
- `e2fsprogs` (mkfs.ext4)
- `dosfstools` (mkfs.vfat)
- `util-linux` (sfdisk, losetup)
- `systemd-boot` (bootctl, EFI stub)
- `packer` (optional, for cloud-native builds)
- `yamllint` (optional, for cloud-init validation)
