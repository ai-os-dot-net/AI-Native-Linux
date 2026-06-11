# AI-OS.NET SDDM Theme

Security-posture-aware QML login screen for the SDDM display manager.

## Features

- AIOS brand identity (logo, typography, color palette)
- Hostname display (reads /etc/hostname)
- Security posture indicator (reads /etc/aios/time-posture)
  - SECURE_DEFAULT: green badge
  - STIG_ALIGNED: amber badge
  - AIRGAP_HIGH: red badge
- Subject selector with name, kind (operator/admin/user), clearance level
- Keyboard layout selector using SDDM keyboard model
- Clean, dark-themed UI following the AIOS visual language

## Installation

```bash
# Copy theme to SDDM themes directory
sudo cp -r distro/desktop/sddm-aios-theme /usr/share/sddm/themes/aios/

# Enable the theme
sudo mkdir -p /etc/sddm.conf.d
sudo tee /etc/sddm.conf.d/aios-theme.conf <<'EOF'
[Theme]
Current=aios
EOF

# Restart SDDM
sudo systemctl restart sddm
```

## Configuration

The theme reads system state from these files:
- `/etc/hostname` — displayed on the login screen
- `/etc/aios/time-posture` — security posture string (SECURE_DEFAULT, STIG_ALIGNED, AIRGAP_HIGH)

The subject list can be populated dynamically via the `subjects.json` drop-in at `/etc/aios/sddm-subjects.json`:

```json
[
  { "id": "operator", "name": "Operator", "kind": "operator", "clearance": "SECRET" },
  { "id": "admin",     "name": "Administrator", "kind": "admin", "clearance": "TOP_SECRET" },
  { "id": "user",      "name": "User", "kind": "user", "clearance": "CONFIDENTIAL" }
]
```

## Development

The theme requires:
- Qt 5.15+ with QtQuick, QtQuick.Controls, QtQuick.Layouts
- SDDM QML components (SddmComponents 2.0)

To test without restarting SDDM:
```bash
sddm-greeter --test-mode --theme /usr/share/sddm/themes/aios
```
