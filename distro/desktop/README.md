# AI-OS.NET Desktop Integration — Revision 6

AI-OS.NET daily-driver desktop: SDDM login → session manager → KDE Plasma with AI-native services.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        SDDM Login                           │
│  sddm-aios-theme: subject selector + posture indicator      │
└─────────────────────┬───────────────────────────────────────┘
                      │ Authenticated
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                   Session Manager                           │
│  session-manager.sh: launch AIOS daemons, Plasma, teardown  │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Policy Kernel │  │ Evidence Log │  │ D-Bus Setup  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────┬───────────────────────────────────────┘
                      │ Wayland session
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    KDE Plasma Desktop                       │
│                                                             │
│  ┌──────────────────┐  ┌──────────────┐  ┌───────────┐    │
│  │ KDE Renderer Svc │  │ Cognitive    │  │ Evidence   │    │
│  │ (autostart)      │  │ Init         │  │ Tray       │    │
│  └──────────────────┘  └──────────────┘  └───────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Security Model

```
SDDM (display manager)
  │ reads /etc/aios/time-posture → posture indicator
  │ authenticates subject (operator/admin/user)
  ▼
session-manager.sh
  │ verifies TPM2 PCR attestation
  │ reads posture from /etc/aios/time-posture
  │ starts Policy Kernel daemon (enforces capabilities)
  │ starts Evidence Log daemon (tamper-evident journal)
  │ sets up D-Bus session bus
  ▼
KDE Plasma (desktop environment)
  │ AIOS_WAYLAND_DISPLAY → Wayland compositor binds AIOS zones
  │ aios-renderer-kde.service → surface composition engine
  │ aios-cognitive-init.sh → model provider pre-warming
  │ aios-evidence-tray.sh → live posture tray icon
  ▼
Session End
  │ log_evidence SESSION_END
  │ graceful teardown of all AIOS daemons
```

## Files

```
distro/desktop/
├── aios-plasma.desktop          # XDG session entry for SDDM
├── session-manager.sh           # Session lifecycle orchestrator
├── sddm-aios-theme/
│   ├── Main.qml                 # Login screen QML
│   ├── theme.conf               # SDDM theme metadata
│   ├── components/
│   │   ├── SubjectSelector.qml  # Subject picker widget
│   │   └── PostureIndicator.qml # Security posture badge
│   └── README.md                # Theme installation guide
├── plasma-autostart/
│   ├── aios-renderer-kde.sh     # KDE renderer service start
│   ├── aios-cognitive-init.sh   # Model provider check + warm
│   └── aios-evidence-tray.sh    # Posture tray icon daemon
├── tests/
│   └── test-session-start.sh    # Validation tests
└── README.md                    # This file
```

## Session Lifecycle

1. **SDDM displays login screen** — AIOS theme with posture badge, subject selector, keyboard layout
2. **User authenticates** — SDDM launches `/usr/share/xsessions/aios-session-manager.sh`
3. **Session manager starts** — generates session UUID, reads posture, verifies TPM2
4. **AIOS daemons launch** — Policy Kernel + Evidence Log start before desktop
5. **KDE Plasma starts** — Wayland session with `AIOS_WAYLAND_DISPLAY` env var
6. **Autostart triggers** — Renderer service, cognitive init, evidence tray icon
7. **Session ends** — Evidence logged, all AIOS daemons stop gracefully

## Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `AIOS_BIN` | `/usr/bin/aios` | CLI binary path |
| `AIOS_LIB_DIR` | `/usr/lib/aios` | Service binary directory |
| `AIOS_CONFIG_DIR` | `/etc/aios` | Configuration directory |
| `AIOS_STATE_DIR` | `/var/lib/aios` | State/evidence directory |
| `AIOS_RUN_DIR` | `/run/aios` | Runtime PID files |
| `AIOS_WAYLAND_DISPLAY` | `$WAYLAND_DISPLAY` | AIOS Wayland display name |
| `OLLAMA_HOST` | `http://127.0.0.1:11434` | Ollama API endpoint |
| `VLLM_HOST` | `http://127.0.0.1:8000` | vLLM API endpoint |
| `POSTURE_FILE` | `/etc/aios/time-posture` | Posture state file |
| `COGNITIVE_PREWARM` | `0` | Pre-warm models on login |

## Installation

```bash
# Copy desktop entry to XDG sessions
sudo cp distro/desktop/aios-plasma.desktop /usr/share/xsessions/

# Copy session manager
sudo cp distro/desktop/session-manager.sh /usr/share/xsessions/aios-session-manager.sh
sudo chmod +x /usr/share/xsessions/aios-session-manager.sh

# Install SDDM theme
sudo cp -r distro/desktop/sddm-aios-theme /usr/share/sddm/themes/aios/
sudo tee /etc/sddm.conf.d/aios-theme.conf <<'EOF'
[Theme]
Current=aios
EOF

# Install autostart scripts
mkdir -p ~/.config/autostart/
cp distro/desktop/plasma-autostart/*.sh ~/.config/autostart/
chmod +x ~/.config/autostart/*.sh

# Enable KDE renderer systemd --user service
systemctl --user enable aios-renderer-kde.service
```

## Testing

```bash
# Run syntax and sanity checks
sh distro/desktop/tests/test-session-start.sh

# Test session manager in headless mode (no Plasma needed)
AIOS_BIN=/bin/true distro/desktop/session-manager.sh 2>&1 | head -20
```
