#!/bin/bash
set -e

REPO_ROOT="/home/luckyngoriko/dev/055.AI-OS.NET--LINUX-AI"
ROOTFS="${REPO_ROOT}/distro/build/out/rootfs"

echo "=== Step 1: Clean and reinit rootfs RPM database ==="
sudo rm -rf "${ROOTFS}"
sudo mkdir -p "${ROOTFS}"/{dev,proc,sys,run,tmp,etc,var/lib/rpm}

# Initialize RPM database in rootfs
sudo rpm --root "${ROOTFS}" --initdb 2>&1

echo "=== Step 2: Install KDE Plasma 6 packages (~10-15 min, ~2GB download) ==="
sudo zypper --root "${ROOTFS}" --non-interactive --gpg-auto-import-keys install \
  plasma6-workspace plasma6-desktop plasma6-session \
  sddm sddm-kcm6 breeze6-icons breeze6-cursors breeze6-wallpapers \
  plasma6-integration plasma6-breeze plasma6-systemmonitor \
  kwin6 konsole dolphin kate firefox \
  xdg-desktop-portal-kde xdg-user-dirs \
  NetworkManager ModemManager \
  pipewire wireplumber alsa-utils \
  Mesa-dri Mesa-libGL1 \
  noto-sans-fonts google-noto-fonts \
  2>&1 | tail -30

echo "=== Step 3: Install AIOS files into rootfs ==="
# Copy existing rootfs content (AIOS binaries, configs, systemd units)
sudo cp -a "${REPO_ROOT}/distro/build/out/rootfs-pre-kde"/. "${ROOTFS}/" 2>/dev/null || true

# Ensure SDDM starts
sudo mkdir -p "${ROOTFS}/etc/systemd/system/display-manager.service.wants"
sudo ln -sf /usr/lib/systemd/system/sddm.service "${ROOTFS}/etc/systemd/system/display-manager.service.wants/sddm.service" 2>/dev/null || true
sudo systemctl --root "${ROOTFS}" enable sddm 2>/dev/null || true
sudo systemctl --root "${ROOTFS}" set-default graphical.target 2>/dev/null || true

echo "=== Step 4: Verify ==="
ls -la "${ROOTFS}"/usr/bin/plasmashell 2>/dev/null && echo "✅ plasmashell found" || echo "❌ plasmashell MISSING"
ls -la "${ROOTFS}"/usr/bin/sddm 2>/dev/null && echo "✅ SDDM found" || echo "❌ SDDM MISSING"
ls -la "${ROOTFS}"/usr/bin/kwin_wayland 2>/dev/null && echo "✅ kwin_wayland found" || echo "❌ kwin MISSING"
echo ""
echo "RootFS size:"
sudo du -sh "${ROOTFS}"
echo ""
echo "✅ KDE rootfs installation complete!"
