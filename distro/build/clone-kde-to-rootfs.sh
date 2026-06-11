#!/bin/bash
# Fast KDE clone: copies KDE binaries from host system into AIOS rootfs
set -e
REPO_ROOT="/home/luckyngoriko/dev/055.AI-OS.NET--LINUX-AI"
ROOTFS_BASE="${REPO_ROOT}/distro/build/out"
OLD_ROOTFS="${ROOTFS_BASE}/rootfs"
NEW_ROOTFS="${ROOTFS_BASE}/rootfs-desktop"

echo "=== Saving AIOS rootfs ==="
sudo rm -rf "${NEW_ROOTFS}"
sudo cp -a "${OLD_ROOTFS}" "${NEW_ROOTFS}"

echo "=== Copying KDE Plasma from host system ==="
for dir in \
  usr/bin \
  usr/lib64 \
  usr/libexec \
  usr/share/applications \
  usr/share/icons \
  usr/share/plasma \
  usr/share/sddm \
  usr/share/wallpapers \
  usr/share/fonts \
  usr/share/locale \
  usr/share/color-schemes \
  usr/share/kservices5 \
  usr/share/kservicetypes5 \
  usr/share/kpackage \
  usr/share/konsole \
  usr/share/katepart5 \
  usr/share/knotifications5 \
  usr/share/wayland-sessions \
  usr/share/xsessions \
  etc/sddm \
  etc/xdg \
  etc/alternatives \
  etc/fonts; do
  if [ -d "/${dir}" ]; then
    sudo mkdir -p "$(dirname "${NEW_ROOTFS}/${dir}")"
    sudo cp -a "/${dir}" "${NEW_ROOTFS}/${dir}" 2>/dev/null || true
    echo "  Copied: /${dir}"
  fi
done

echo "=== Copying essential shared libraries ==="
# Copy required .so files from host
sudo mkdir -p "${NEW_ROOTFS}/usr/lib64" "${NEW_ROOTFS}/lib64"
sudo cp -a /usr/lib64/libQt6*.so* "${NEW_ROOTFS}/usr/lib64/" 2>/dev/null || true
sudo cp -a /usr/lib64/libKF6*.so* "${NEW_ROOTFS}/usr/lib64/" 2>/dev/null || true
sudo cp -a /usr/lib64/libwayland*.so* "${NEW_ROOTFS}/usr/lib64/" 2>/dev/null || true
sudo cp -a /usr/lib64/libEGL*.so* /usr/lib64/libGL*.so* "${NEW_ROOTFS}/usr/lib64/" 2>/dev/null || true
sudo cp -a /usr/lib64/libdrm*.so* /usr/lib64/libgbm*.so* "${NEW_ROOTFS}/usr/lib64/" 2>/dev/null || true
sudo cp -a /usr/lib64/libxcb*.so* /usr/lib64/libX11*.so* "${NEW_ROOTFS}/usr/lib64/" 2>/dev/null || true

echo "=== Enabling SDDM ==="
sudo mkdir -p "${NEW_ROOTFS}/etc/systemd/system/display-manager.service.wants"
sudo ln -sf /usr/lib/systemd/system/sddm.service \
  "${NEW_ROOTFS}/etc/systemd/system/display-manager.service.wants/sddm.service" 2>/dev/null || true

echo "=== Creating X11/Wayland launcher for AIOS ==="
sudo mkdir -p "${NEW_ROOTFS}/etc/xdg/autostart"
sudo tee "${NEW_ROOTFS}/etc/xdg/autostart/aios-desktop.desktop" > /dev/null << 'DESKTOP'
[Desktop Entry]
Type=Application
Name=AI-OS.NET Desktop
Comment=AI-OS.NET Desktop Session Tools
Exec=/usr/lib/aios/aios-init
X-KDE-autostart-phase=1
OnlyShowIn=KDE;
DESKTOP

echo "=== Final stats ==="
echo "RootFS desktop size:"
du -sh "${NEW_ROOTFS}"
echo ""
ls "${NEW_ROOTFS}/usr/bin/plasmashell" 2>/dev/null && echo "✅ plasmashell found" || echo "⚠️ plasmashell not found"
ls "${NEW_ROOTFS}/usr/bin/sddm" 2>/dev/null && echo "✅ sddm found" || echo "⚠️ sddm not found"
echo ""
echo "✅ KDE desktop rootfs ready at: ${NEW_ROOTFS}"
