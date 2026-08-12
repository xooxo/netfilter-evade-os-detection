#!/usr/bin/env bash
# Boot a Debian 12 VM with QEMU + gdbstub for debugging netfilter_module.ko.
#
# The guest has two NICs:
#   eth0 = user-mode / SLIRP  -> outbound only, used for apt / package install
#   eth1 = tap                -> point-to-point link with the host at
#                                 host 192.168.100.1  <->  guest 192.168.100.2
# Nmap probes sent to 192.168.100.2 hit the guest's real TCP/IP stack (and
# therefore your netfilter hook), which is what you need to validate the
# OS-detection evasion.
#
# Inside the VM:
#     cd /mnt/host && make
#     sudo insmod netfilter_module.ko
#
# From the host:
#     ssh debian@192.168.100.2
#     sudo nmap -O 192.168.100.2
#     gdb -ex 'target remote :1234' /path/to/vmlinux
#
# The tap device is created the first time (needs sudo once) and persists,
# so subsequent runs don't prompt. Remove it with:
#     sudo ip tuntap del tap0 mode tap
#
# Serial console is on stdio. Exit QEMU with Ctrl-A then X.

set -euo pipefail

VM_DIR="${VM_DIR:-$HOME/.local/share/netfilter-debug-vm}"
IMG_URL="https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2"
BASE="$VM_DIR/debian-12-generic-amd64.qcow2"
DISK="$VM_DIR/disk.qcow2"
SEED="$VM_DIR/seed.iso"

MEMORY="${MEMORY:-2G}"
CPUS="${CPUS:-2}"
DISK_SIZE="${DISK_SIZE:-10G}"
GDB_PORT="${GDB_PORT:-1234}"
SSH_PORT="${SSH_PORT:-2222}"
SHARE_DIR="${SHARE_DIR:-$PWD}"
# FREEZE=1 halts the CPU at reset so you can attach gdb before boot.
FREEZE="${FREEZE:-0}"

TAP_IF="${TAP_IF:-tap0}"
HOST_IP="${HOST_IP:-192.168.100.1}"
GUEST_IP="${GUEST_IP:-192.168.100.2}"
TAP_PREFIX="${TAP_PREFIX:-24}"
SLIRP_MAC="${SLIRP_MAC:-52:54:00:12:34:55}"
TAP_MAC="${TAP_MAC:-52:54:00:12:34:56}"

mkdir -p "$VM_DIR"

for bin in qemu-system-x86_64 qemu-img curl ip; do
  command -v "$bin" >/dev/null || { echo "missing dependency: $bin" >&2; exit 1; }
done

PUBKEY=""
for k in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub"; do
  [[ -f "$k" ]] && { PUBKEY="$(cat "$k")"; break; }
done
if [[ -z "$PUBKEY" ]]; then
  echo "No SSH public key in ~/.ssh. Run: ssh-keygen -t ed25519" >&2
  exit 1
fi

if [[ ! -f "$BASE" ]]; then
  echo "Downloading $IMG_URL"
  curl -fL --progress-bar -o "$BASE.part" "$IMG_URL"
  mv "$BASE.part" "$BASE"
fi

if [[ ! -f "$DISK" ]]; then
  qemu-img create -f qcow2 -F qcow2 -b "$BASE" "$DISK" "$DISK_SIZE"
fi

if [[ ! -f "$SEED" ]]; then
  UD="$VM_DIR/user-data"
  MD="$VM_DIR/meta-data"
  NC="$VM_DIR/network-config"
  cat > "$UD" <<EOF
#cloud-config
hostname: netfilter-debug
users:
  - name: debian
    sudo: ALL=(ALL) NOPASSWD:ALL
    shell: /bin/bash
    ssh_authorized_keys:
      - $PUBKEY
package_update: true
packages:
  - build-essential
  - linux-headers-amd64
  - linux-image-amd64-dbg
  - gdb
  - nmap
  - tcpdump
runcmd:
  - mkdir -p /mnt/host
  - printf 'host  /mnt/host  9p  trans=virtio,version=9p2000.L,rw  0 0\n' >> /etc/fstab
  - mount /mnt/host || true
EOF
  cat > "$MD" <<EOF
instance-id: netfilter-debug
local-hostname: netfilter-debug
EOF
  cat > "$NC" <<EOF
version: 2
ethernets:
  slirp:
    match:
      macaddress: "${SLIRP_MAC}"
    dhcp4: true
  tap:
    match:
      macaddress: "${TAP_MAC}"
    addresses:
      - ${GUEST_IP}/${TAP_PREFIX}
EOF
  if command -v cloud-localds >/dev/null; then
    cloud-localds --network-config="$NC" "$SEED" "$UD" "$MD"
  elif command -v genisoimage >/dev/null; then
    genisoimage -quiet -output "$SEED" -volid cidata -joliet -rock \
      -graft-points user-data="$UD" meta-data="$MD" network-config="$NC"
  elif command -v mkisofs >/dev/null; then
    mkisofs -quiet -output "$SEED" -volid cidata -joliet -rock \
      -graft-points user-data="$UD" meta-data="$MD" network-config="$NC"
  else
    echo "Need one of: cloud-localds, genisoimage, mkisofs" >&2
    exit 1
  fi
fi

if ! ip link show "$TAP_IF" &>/dev/null; then
  echo "Creating $TAP_IF (needs sudo, one-time)"
  sudo ip tuntap add dev "$TAP_IF" mode tap user "$USER"
  sudo ip addr add "${HOST_IP}/${TAP_PREFIX}" dev "$TAP_IF"
  sudo ip link set "$TAP_IF" up
fi

ACCEL="tcg"; CPU="max"
if [[ -w /dev/kvm ]]; then ACCEL="kvm"; CPU="host"; fi

FREEZE_ARG=()
[[ "$FREEZE" == "1" ]] && FREEZE_ARG=(-S)

echo "gdb:   target remote :${GDB_PORT}"
echo "ssh:   ssh debian@${GUEST_IP}     (or: ssh -p ${SSH_PORT} debian@localhost)"
echo "nmap:  sudo nmap -O ${GUEST_IP}   (probes reach the guest kernel)"
echo "share: ${SHARE_DIR} -> /mnt/host (inside VM)"
echo "exit:  Ctrl-A then X"
echo

exec qemu-system-x86_64 \
  -machine q35,accel="$ACCEL" \
  -cpu "$CPU" \
  -m "$MEMORY" \
  -smp "$CPUS" \
  -drive if=virtio,file="$DISK",format=qcow2 \
  -drive if=virtio,file="$SEED",format=raw,readonly=on \
  -netdev "user,id=n0,hostfwd=tcp::${SSH_PORT}-:22" \
  -device "virtio-net-pci,netdev=n0,mac=${SLIRP_MAC}" \
  -netdev "tap,id=n1,ifname=${TAP_IF},script=no,downscript=no" \
  -device "virtio-net-pci,netdev=n1,mac=${TAP_MAC}" \
  -virtfs "local,path=${SHARE_DIR},mount_tag=host,security_model=mapped,id=host" \
  -nographic \
  -gdb "tcp::${GDB_PORT}" \
  "${FREEZE_ARG[@]}"
