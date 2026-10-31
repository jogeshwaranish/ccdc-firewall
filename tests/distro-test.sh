#!/bin/sh
# Runs tests/netns-test.sh (both backends) inside a distro container.
#   sh tests/distro-test.sh debian:trixie [docker|podman]
set -eu
IMAGE=$1
ENGINE=${2:-docker}
REPO=$(cd "$(dirname "$0")/.." && pwd)
$ENGINE run --rm --privileged -v "$REPO:/repo:ro" "$IMAGE" sh -c '
set -e
if command -v apt-get >/dev/null; then
	apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nftables iptables iproute2 python3 util-linux >/dev/null
elif command -v dnf >/dev/null; then
	dnf install -y -q nftables iptables-nft iproute python3 util-linux procps-ng >/dev/null
elif command -v pacman >/dev/null; then
	pacman -Sy --noconfirm --needed nftables iptables-nft iproute2 python util-linux >/dev/null 2>&1 || pacman -Sy --noconfirm --needed nftables iptables iproute2 python util-linux >/dev/null
elif command -v apk >/dev/null; then
	apk add -q nftables iptables iproute2 python3 util-linux
fi
sh /repo/tests/netns-test.sh nft && sh /repo/tests/netns-test.sh iptables'
