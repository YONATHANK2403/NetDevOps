#!/bin/sh
# Charge les règles nftables, puis abandonne les privilèges root.
set -eu
nft -f /etc/nftables.conf
echo "[router-fw] règles nftables chargées"
exec su -s /bin/sh -c 'exec tail -f /dev/null' nobody
